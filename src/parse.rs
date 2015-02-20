#![no_implicit_prelude]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::{str};
use std::vec::{Vec};
use std::string::{String};
use std::result::{Result};
use std::result::Result::{Ok, Err};
use std::io::{Read};
use std::slice::{SliceExt};
use std::time::{Duration};

use {Data, Packet, Record, Question, Class, Type, ResponseCode, QueryKind};
use {A, AAAA, MX, PTR, RP, TXT, ALL, IN};

use rust::{ReadExt2};

pub fn packet(src: &mut &[u8]) -> Result<Packet, ()> {
    let start = *src;

    let id = trycvt!(src.read_i16_be());
    let flags = trycvt!(src.read_u16_be());
    let is_query = flags & 0b1000_0000_0000_0000 == 0;
    let kind_ = (flags & 0b0111_1000_0000_0000) >> 11;
    let kind = trycvt!(kind(kind_));
    let is_authoritative = flags & 0b0000_0100_0000_0000 != 0;
    let truncated = flags & 0b0000_0010_0000_0000 != 0;
    let recursion_desired = flags & 0b0000_0001_0000_0000 != 0;
    let recursion_available = flags & 0b0000_0000_1000_0000 != 0;
    let response_code_ = flags & 0b0000_0000_0000_1111;
    let response_code = trycvt!(response_code(response_code_));
    let num_questions = trycvt!(src.read_u16_be());
    let num_answers = trycvt!(src.read_u16_be());
    let num_authority = trycvt!(src.read_u16_be());
    let num_additional = trycvt!(src.read_u16_be());
    let mut questions = vec!();
    for _ in 0..num_questions {
        match question(src, start) {
            Ok(q) => questions.push(q),
            Err(false) => return Err(()),
            _ => { },
        }
    }
    let mut answers = vec!();
    let mut authority = vec!();
    let mut additional = vec!();
    {
        let mut vec = [(&mut answers, num_answers),
                       (&mut authority, num_authority),
                       (&mut additional, num_additional)];
        for v in vec.iter_mut() {
            for _ in 0..v.1 {
                match record(src, start) {
                    Ok(q) => v.0.push(q),
                    Err(false) => return Err(()),
                    _ => { },
                }
            }
        }
    }
    Ok(Packet {
        id:                  id,
        is_query:            is_query,
        kind:                kind,
        is_authoritative:    is_authoritative,
        truncated:           truncated,
        recursion_desired:   recursion_desired,
        recursion_available: recursion_available,
        response_code:       response_code,

        question:   questions,
        answer:     answers,
        authority:  authority,
        additional: additional,
    })
}

fn kind(kind: u16) -> Result<QueryKind, ()> {
    match kind {
        0 => Ok(QueryKind::Standard),
        1 => Ok(QueryKind::Inverse),
        2 => Ok(QueryKind::Status),
        _ => Err(()),
    }
}

fn response_code(code: u16) -> Result<ResponseCode, ()> {
    match code {
        0 => Ok(ResponseCode::Ok),
        1 => Ok(ResponseCode::FormatError),
        2 => Ok(ResponseCode::ServerFailure),
        3 => Ok(ResponseCode::NameError),
        4 => Ok(ResponseCode::NotImplemented),
        5 => Ok(ResponseCode::Refused),
        _ => Err(()),
    }
}

fn question(src: &mut &[u8], start: &[u8]) -> Result<Question, bool> {
    let name = trycvt!(domain_name(src, start));
    let ty = ty(src);
    let class = class(src);
    if ty.is_err() || class.is_err() {
        Err(true)
    } else {
        Ok(Question {
            name:  name,
            ty:    ty.unwrap(),
            class: class.unwrap(),
        })
    }
}

fn record(src: &mut &[u8], start: &[u8]) -> Result<Record, bool> {
    let name = trycvt!(domain_name(src, start));
    let ty = ty(src);
    let class = class(src);
    let ttl = trycvt!(src.read_i32_be());
    let len = trycvt!(src.read_u16_be());
    if ty.is_err() || class.is_err() {
        return if len as usize <= src.len() {
            *src = &src[len as usize..];
            Err(true)
        } else {
            Err(false)
        };
    }
    let data = match ty.unwrap() {
        Type::A    => trycvt!(a(src)),
        Type::Aaaa => trycvt!(aaaa(src)),
        Type::Mx   => trycvt!(mx(src, start)),
        Type::Ptr  => trycvt!(ptr(src, start)),
        Type::Rp   => trycvt!(rp(src, start)),
        Type::Txt  => trycvt!(txt(src, len as usize)),
        Type::All  => return Err(false),
    };
    Ok(Record {
        name:         name,
        class:        class.unwrap(),
        time_to_live: Duration::seconds(ttl as i64),
        data:         data,
    })
}

fn ty(src: &mut &[u8]) -> Result<Type, ()> {
    let ty = trycvt!(src.read_u16_be());
    match ty {
        A    => Ok(Type::A),
        AAAA => Ok(Type::Aaaa),
        MX   => Ok(Type::Mx),
        PTR  => Ok(Type::Ptr),
        RP   => Ok(Type::Rp),
        TXT  => Ok(Type::Txt),
        ALL  => Ok(Type::All),
        _ => Err(())
    }
}

fn class(src: &mut &[u8]) -> Result<Class, ()> {
    let ty = trycvt!(src.read_u16_be());
    match ty {
        IN  => Ok(Class::In),
        ALL => Ok(Class::All),
        _ => Err(())
    }
}

fn a(src: &mut &[u8]) -> Result<Data, ()> {
    if src.len() < 4 {
        Err(())
    } else {
        let mut a = [0; 4];
        let _ = src.read(&mut a);
        Ok(Data::A(Ipv4Addr::new(a[0], a[1], a[2], a[3])))
    }
}

fn aaaa(src: &mut &[u8]) -> Result<Data, ()> {
    if src.len() < 16 {
        return Err(());
    }
    let ip = Ipv6Addr::new(
        src.read_u16_be().unwrap(),
        src.read_u16_be().unwrap(),
        src.read_u16_be().unwrap(),
        src.read_u16_be().unwrap(),
        src.read_u16_be().unwrap(),
        src.read_u16_be().unwrap(),
        src.read_u16_be().unwrap(),
        src.read_u16_be().unwrap());
    Ok(Data::Aaaa(ip))
}

fn mx(src: &mut &[u8], start: &[u8]) -> Result<Data, ()> {
    let preference = trycvt!(src.read_i16_be());
    let domain = trycvt!(domain_name(src, start));
    Ok(Data::Mx(preference, domain))
}

fn ptr(src: &mut &[u8], start: &[u8]) -> Result<Data, ()> {
    let domain = trycvt!(domain_name(src, start));
    Ok(Data::Ptr(domain))
}

fn rp(src: &mut &[u8], start: &[u8]) -> Result<Data, ()> {
    let mbox = trycvt!(domain_name(src, start));
    let txt = trycvt!(domain_name(src, start));
    Ok(Data::Rp(mbox, txt))
}

fn txt(src: &mut &[u8], total_len: usize) -> Result<Data, ()> {
    let mut res = vec!();
    let mut cur_len = 0;
    while cur_len < total_len {
        let txt = trycvt!(character_string(src));
        cur_len += txt.len() + 1;
        res.push(txt);
    }
    Ok(Data::Txt(res))
}

fn domain_name(src: &mut &[u8], start: &[u8]) -> Result<String, ()> {
    let mut res = String::new();
    loop {
        let len = trycvt!(src.read_u8());
        if len == 0 {
            break;
        } else if res.len() > 0 {
            res.push('.');
        }
        if len & 0b1100_0000 != 0 {
            return if len & 0b1100_0000 == 0b1100_0000 {
                let b2 = trycvt!(src.read_u8());
                let offset = ((len as usize & 0b0011_1111) << 8) | (b2 as usize);
                if start.len() < offset {
                    Err(())
                } else {
                    let mut tmp = &start[offset..];
                    let s = trycvt!(domain_name(&mut tmp, start));
                    res.push_str(&s);
                    Ok(res)
                }
            } else {
                Err(())
            };
        }
        if src.len() < len as usize {
            return Err(());
        }
        unsafe {
            res.reserve(len as usize);
            let oldlen = res.len();
            res.as_mut_vec().set_len(oldlen + len as usize);
            let _ = src.read(&mut res.as_mut_vec()[oldlen..]);
            if str::from_utf8(&mut res.as_mut_vec()[oldlen..]).is_err() {
                res.as_mut_vec().set_len(oldlen);
                return Err(());
            }
        }
    }
    Ok(res)
}

fn character_string(src: &mut &[u8]) -> Result<String, ()> {
    let len = trycvt!(src.read_u8());
    if src.len() < len as usize {
        return Err(());
    }
    let mut res = Vec::with_capacity(len as usize);
    unsafe { res.set_len(len as usize); }
    let _ = src.read(&mut res);
    match String::from_utf8(res) {
        Ok(s) => Ok(s),
        _ => Err(()),
    }
}
