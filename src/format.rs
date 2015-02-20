use std::net::{Ipv4Addr, Ipv6Addr};
use std::io::{Write};

use {FormatError, Data, len, Packet, Record, Question};
use rust::{WriteExt2};

pub fn packet(dst: &mut &mut [u8], p: &Packet) -> Result<(), FormatError> {
    let _ = dst.write_i16_be(p.id).ok();
    let mut flags1 = 0;
    flags1 |= (!p.is_query as u8) << 7;
    flags1 |= (p.kind as u8) << 3;
    flags1 |= (p.is_authorative as u8) << 2;
    flags1 |= (p.truncated as u8) << 1;
    flags1 |= p.recursion_desired as u8;
    let _ = dst.write_u8(flags1).ok();
    let mut flags2 = 0;
    flags2 |= (p.recursion_available as u8) << 7;
    flags2 |= p.response_code as u8;
    let _ = dst.write_u8(flags2).ok();
    let _ = dst.write_u16_be(p.question.len() as u16).ok();
    let _ = dst.write_u16_be(p.answer.len() as u16).ok();
    let _ = dst.write_u16_be(p.authority.len() as u16).ok();
    let _ = dst.write_u16_be(p.additional.len() as u16).ok();

    for q in &p.question { try!(question(dst, q)); }
    for r in &p.answer { try!(record(dst, r)); }
    for r in &p.authority { try!(record(dst, r)); }
    for r in &p.additional { try!(record(dst, r)); }
    
    Ok(())
}

fn question(dst: &mut &mut [u8], q: &Question) -> Result<(), FormatError> {
    try!(domain_name(dst, &q.name));
    let _ = dst.write_u16_be(q.ty as u16);
    let _ = dst.write_u16_be(q.class as u16);
    Ok(())
}

fn record(dst: &mut &mut [u8], r: &Record) -> Result<(), FormatError> {
    try!(domain_name(dst, &r.name));
    let _ = dst.write_u16_be(r.data.to_type() as u16);
    let _ = dst.write_u16_be(r.class as u16);
    let _ = dst.write_i32_be(r.time_to_live.num_seconds() as i32);
    let _ = dst.write_u16_be(len::data(&r.data) as u16);
    data(dst, &r.data)
}

fn data(dst: &mut &mut [u8], d: &Data) -> Result<(), FormatError> {
    match *d {
        Data::A(ip)                      => a(dst, &ip),
        Data::Aaaa(ip)                   => aaaa(dst, &ip),
        Data::Mx(preference, ref domain) => mx(dst, preference, domain),
        Data::Ptr(ref domain)            => ptr(dst, domain),
        Data::Rp(ref mbox, ref txt)      => rp(dst, mbox, txt),
        Data::Txt(ref text)              => txt(dst, text),
    }
}

fn a(dst: &mut &mut [u8], ip: &Ipv4Addr) -> Result<(), FormatError> {
    let octets = ip.octets();
    for &oct in octets.iter() {
        let _ = dst.write_u8(oct);
    }
    Ok(())
}

fn aaaa(dst: &mut &mut [u8], ip: &Ipv6Addr) -> Result<(), FormatError> {
    let segments = ip.segments();
    for &seg in segments.iter() {
        let _ = dst.write_u16_be(seg);
    }
    Ok(())
}

fn mx(dst: &mut &mut [u8], preference: i16, domain: &str) -> Result<(), FormatError> {
    let _ = dst.write_i16_be(preference);
    domain_name(dst, domain)
}

fn ptr(dst: &mut &mut [u8], domain: &str) -> Result<(), FormatError> {
    domain_name(dst, domain)
}

fn rp(dst: &mut &mut [u8], mbox: &str, txt: &str) -> Result<(), FormatError> {
    try!(domain_name(dst, mbox));
    domain_name(dst, txt)
}

fn txt(dst: &mut &mut [u8], s: &[String]) -> Result<(), FormatError> {
    for s in s {
        try!(character_string(dst, s));
    }
    Ok(())
}

fn domain_name(dst: &mut &mut [u8], s: &str) -> Result<(), FormatError> {
    for part in s.split('.') {
        if part.len() > 63 {
            return Err(FormatError::Label(part.len()));
        }
        let _ = dst.write_u8(part.len() as u8);
        let _ = dst.write_all(part.as_bytes());
    }
    let _ = dst.write_u8(0);
    Ok(())
}

fn character_string(dst: &mut &mut [u8], s: &str) -> Result<(), FormatError> {
    if s.len() > 255 {
        return Err(FormatError::String(s.len()));
    }
    let _ = dst.write_u8(s.len() as u8);
    let _ = dst.write(s.as_bytes());
    Ok(())
}
