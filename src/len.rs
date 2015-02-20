use std::iter::{AdditiveIterator};

use {Data, Packet, Record, Question};

pub fn packet(p: &Packet) -> usize {
    let mut len = 12; // Header size
    for q in &p.question   { len += question(q); }
    for r in &p.answer     { len += record(r);   }
    for r in &p.authority  { len += record(r);   }
    for r in &p.additional { len += record(r);   }
    len
}

fn question(q: &Question) -> usize {
    domain_name(&q.name) + 4
}

fn record(r: &Record) -> usize {
    domain_name(&r.name) + 2 + 2 + 4 + 2 + data(&r.data)
}

pub fn data(d: &Data) -> usize {
    match *d {
        Data::A(..)                 => a(),
        Data::Aaaa(..)              => aaaa(),
        Data::Mx(_, ref domain)     => mx(domain),
        Data::Ptr(ref domain)       => ptr(domain),
        Data::Rp(ref mbox, ref txt) => rp(mbox, txt),
        Data::Txt(ref text)         => txt(text),
    }
}

fn a() -> usize {
    4
}

fn aaaa() -> usize {
    16
}

fn mx(domain: &str) -> usize {
    2 + domain_name(domain)
}

fn ptr(domain: &str) -> usize {
    domain_name(domain)
}

fn rp(mbox: &str, txt: &str) -> usize {
    domain_name(mbox) + domain_name(txt)
}

fn txt(s: &[String]) -> usize {
    s.iter().map(|v| character_string(v)).sum()
}

fn domain_name(s: &str) -> usize {
    let mut len = 0;
    for part in s.split('.') {
        len += 1 + part.len();
    }
    len += 1;
    len
}

fn character_string(s: &str) -> usize {
    1 + s.len()
}
