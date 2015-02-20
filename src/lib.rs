//! Rudimentary DNS library.
//!
//! Provides a simple API for parsing and formatting DNS packets.
//!
//! See RFC 1035 for more details.
//!
//! # Example
//!
//! ```ignore
//! let mut packet = Packet::query(12345);
//! packet.question.push(Question {
//!     name: "google.com".to_string(),
//!     ty: Type::A,
//!     class: Class::In
//! });
//! let mut buf = [0; 512];
//! let len = try!(packet.format(&mut buf));
//! ```
//!
//! # Toy functions
//!
//! On Linux it also provides a toy API for hostname resolution and other things.

#![crate_type = "lib"]
#![crate_name = "dns2"]
#![feature(core)]
#![feature(io)]
#![feature(net)]
#![feature(std_misc)]
#![feature(libc)]
#![feature(fs)]

extern crate libc;

use std::time::{Duration};
use std::net::{Ipv4Addr, Ipv6Addr};

#[macro_use] mod rust;
mod parse;
mod len;
mod format;
#[cfg(target_os = "linux")] pub mod toy;

const IN: u16 = 1;

const A:    u16 = 1;
const AAAA: u16 = 28;
const MX:   u16 = 15;
const PTR:  u16 = 12;
const RP:   u16 = 17;
const TXT:  u16 = 16;
const ALL:  u16 = 255;

/// A DNS packet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Packet {
    /// ID of the packet.
    pub id:                  i16,
    /// Set if this is a query.
    pub is_query:            bool,
    /// Kind of the query.
    pub kind:                QueryKind,
    /// Set if the answer is authoritative.
    pub is_authoritative:    bool,
    /// Set if the packet has been truncated.
    pub truncated:           bool,
    /// Set if recursion is desired for this query.
    pub recursion_desired:   bool,
    /// Set if recursion is available.
    pub recursion_available: bool,
    /// Response code.
    pub response_code:       ResponseCode,

    /// Questions.
    pub question:   Vec<Question>,
    /// Answers.
    pub answer:     Vec<Record>,
    /// Pointers to authorities.
    pub authority:  Vec<Record>,
    /// Additional information.
    pub additional: Vec<Record>,
}

impl Packet {
    /// Parses the bytes in src as a DNS packet.
    ///
    /// # Return value
    ///
    /// Returns the number of bytes read and the packet on success.
    pub fn parse(mut src: &[u8]) -> Result<(usize, Packet), ()> {
        let bac = src;
        let packet = match parse::packet(&mut src) {
            Ok(p) => p,
            _ => return Err(()),
        };
        let len = src.as_ptr() as usize - bac.as_ptr() as usize;
        Ok((len, packet))
    }

    /// Formats the packet into the provided buffer.
    ///
    /// # Return value
    ///
    /// Returns the number of bytes written on success.
    pub fn format(&self, mut dst: &mut [u8]) -> Result<usize, FormatError> {
        let len = len::packet(self);
        if len > 512 {
            return Err(FormatError::Size);
        }
        if len > dst.len() {
            return Err(FormatError::Buffer(len));
        }
        let back = dst.as_ptr() as usize;
        try!(format::packet(&mut dst, self));
        Ok(dst.as_ptr() as usize - back)
    }

    /// Creates a new packet that has all header values preset for a query.
    pub fn query(id: i16) -> Packet {
        Packet {
            id:                  id,
            is_query:            true,
            kind:                QueryKind::Standard,
            is_authoritative:    false,
            truncated:           false,
            recursion_desired:   true,
            recursion_available: false,
            response_code:       ResponseCode::Ok,

            question: vec!(),
            answer: vec!(),
            authority: vec!(),
            additional: vec!(),
        }
    }
}

/// An error that can occur during formatting.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FormatError {
    /// The size of the packet would exceed 512 bytes.
    Size,
    /// The buffer is too small. The argument is the required buffer size.
    Buffer(usize),
    /// One of the domain labels is larger than 63 bytes.
    Label(usize),
    /// A character string is larger than 255 bytes.
    String(usize),
}

/// The kind of the query.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum QueryKind {
    /// Standard query.
    Standard = 0,
    /// Inverse query.
    Inverse  = 1,
    /// Server status request.
    Status   = 2,
}

/// The response code.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ResponseCode {
    /// No error.
    Ok             = 0,
    /// Format error.
    FormatError    = 1,
    /// Server failure.
    ServerFailure  = 2,
    /// Name error.
    NameError      = 3,
    /// Not implemented.
    NotImplemented = 4,
    /// Refused.
    Refused        = 5,
}

/// Type of the record or question.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Type {
    /// IPv4 address.
    A    = A,
    /// IPv6 address.
    Aaaa = AAAA,
    /// Mail exchange.
    Mx   = MX,
    /// Pointer to a domain name.
    Ptr  = PTR,
    /// Responsible person.
    Rp   = RP,
    /// Text.
    Txt  = TXT,
    /// All.
    All  = ALL,
}

/// Class of the request.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Class {
    /// Internet.
    In  = IN,
    /// All.
    All = ALL,
}

/// A question.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Question {
    /// Domain name.
    pub name:  String,
    /// Question type.
    pub ty:    Type,
    /// Question class.
    pub class: Class,
}

/// A record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// Domain name.
    pub name:         String,
    /// Class.
    pub class:        Class,
    /// Time to live.
    pub time_to_live: Duration,
    /// Data.
    pub data:         Data,
}

/// Record data.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Data {
    /// IPv4 address.
    A(Ipv4Addr),
    /// IPv6 address.
    Aaaa(Ipv6Addr),
    /// Mail exchange.
    Mx(i16, String),
    /// Pointer to a domain name.
    Ptr(String),
    /// Responsible person.
    Rp(String, String),
    /// Text.
    Txt(Vec<String>),
}

impl Data {
    /// Returns the type of the data.
    pub fn to_type(&self) -> Type {
        match *self {
            Data::A(..)    => Type::A,
            Data::Aaaa(..) => Type::Aaaa,
            Data::Mx(..)   => Type::Mx,
            Data::Ptr(..)  => Type::Ptr,
            Data::Rp(..)   => Type::Rp,
            Data::Txt(..)  => Type::Txt,
        }
    }
}
