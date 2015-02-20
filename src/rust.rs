use std::io::{self, Write, Read};

pub trait WriteExt2: Write {
    fn write_u32_be(&mut self, val: u32) -> io::Result<()> {
        let buf = [(val >> 24) as u8, (val >> 16) as u8, (val >> 8) as u8, val as u8];
        self.write_all(&buf)
    }

    fn write_i32_be(&mut self, val: i32) -> io::Result<()> {
        self.write_u32_be(val as u32)
    }

    fn write_u16_be(&mut self, val: u16) -> io::Result<()> {
        let buf = [(val >> 8) as u8, val as u8];
        self.write_all(&buf)
    }

    fn write_i16_be(&mut self, val: i16) -> io::Result<()> {
        self.write_u16_be(val as u16)
    }

    fn write_u8(&mut self, val: u8) -> io::Result<()> {
        self.write_all(&[val])
    }
}

impl<T: Write> WriteExt2 for T { }

pub trait ReadExt2: Read {
    fn read_u32_be(&mut self) -> io::Result<u32> {
        let mut buf = [0; 4];
        try!(self.read(&mut buf));
        Ok((buf[0] as u32) << 24 | (buf[1] as u32) << 16 | (buf[2] as u32) << 8
            | buf[3] as u32)
    }

    fn read_i32_be(&mut self) -> io::Result<i32> {
        self.read_u32_be().map(|v| v as i32)
    }

    fn read_u16_be(&mut self) -> io::Result<u16> {
        let mut buf = [0; 2];
        try!(self.read(&mut buf));
        Ok((buf[0] as u16) << 8 | buf[1] as u16)
    }

    fn read_i16_be(&mut self) -> io::Result<i16> {
        self.read_u16_be().map(|v| v as i16)
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0];
        try!(self.read(&mut buf));
        Ok(buf[0])
    }
}

impl<T: Read> ReadExt2 for T { }

#[macro_export]
macro_rules! trycvt {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(_) => return Err(::std::default::Default::default()),
        }
    }
}
