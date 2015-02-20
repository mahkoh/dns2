//! Toy DNS API. Only available on linux.

use std::net::{IpAddr, UdpSocket};
use std::time::{Duration};
use std::io::{self, BufReader, BufRead};
use std::fs::{File};

use {Data, Packet, Type, Question, Class};

#[cfg(unix)]
fn set_timeout(socket: &mut UdpSocket, mut duration: Duration) -> Result<(), ()> {
    use libc::{timeval, setsockopt, time_t, suseconds_t, socklen_t, c_int, SOL_SOCKET};
    use std::{mem};
    use std::os::unix::{AsRawFd};

    #[cfg(target_os = "linux")]
    const SO_RCVTIMEO: c_int = 20;

    let seconds = duration.num_seconds() as time_t;
    duration = duration - Duration::seconds(duration.num_seconds());
    let useconds = duration.num_microseconds().unwrap() as suseconds_t;

    let fd = socket.as_raw_fd();
    let timeval = timeval {
        tv_sec: seconds,
        tv_usec: useconds,
    };

    unsafe {
        if setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeval as *const _ as *const _,
                      mem::size_of_val(&timeval) as socklen_t) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn get_socket() -> io::Result<UdpSocket> {
    UdpSocket::bind(&(IpAddr::new_v4(0,0,0,0), 0))
}

fn get_ips_int(hostname: &str, timeout: Option<Duration>,
               ty: Type) -> Result<Vec<IpAddr>, ()> {
    let mut res = vec!();
    for data in try!(query_int(hostname, ty, timeout)) {
        match data {
            Data::A(addr) => res.push(IpAddr::V4(addr)),
            Data::Aaaa(addr) => res.push(IpAddr::V6(addr)),
            _ => { },
        }
    }
    Ok(res)
}

#[cfg(unix)]
fn nameservers_int() -> Result<Vec<IpAddr>, ()> {
    let mut res = vec!();
    let mut file = BufReader::new(trycvt!(File::open("/etc/resolv.conf")));
    let mut line = String::new();
    while file.read_line(&mut line).is_ok() {
        if line.len() == 0 {
            break;
        }
        if line.starts_with("nameserver ") {
            if let Ok(ip) = line["nameserver ".len()..].trim().parse() {
                res.push(ip);
            }
        }
        line.truncate(0);
    }
    Ok(res)
}

/// Retrieves a list of nameservers from the OS.
pub fn nameservers() -> Vec<IpAddr> {
    match nameservers_int() {
        Ok(v) => v,
        _ => vec!(),
    }
}

/// Queries a nameserver for the A and AAAA records of this hostname.
pub fn ips(hostname: &str, timeout: Option<Duration>) -> Vec<IpAddr> {
    let mut res = match get_ips_int(hostname, timeout, Type::A) {
        Ok(v) => v,
        _ => vec!(),
    };
    if let Ok(v) = get_ips_int(hostname, timeout, Type::Aaaa) {
        res.extend(v.into_iter());
    }
    res
}

fn query_int(hostname: &str, ty: Type,
                 timeout: Option<Duration>) -> Result<Vec<Data>, ()> {
    let mut socket = trycvt!(get_socket());
    if let Some(t) = timeout {
        try!(set_timeout(&mut socket, t));
    }
    let id = 12345;
    let mut packet = Packet::query(id);
    packet.question.push(Question {
        name: hostname.to_string(),
        ty: ty,
        class: Class::In
    });
    let mut buf = [0; 512];
    let len = trycvt!(packet.format(&mut buf));
    let nameserver = nameservers().into_iter().next().unwrap_or(IpAddr::new_v4(8,8,8,8));
    trycvt!(socket.send_to(&buf[..len], &(nameserver, 53)));
    let len = trycvt!(socket.recv_from(&mut buf)).0;
    let packet = trycvt!(Packet::parse(&buf[..len])).1;
    Ok(packet.answer.into_iter().map(|ans|ans.data).collect())
}

/// Queries a nameserver for the data with type `ty`.
pub fn query(hostname: &str, ty: Type, timeout: Option<Duration>) -> Vec<Data> {
    match query_int(hostname, ty, timeout) {
        Ok(v) => v,
        _ => vec!(),
    }
}
