extern crate path;
use path::{Path, Connection, Identifier, Data};
use path::error::ErrorType;

use std::net::{IpAddr, Ipv4Addr};
use std::error::Error;

extern crate time;
use time::{Duration, precise_time_ns};

extern crate log;
use log::LogLevel;

fn get_identifier() -> Identifier {
    Identifier::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    1234,
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    443,
                    6)
}

#[test]
fn path_success() {
    let mut path: Path<u8> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();
    println!("{}", identifier);

    for i in 1..10 {
        let data = path.track(&identifier).unwrap();
        assert_eq!(data.packet_counter, i);
        let connection = Connection::new(&identifier, data);
        println!("{}", connection);
    }
}

#[test]
fn path_success_data() {
    let mut path: Path<u8> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();
    println!("{}", identifier);

    for i in 1..10 {
        let data = path.track(&identifier).unwrap();
        match i {
            1 => assert_eq!(data.custom, None),
            _ => assert_eq!(data.custom, Some(i - 1)),
        }
        data.custom = Some(i);
        assert_eq!(data.packet_counter as u8, i);
        let connection = Connection::new(&identifier, data);
        println!("{}", connection);
    }
}

#[test]
fn path_success_pop_front() {
    let mut path: Path<u8> = Path::new().set_log_level(LogLevel::Trace);
    path.max_connections = 1;
    let mut identifier = get_identifier();

    for i in 1..10 {
        identifier.lower.port = i;
        assert!(path.track(&identifier).is_ok());
        assert_eq!(path.hashmap.len(), 1);
    }
}

#[test]
fn path_success_compare_identifiers() {
    let identifier = Identifier::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                     443,
                                     IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                     1234,
                                     6);
    assert_eq!(identifier, get_identifier());
}

#[test]
fn path_failure_compare_identifiers() {
    let mut identifier = get_identifier();
    identifier.lower.port -= 1;
    assert!(identifier != get_identifier());
}

#[test]
fn path_failure_compare_data() {
    let data1: Data<u8> = Data::new(precise_time_ns());
    let data2: Data<u8> = Data::new(precise_time_ns());
    assert!(data1 != data2);
}

#[test]
fn path_failure_compare_connection() {
    let mut data1: Data<u8> = Data::new(precise_time_ns());
    let mut data2: Data<u8> = Data::new(precise_time_ns());
    let identifier = get_identifier();
    let c1 = Connection::new(&identifier, &mut data1);
    let c2 = Connection::new(&identifier, &mut data2);
    assert!(c1 != c2);
}

#[test]
fn path_failure_timeout() {
    let mut path: Path<u8> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();
    path.timeout = Duration::zero();
    assert!(path.track(&identifier).is_ok());

    // Should timeout
    let res = path.track(&identifier);
    assert!(res.is_err());
    if let Err(e) = res {
        assert_eq!(e.code, ErrorType::Timeout);
        println!("{}", e);
        println!("{}", e.description());
        println!("{:?}", e);
    }
}

#[test]
fn path_failure_packet_counter_overflow() {
    let mut path: Path<u8> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();

    {
        let data = path.track(&identifier).unwrap();
        data.packet_counter = u64::max_value();
    }

    // Packet counter should overflow
    let res = path.track(&identifier);
    assert!(res.is_err());
    if let Err(e) = res {
        assert_eq!(e.code, ErrorType::PacketCounterOverflow);
    }
}
