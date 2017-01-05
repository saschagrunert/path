extern crate path;
use path::{Path, Connection, Identifier, Data};
use path::error::ErrorType;

use std::net::{IpAddr, Ipv4Addr};
use std::error::Error;

extern crate time;
use time::Duration;

extern crate log;
use log::LogLevel;

fn get_identifier() -> Identifier<u8> {
    Identifier::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    1234,
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    443,
                    6)
}

#[test]
fn path_success() {
    let mut path: Path<u8, ()> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();
    println!("{}", identifier);

    for i in 1..10 {
        let connection = path.track(identifier.clone()).unwrap();
        assert_eq!(connection.data.packet_counter(), i);
        let connection = Connection::new(&identifier, connection.data);
        println!("{}", connection);
    }
}

#[test]
fn path_success_data() {
    let mut path: Path<u8, u8> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();
    println!("{}", identifier);

    for i in 1..10 {
        let connection = path.track(identifier.clone()).unwrap();
        match i {
            1 => assert_eq!(connection.data.custom, None),
            _ => assert_eq!(connection.data.custom, Some(i - 1)),
        }
        connection.data.custom = Some(i);
        assert_eq!(connection.data.packet_counter() as u8, i);
        let connection = Connection::new(&identifier, connection.data);
        println!("{}", connection);
    }
}

#[test]
fn path_success_pop_front() {
    let mut path: Path<u8, ()> = Path::new().set_log_level(LogLevel::Trace);
    path.max_connections = 1;
    let mut identifier = get_identifier();

    for i in 1..10 {
        identifier.lower.port = i;
        assert!(path.track(identifier.clone()).is_ok());
        assert_eq!(path.connection_count(), 1);
    }
}

#[test]
fn path_success_remove() {
    let mut path: Path<u8, ()> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();

    assert!(path.track(identifier.clone()).is_ok());
    assert_eq!(path.connection_count(), 1);
    path.remove(&identifier);
    assert_eq!(path.connection_count(), 0);
}

#[test]
fn path_success_flush() {
    let mut path: Path<u8, ()> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();
    path.timeout = Duration::milliseconds(1);

    assert!(path.track(identifier.clone()).is_ok());
    assert_eq!(path.connection_count(), 1);
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_eq!(path.flush().len(), 1);
    assert_eq!(path.connection_count(), 0);
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
fn path_success_get_last_mut() {
    let mut path: Path<u8, ()> = Path::new().set_log_level(LogLevel::Trace);
    let mut identifier = get_identifier();
    assert!(path.track(identifier.clone()).is_ok());
    identifier.lower.port = identifier.lower.port + 1;
    assert!(path.track(identifier.clone()).is_ok());
    assert_eq!(path.last_mut().unwrap().identifier, &identifier);
}


#[test]
fn path_failure_compare_identifiers() {
    let mut identifier = get_identifier();
    identifier.lower.port -= 1;
    assert!(identifier != get_identifier());
}

#[test]
fn path_failure_compare_data() {
    let data1: Data<()> = Data::new();
    let data2: Data<()> = Data::new();
    assert!(data1 != data2);
}

#[test]
fn path_failure_compare_connection() {
    let mut data1: Data<()> = Data::new();
    let mut data2: Data<()> = Data::new();
    let identifier = get_identifier();
    let c1 = Connection::new(&identifier, &mut data1);
    let c2 = Connection::new(&identifier, &mut data2);
    assert!(c1 != c2);
}

#[test]
fn path_failure_timeout() {
    let mut path: Path<u8, ()> = Path::new().set_log_level(LogLevel::Trace);
    let identifier = get_identifier();
    path.timeout = Duration::zero();
    assert!(path.track(identifier.clone()).is_ok());

    // Should timeout
    let res = path.track(identifier);
    assert!(res.is_err());
    if let Err(e) = res {
        assert_eq!(e.code, ErrorType::Timeout);
        println!("{}", e);
        println!("{}", e.description());
        println!("{:?}", e);
    }
}
