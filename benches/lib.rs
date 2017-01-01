#![feature(test)]
extern crate path;
extern crate test;

use test::Bencher;
use path::{Path, Identifier};
use std::net::{IpAddr, Ipv4Addr};

fn get_identifier() -> Identifier<u8> {
    Identifier::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    1234,
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    443,
                    16)
}

#[bench]
fn single_connection(bencher: &mut Bencher) {
    let mut path: Path<u8, ()> = Path::new();
    let identifier = get_identifier();

    bencher.iter(|| {
        assert!(path.track(&identifier).is_ok());
    });
}

#[bench]
fn thousand_connections(bencher: &mut Bencher) {
    let mut path: Path<u8, ()> = Path::new();
    let mut identifier = get_identifier();

    bencher.iter(|| {
        for i in 1..1001 {
            identifier.lower.port = i;
            assert!(path.track(&identifier).is_ok());
        }
    });
}

#[bench]
fn last_mut(bencher: &mut Bencher) {
    let mut path: Path<u8, ()> = Path::new();
    let mut identifier = get_identifier();

    for i in 1..1000 {
        identifier.lower.port = i;
        path.track(&identifier).expect("Tracking failed");
    }

    bencher.iter(|| {
        assert!(path.last_mut().is_some());
    });
}
