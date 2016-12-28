#![feature(test)]
extern crate path;
extern crate test;

use test::Bencher;
use path::{Path, Identifier};
use std::net::{IpAddr, Ipv4Addr};

#[bench]
fn single_connection(bencher: &mut Bencher) {
    let mut path :Path<u8, u8> = Path::new();
    let identifier = Identifier::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                     1234,
                                     IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                     443,
                                     16);

    bencher.iter(|| {
        assert!(path.track(&identifier).is_ok());
    });
}
