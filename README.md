# path
[![Build Status](https://travis-ci.org/saschagrunert/path.svg)](https://travis-ci.org/saschagrunert/path) [![Build status](https://ci.appveyor.com/api/projects/status/kqw79om66jb44oaw?svg=true)](https://ci.appveyor.com/project/saschagrunert/path) [![Coverage Status](https://coveralls.io/repos/github/saschagrunert/path/badge.svg?branch=master)](https://coveralls.io/github/saschagrunert/path?branch=master) [![master doc path](https://img.shields.io/badge/master_doc-path-blue.svg)](https://saschagrunert.github.io/path) [![License MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/saschagrunert/path/blob/master/LICENSE) [![Crates.io](https://img.shields.io/crates/v/path.svg)](https://crates.io/crates/path) [![doc.rs](https://docs.rs/path/badge.svg)](https://docs.rs/path)
## [IP](https://en.wikipedia.org/wiki/Internet_Protocol) based connection identification and tracing
This crate is highly inspired by the [netfilter](http://www.netfilter.org/) project, which provides connection tracking
for [TCP/IP](https://en.wikipedia.org/wiki/Internet_protocol_suite) based protocols. The timeout of a connection
(per default 10 minutes) is handled completely internally by using the [time](https://crates.io/crates/time) crate.

# Example usage
```rust
use path::{Path, Identifier};
use std::net::{IpAddr, Ipv4Addr};

// Create a new `Path` for tracking `u8` values as custom data
let mut path :Path<u8, u8> = Path::new();

// Build up a new identifier from IP Addresses, their ports, and a key (in this case the IP Protocol)
let identifier = Identifier::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234,
                                 IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443,
                                 6);

// Do the actual work
let connection = path.track(identifier).unwrap();

// Now it is possible to set/get the custom data
assert_eq!(connection.data.custom, None);
assert_eq!(connection.data.packet_counter, 1);
```
