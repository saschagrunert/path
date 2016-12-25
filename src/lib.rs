//! # [IP](https://en.wikipedia.org/wiki/Internet_Protocol) based connection identification and
//! tracing
//!
//! This crate is highly inspired by the [netfilter](http://www.netfilter.org/) project, which
//! provides connection tracking for
//! [TCP/IP](https://en.wikipedia.org/wiki/Internet_protocol_suite) based protocols. The timeout of
//! a connection (per default 10 minutes) is handled completely internally by using the
//! [time](https://crates.io/crates/time) crate.
//!
//! # Example usage
//! ```
//! use path::{Path, Identifier};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! // Create a new `Path` for tracking `u8` values as custom data
//! let mut path :Path<u8, u8> = Path::new();
//!
//! // Build up a new identifier from IP Addresses, their ports, and a key (in this case the IP Protocol)
//! let identifier = Identifier::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234,
//!                                  IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443,
//!                                  6);
//!
//! // Do the actual work
//! let data = path.track(&identifier).unwrap();
//!
//! // Now it is possible to set/get the custom data
//! assert_eq!(data.custom, None);
//! assert_eq!(data.packet_counter, 1);
//! ```
//!
#![deny(missing_docs)]

#[macro_use]
extern crate log;
extern crate fnv;
extern crate time;
extern crate mowl;
extern crate linked_hash_map;

#[macro_use]
pub mod error;
use error::{PathResult, ErrorType};

use std::fmt;
use std::hash::{BuildHasherDefault, Hash};
use std::net::IpAddr;

use time::{Duration, precise_time_ns};
use fnv::FnvHasher;
use linked_hash_map::LinkedHashMap;
use log::LogLevel;

type HashMapFnv<K, C> = LinkedHashMap<Identifier<K>, Data<C>, BuildHasherDefault<FnvHasher>>;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Global connection tracking structure
pub struct Path<K, C>
    where K: Hash + Eq + PartialEq
{
    /// Main storage for all connections
    pub hashmap: HashMapFnv<K, C>,

    /// A general connection timeout, per default 10 minutes
    pub timeout: Duration,

    /// Maximum amount of flows within the HashMap, per default 1 million
    pub max_connections: u64,
}

impl<K, C> Path<K, C>
    where C: Clone,
          K: fmt::Debug + Clone + Hash + Eq + PartialEq
{
    /// Create a new `Path` instance with a timeout of 10 minutes and 1 million connections at a
    /// maximum
    ///
    /// # Examples
    /// ```
    /// use path::Path;
    ///
    /// let path :Path<u8, u8> = Path::new();
    /// ```
    pub fn new() -> Self {
        Path {
            hashmap: HashMapFnv::default(),
            timeout: Duration::minutes(10),
            max_connections: 1_000_000, // 0 == unlimited
        }
    }

    /// Set the global log level for reporting
    ///
    /// # Examples
    /// ```
    /// # extern crate log;
    /// # extern crate path;
    /// # fn main() {
    /// use log::LogLevel;
    /// use path::Path;
    ///
    /// let path :Path<u8, u8> = Path::new().set_log_level(LogLevel::Trace);
    /// # }
    /// ```
    pub fn set_log_level(self, level: LogLevel) -> Self {
        // Setup the logger if not already set
        if mowl::init_with_level(level).is_err() {
            error!("Logger already set.");
        };
        info!("Log level set to: {:?}", level);
        self
    }

    /// Track a connection based on its `Identifier`
    ///
    /// # Examples
    /// ```
    /// use path::{Path, Identifier};
    /// use std::net::{IpAddr, Ipv4Addr};
    ///
    /// let mut path :Path<u8, u8> = Path::new();
    /// let identifier = Identifier::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234,
    ///                                  IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443,
    ///                                  6);
    /// let data = path.track(&identifier).unwrap();
    ///
    /// assert_eq!(data.custom, None);
    /// assert_eq!(data.packet_counter, 1);
    /// ```
    pub fn track(&mut self, identifier: &Identifier<K>) -> PathResult<&mut Data<C>> {
        // Get the current timestamp
        let now = precise_time_ns();

        // Check if the entry already exists and retrieve a connection state
        let connection_state = match self.hashmap.get_refresh(identifier) {
            Some(data) => {
                if Duration::nanoseconds((now - data.timestamp) as i64) <= self.timeout {
                    match data.packet_counter.checked_add(1) {
                        Some(value) => data.packet_counter = value,
                        None => bail!(ErrorType::PacketCounterOverflow, "Packet counter overflow"),
                    }
                    data.timestamp = now;
                    ConnectionState::Ok
                } else {
                    ConnectionState::Timeout
                }
            }
            None => ConnectionState::New,
        };

        // Do something based on the connection state
        match connection_state {

            // Connection timeout happened
            ConnectionState::Timeout => {
                self.hashmap.remove(identifier);
                warn!("Connection removed (timeout): {}", identifier);
                bail!(ErrorType::Timeout, "Connection removed because of timeout");
            }

            // Add a new connection
            ConnectionState::New => {
                // But check first if the HashMap contains available free slots
                if self.max_connections > 0 && self.hashmap.len() as u64 >= self.max_connections {
                    // Remove the oldest not active element from the table (LRU cache)
                    let removed = self.hashmap.pop_front();
                    warn!("Connection removed (HashMap full): {}", removed.unwrap().0);
                }

                // Insert a new connection
                self.hashmap.insert(identifier.clone(), Data::new(now));
                debug!("Connection inserted: {}", identifier);
            }

            // We just need to return a mutable reference to the HashMap value
            ConnectionState::Ok => {}
        }

        // Usually it should be impossible to have no valid entry here
        match self.hashmap.get_mut(identifier) {
            Some(data) => Ok(data),
            None => bail!(ErrorType::Internal, "Could not get connection data."),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Connection representation
pub struct Connection<'a, 'b, K: 'a, C: 'b> {
    /// Identifies the connection
    pub identifier: &'a Identifier<K>,

    /// Data which can be used for the connection
    pub data: &'b mut Data<C>,
}

impl<'a, 'b, K, C> Connection<'a, 'b, K, C> {
    /// Create a new `Connection` from an `Identifier` and `Data`
    pub fn new(identifier: &'a Identifier<K>, data: &'b mut Data<C>) -> Self {
        Connection {
            identifier: identifier,
            data: data,
        }
    }
}

impl<'a, 'b, K, C> fmt::Display for Connection<'a, 'b, K, C>
    where K: fmt::Debug
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// Identifies the connection
pub struct Identifier<K> {
    /// Lower subscriber
    pub lower: Subscriber,

    /// Greater subscriber
    pub greater: Subscriber,

    /// Usually the communication protocol of the subscribers
    pub key: K,
}

impl<K> Identifier<K> {
    /// Create a new `Identifier` from needed connection information
    pub fn new(source_ip: IpAddr, source_port: u16, destination_ip: IpAddr, destination_port: u16, key: K) -> Self {
        let source_tuple = (source_ip, source_port);
        let destination_tuple = (destination_ip, destination_port);
        let connection_tuple = if source_tuple > destination_tuple {
            (destination_tuple, source_tuple)
        } else {
            (source_tuple, destination_tuple)
        };
        Identifier {
            lower: Subscriber {
                address: (connection_tuple.0).0,
                port: (connection_tuple.0).1,
            },
            greater: Subscriber {
                address: (connection_tuple.1).0,
                port: (connection_tuple.1).1,
            },
            key: key,
        }
    }
}

impl<K: fmt::Debug> fmt::Display for Identifier<K> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{}:{} ↹ {}:{} ({:?})",
               self.lower.address,
               self.lower.port,
               self.greater.address,
               self.greater.port,
               self.key)
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
/// Identifies the connection endpoints
pub struct Subscriber {
    /// Address of the subscriber
    pub address: IpAddr,

    /// Communication port
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Identifies the connection
pub struct Data<C> {
    /// Data from the user
    pub custom: Option<C>,

    /// The packet counter for the connection
    pub packet_counter: u64,

    /// Last accessed timestamp
    timestamp: u64,
}

impl<C> Data<C> {
    /// Create new connection data
    pub fn new(timestamp: u64) -> Self {
        Data {
            packet_counter: 1,
            timestamp: timestamp,
            custom: None,
        }
    }
}

/// Available connection states for control flow
enum ConnectionState {
    /// Everything is okay, the connection timestamp has been updated
    Ok,

    /// The connection is new an needs to be inserted into the HashMap
    New,

    /// A timeout occurred and needs to be removed from the HashMap
    Timeout,
}
