#[macro_use]
extern crate lazy_static;
extern crate num_bigint_dig as num_bigint;

#[cfg(feature = "serde")]
extern crate serde_crate;

#[cfg(test)]
extern crate hex;
#[cfg(all(test, feature = "serde"))]
extern crate serde_test;

pub mod errors;

mod key;

pub use self::key::{PublicKey, PrivateKey, Signature};
