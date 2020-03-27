#[macro_use]
extern crate lazy_static;
extern crate num_bigint_dig as num_bigint;
extern crate num_traits;
extern crate num_iter;
extern crate rand;
extern crate subtle;
extern crate zeroize;

#[cfg(feature = "serde")]
extern crate serde_crate;

#[cfg(test)]
extern crate hex;
#[cfg(all(test, feature = "serde"))]
extern crate serde_test;

pub mod errors;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}