use crate::errors::{Error, Result};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num_bigint::{BigUint, RandPrime};
use num_bigint_dig::traits::ModInverse;
use num_traits::{FromPrimitive, Num, One, Zero};
use rand::Rng;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
use zeroize::Zeroize;

lazy_static! {
  static ref MIN_PUB_EXPONENT: BigUint = BigUint::from_u64(2).unwrap();
  static ref MAX_PUB_EXPONENT: BigUint = BigUint::from_u64(1 << (31 - 1)).unwrap();
}

/// Default exponent for RSA keys.
const EXP: u64 = 65537;

/// Represents the public part of an RSA key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
  feature = "serde",
  derive(Serialize, Deserialize),
  serde(crate = "serde_crate")
)]
pub struct PublicKey {
  n: BigUint,
  e: BigUint,
}

/// Represents a whole RSA key, public and private parts.
#[derive(Debug, Clone)]
#[cfg_attr(
  feature = "serde",
  derive(Serialize, Deserialize),
  serde(crate = "serde_crate")
)]
pub struct PrivateKey {
  /// Modulus
  n: BigUint,
  /// Public exponent
  e: BigUint,
  /// Private exponent
  d: BigUint,
  /// Prime factors of N, contains 2 elements.
  primes: Vec<BigUint>,
}

pub struct Signature {
  /// common massage
  pub a: String,
  pub c: BigUint,
  pub s: BigUint,
}

impl PartialEq for PrivateKey {
  #[inline]
  fn eq(&self, other: &PrivateKey) -> bool {
    self.n == other.n && self.e == other.e && self.d == other.d && self.primes == other.primes
  }
}

impl Eq for PrivateKey {}

impl Zeroize for PrivateKey {
  fn zeroize(&mut self) {
    self.d.zeroize();
    for prime in self.primes.iter_mut() {
      prime.zeroize();
    }
    self.primes.clear();
  }
}

impl Drop for PrivateKey {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl PublicKey {
  pub fn new(n: BigUint, e: BigUint) -> Result<Self> {
    let k = PublicKey { n, e };
    check_public(&k)?;

    Ok(k)
  }
  pub fn verify(&self, message: String, sig: &Signature) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.input_str(&message);
    let m = hasher.result_str();
    let m = BigUint::from_str_radix(&m, 16).unwrap();
    hasher.reset();
    hasher.input_str(&sig.a);
    let a = hasher.result_str();
    let a = BigUint::from_str_radix(&a, 16).unwrap();

    let left = sig.s.modpow(self.e(), self.n());
    let mid_val = sig.c.modpow(&BigUint::from_u64(2).unwrap(), self.n()) + BigUint::one();
    let mid_val = mid_val.modpow(&BigUint::from_u64(2).unwrap(), self.n());
    let mut right = a * m.modpow(&BigUint::from_u64(2).unwrap(), self.n()) * mid_val;
    right %= self.n();

    if left != right {
      return Err(Error::Verification);
    }
    Ok(())
  }
  pub fn n(&self) -> &BigUint {
    &self.n
  }
  pub fn e(&self) -> &BigUint {
    &self.e
  }
}

impl PrivateKey {
  pub fn new<R: Rng>(rng: &mut R, bit_size: usize) -> Result<PrivateKey> {
    let nprimes = 2;
    if bit_size < 64 {
      let prime_limit = (1u64 << (bit_size / nprimes) as u64) as f64;

      // pi aproximates the number of primes less than prime_limit
      let mut pi = prime_limit / (prime_limit.ln() - 1f64);
      // Generated primes start with 0b11, so we can only use a quarter of them.
      pi /= 4f64;
      // Use a factor of two to ensure taht key generation terminates in a
      // reasonable amount of time.
      pi /= 2f64;

      if pi < nprimes as f64 {
        return Err(Error::TooFewPrimes);
      }
    }

    let mut primes = vec![BigUint::zero(); nprimes];
    let n_final: BigUint;
    let d_final: BigUint;

    'next: loop {
      let mut todo = bit_size;
      // `gen_prime` should set the top two bits in each prime.
      // Thus each prime has the form
      //   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
      // And the product is:
      //   P = 2^todo × α
      // where α is the product of nprimes numbers of the form 0.11...
      //
      // If α < 1/2 (which can happen for nprimes > 2), we need to
      // shift todo to compensate for lost bits: the mean value of 0.11...
      // is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
      // will give good results.
      if nprimes >= 7 {
        todo += (nprimes - 2) / 5;
      }

      for (i, prime) in primes.iter_mut().enumerate() {
        *prime = rng.gen_prime(todo / (nprimes - i));
        todo -= prime.bits();
      }

      // Makes sure that primes is pairwise unequal.
      for (i, prime1) in primes.iter().enumerate() {
        for prime2 in primes.iter().take(i) {
          if prime1 == prime2 {
            continue 'next;
          }
        }
      }

      let mut n = BigUint::one();
      let mut totient = BigUint::one();

      for prime in &primes {
        n *= prime;
        totient *= prime - BigUint::one();
      }

      if n.bits() != bit_size {
        // This should never happen for nprimes == 2 because
        // gen_prime should set the top two bits in each prime.
        // For nprimes > 2 we hope it does not happen often.
        continue 'next;
      }

      let exp = BigUint::from_u64(EXP).expect("invalid static exponent");
      if let Some(d) = exp.mod_inverse(totient) {
        n_final = n;
        d_final = d.to_biguint().unwrap();
        break;
      }
    }

    Ok(PrivateKey::from_components(
      n_final,
      BigUint::from_u64(EXP).expect("invalid static exponent"),
      d_final,
      primes,
    ))
  }

  pub fn from_components(n: BigUint, e: BigUint, d: BigUint, primes: Vec<BigUint>) -> PrivateKey {
    PrivateKey { n, e, d, primes }
  }
  pub fn n(&self) -> &BigUint {
    &self.n
  }
  pub fn e(&self) -> &BigUint {
    &self.e
  }
  /// Returns the private exponent of the key.
  pub fn d(&self) -> &BigUint {
    &self.d
  }

  /// Returns the prime factors.
  pub fn primes(&self) -> &[BigUint] {
    &self.primes
  }

  pub fn sign(&self, a: String, alpha: BigUint, beta: BigUint, x: BigUint) -> (BigUint, BigUint) {
    let beta_invert = beta.mod_inverse(self.n()).unwrap();
    let beta_invert = beta_invert.to_biguint().unwrap();
    let mut hasher = Sha256::new();
    hasher.input_str(&a);
    let a = hasher.result_str();
    let a = BigUint::from_str_radix(&a, 16).unwrap();

    let mut mid_val = x.modpow(&BigUint::from_u64(2).unwrap(), self.n()) + BigUint::one();
    mid_val *= beta_invert.modpow(&BigUint::from_u64(2).unwrap(), self.n());
    mid_val *= alpha;
    mid_val = mid_val.modpow(&BigUint::from_u64(2).unwrap(), self.n());
    mid_val *= a;

    let d_1 = self.d() - BigUint::one();

    let t = mid_val.modpow(&d_1, self.n());
    (beta_invert, t)
  }
}

impl From<PrivateKey> for PublicKey {
  fn from(private_key: PrivateKey) -> Self {
    (&private_key).into()
  }
}

impl From<&PrivateKey> for PublicKey {
  fn from(private_key: &PrivateKey) -> Self {
    let n = private_key.n.clone();
    let e = private_key.e.clone();

    PublicKey { n, e }
  }
}

/// Check that the public key is well formed and has an exponent within acceptable bounds.
#[inline]
pub fn check_public(public_key: &PublicKey) -> Result<()> {
  if public_key.e() < &*MIN_PUB_EXPONENT {
    return Err(Error::PublicExponentTooSmall);
  }

  if public_key.e() > &*MAX_PUB_EXPONENT {
    return Err(Error::PublicExponentTooLarge);
  }

  Ok(())
}
