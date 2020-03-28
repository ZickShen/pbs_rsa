
use num_bigint::traits::ModInverse;
use num_bigint::{RandPrime, BigUint};
use num_traits::{FromPrimitive, One, Zero};
use rand::{rngs::ThreadRng, Rng};
use crate::errors::{Error, Result};
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
    primes: Vec<BigUint>
}

pub struct Signature {
    /// common massage
    a: String,
    c: BigUint,
    s: BigUint
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
        let k = PublicKey{ n, e };
        check_public(&k)?;

        Ok(k)
    }
    pub fn verify(
        &self,
        message: String,
        sig: &Signature
    ) -> Result<()> {
            if 1 == 1 {
                return Err(Error::InputNotHashed);
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
    pub fn new<R: Rng>(
        rng: &mut R,
        bit_size: usize
    ) -> Result<PrivateKey>{
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

    pub fn from_components(
        n: BigUint,
        e: BigUint,
        d: BigUint,
        primes: Vec<BigUint>,
    ) -> PrivateKey {
        let mut k = PrivateKey {
            n,
            e,
            d,
            primes,
        };

        k
    }
    /// Returns the private exponent of the key.
    pub fn d(&self) -> &BigUint {
        &self.d
    }

    /// Returns the prime factors.
    pub fn primes(&self) -> &[BigUint] {
        &self.primes
    }
    
    pub fn n(&self) -> &BigUint {
        &self.n
    }
    pub fn e(&self) -> &BigUint {
        &self.e
    }

    pub fn sign(
        &self,
        a: String,
        alpha: BigUint,
        beta: BigUint,
        x: BigUint
    ) -> (BigUint, BigUint) {
        (BigUint::zero(), BigUint::zero())
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

#[cfg(test)]
mod tests{
    use super::*;
    use crypto::sha2::Sha256;
    use crypto::digest::Digest;
    use std::str::FromStr;

    #[test]
    fn test_hash_impl(){
        let mut hasher = Sha256::new();
        hasher.input_str("test_case");
        let hex = hasher.result_str();
        assert_eq!(hex,
            "f01d7c4585b2b2aa40bfe9c729191bb7d6c230a4ecbbe0f8fdfaeef56b855814");
    }

    #[test]
    fn test_verify(){
        let public_key = PublicKey::new(
            BigUint::from_str("17550462670900114315516912958852143538392831931877772722697791463617338848541811052799300109603543550406467794435076856711020110361262889550286150452663063907990590001843903680130672156518792141382510903870929213506968311813342847663784195640778726973101641068937677281753156931529086061036396705457558128566292160020517151288689414390019767935316449066876197044244226370574341791635688838399293381261654774226174956761038829654014545328554726295437597921123898383906814203545260227854277947091622544208632979741641570129577870996921678531559885800790891181660659883008833028698373869508120206597163684072648489631689").unwrap(),
            BigUint::from_str("65537").unwrap()
        ).unwrap();
        let want_sig = Signature{
            a: "test_case".to_string(),
            c: BigUint::from_str("10916493395836605395940068713220040225479877628469359860815830724454244960145138341291125639672178075737060865426968441801349448209307493915432881909058335477963144782683945050947332300891139333064803210092878927246243287223787755915062338476347479644347780647597843345265207196565395330309866188679899054643041314783738435672853369585742435321106501831930213765695074834526120568061783224803038245947255804046015554935549436673455209368734263078195183856452081136578469384150910237377173174799939300985003481762852129492195365825738536333367358955369756090804965727493117758037646966969799799484888828106318796094777").unwrap(),
            s: BigUint::from_str("7295011630424823998555001642254372585459278059409240672771972721639035959179826459530740688073129189700694158715168375369751197617237993628366667003973542155488808814022079414288108004550507960345729317118308104707000933461491689430218887299542186686977977129415530259000262285702450544881144654051955930885572061614549449301008237943865032925091100859744915386794889287739372049516661307481029746985065319365402334092938879275912784344709948463175840750268915920986124529630494095801143081502157294414414210882570908132282807231374147615342279055416709920976255341226219224574473132218899290657824723098939379451001").unwrap()
        };
        let wrong_sig = Signature{
            a: "testt_case".to_string(),
            c: BigUint::from_str("10916493395836605395940068713220040225479877628469359860815830724454244960145138341291125639672178075737060865426968441801349448209307493915432881909058335477963144782683945050947332300891139333064803210092878927246243287223787755915062338476347479644347780647597843345265207196565395330309866188679899054643041314783738435672853369585742435321106501831930213765695074834526120568061783224803038245947255804046015554935549436673455209368734263078195183856452081136578469384150910237377173174799939300985003481762852129492195365825738536333367358955369756090804965727493117758037646966969799799484888828106318796094777").unwrap(),
            s: BigUint::from_str("7295011630424823998555001642254372585459278059409240672771972721639035959179826459530740688073129189700694158715168375369751197617237993628366667003973542155488808814022079414288108004550507960345729317118308104707000933461491689430218887299542186686977977129415530259000262285702450544881144654051955930885572061614549449301008237943865032925091100859744915386794889287739372049516661307481029746985065319365402334092938879275912784344709948463175840750268915920986124529630494095801143081502157294414414210882570908132282807231374147615342279055416709920976255341226219224574473132218899290657824723098939379451001").unwrap()
        };
        assert_eq!(public_key.verify(
            "message".to_string(),
            &want_sig
        ).is_ok(), true);
        assert_eq!(public_key.verify(
            "message".to_string(),
            &wrong_sig
        ).is_ok(), false);
    }
}