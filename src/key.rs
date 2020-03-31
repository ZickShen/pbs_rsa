
use num_bigint_dig::traits::ModInverse;
use num_bigint::{RandPrime, BigUint};
use num_traits::{Num, FromPrimitive, One, Zero};
use rand::{Rng};
use crypto::sha2::Sha256;
use crypto::digest::Digest;
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
    pub a: String,
    pub c: BigUint,
    pub s: BigUint
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
        PrivateKey {
            n,
            e,
            d,
            primes,
        }
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
    
    pub fn sign(
        &self,
        a: String,
        alpha: BigUint,
        beta: BigUint,
        x: BigUint
    ) -> (BigUint, BigUint) {
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

    #[test]
    fn test_sign(){
        let private_key = PrivateKey::from_components(
            BigUint::from_str("17550462670900114315516912958852143538392831931877772722697791463617338848541811052799300109603543550406467794435076856711020110361262889550286150452663063907990590001843903680130672156518792141382510903870929213506968311813342847663784195640778726973101641068937677281753156931529086061036396705457558128566292160020517151288689414390019767935316449066876197044244226370574341791635688838399293381261654774226174956761038829654014545328554726295437597921123898383906814203545260227854277947091622544208632979741641570129577870996921678531559885800790891181660659883008833028698373869508120206597163684072648489631689").unwrap(),
            BigUint::from_str("65537").unwrap(),
            BigUint::from_str("6549991096137233868551019638686003002968556330344667028159135776868280374391323321794071766800327627132639513314426123232599003300824404771509970763411292554214288735448678458158232910818211651221063432836093468318155209097800520484741407772369911394099410087510057656505492552119717349999072692048559047051226165628043023884031069097219787855679219783647384857645949464090851157705516784303212090347050663204705923364838000045175378147456137939770436002922731036038723768092361473051510791713277895990054719246873050193644308998032015177560795039264571385467008158135283147915628362935728925204517747260153147286365").unwrap(),
            vec![
                BigUint::from_str("174755070353196704247496109946200316091202072887326790114589179365117900648782279411155944779450333985813623948826815809319004822220058595391388480872630257173537931621756391239475281441637628007147262392744479992943735283008412127082308019617433434605806995310682386710854430134211930504877959118292715715447").unwrap(),
                BigUint::from_str("100428918230692542341089324495120556890358938021796317519694428703720300384410402445367463667508037507346405809415987475642890862038788385326267319823326513876256786684160696691794253347229551325562084523257485470013788242470272876868034280282897426136118938652316729523946275233147551159603293040186886647487").unwrap()
            ]);
        let (beta_invert, t) = private_key.sign(
            "test_case".to_string(),
            BigUint::from_str("3901299069153363958344330320245598303021500586753787320771731775495059956717332029019162090693929340327005241354267368196020351734183420216444083367055750126081350512361530442922450504485698719979749675864850997705708794663012728587597919939511366645150072691766077993787269004315054515240604192832582400684122999657724120694049766920310185086388844169849254530441494262288412461654196883486143916209704623875347971785695825567520540217429842406957890905775212215715828871451878135530548639083784982049408382335564750198687626285729999781411843488193676055759654408650673762066179185498209444056769616774794795841304").unwrap(),
            BigUint::from_str("8211154237262957750824851398649095727045018803402529353187527603005290757573654932004701585362181347952480873725915652872750202928387856062729728261531329791837548501557463375448077650624584424530785306286515944850179203110861077726625285942861036980364696517911090106034122821584168249434437139716863949609694773805313428499115269316992155377942213701365743483079356569984376295260330283680361443490966922216007971501891116976591819165328308484009578737525182275450690307196713071330582089521781699069280258535671743727125362043227763208985308537752600848446969277453254461416415659469630008973951532595934822447162").unwrap(),
            BigUint::from_str("14760395973925000324994643308218898334154912925660457879054681888068656443613089025583724296719402529682905746522039690764839299993908031755649840928728763008660809072616773291215536243890045109542798607083708210884608930475056882300685313079655831097309590370730963405980806681137934242500637882044226055135617833822168714094315209540754543414896434199774005501832393960875023764818950242672530222966609822365768960353128674211049325564004944977158530231453745458663292832741099325952319445382927367130311533249827895582906922607463196545988198198451286156813076442616545410920252680325024493552112412709107394443586").unwrap()
        );
        assert_eq!(
            beta_invert,
            BigUint::from_str("15518692078973307646889098766559556512584801591808501629537465220072903843497618395704113084037727669461348488692341872194170326454813615558200121525750863954066355077472742408857184692853474648186596820066227287310675969375577754361955669851768135772898012705576121282195638586463080918773012256237405732170989482277537625417482536712228362886917297635957902556480191677976598998129490449470922429525546526456801545968496500464672199922434235441651648605021607121274993866338056653475663923537291565046872483153387030641269182479460546093819315170940492479431486454023430661788552014216446478085071207358973619332998").unwrap()
        );
        assert_eq!(
            t,
            BigUint::from_str("2985514416717570786012078216252434627016593895731050718314630390404258026559599222192372176991038024379254562314047229929444155057803238947856189691162735241525163358546682468445675327711716602506904741128160665342898958144111996325177136468977209389447655604558105474937265823733492833844358226724441799943703723533571617213294012211311051227894984044859925093176022211245083747011758738244175331783333447032818684328438379678797641569334707282306818268663268192509982985051676666037952109879713970706707899658515627164210426882747630408332514428996432567872350272399710380905785198648034451535906453199445334661986").unwrap()
        );
    }
}