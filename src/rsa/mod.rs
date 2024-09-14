use num::{Integer, BigInt, BigUint, bigint::RandomBits, One, Zero};
use rand::Rng;
use num_prime::nt_funcs::is_prime;

#[derive(Debug)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl KeyPair {
    pub fn generate(approx_num_bits: u64) -> Self {
        // generate two large prime numbers
        let p = get_random_prime(approx_num_bits);
        let q = get_random_prime(approx_num_bits);

        // multiply them to get the n component of the public key
        let n = p.clone() * q.clone();

        // apply eulers function to get phi(n)
        let phi_n: BigInt = n.clone() - p - q + 1;

        // start with some e
        let mut e: BigInt;
        if approx_num_bits < 24 {
            e = BigInt::from(2);
        } else {
            e = BigInt::from(65537);
        }
        
        loop {
            // add to e until we get an e that is relatively prime
            // with phi(n)
            if BigInt::gcd(&e, &phi_n).is_one() {
                break;
            }

            e += 1;
        }

        let public = PublicKey {
            e: e.clone(),
            n,
        };

        // find the private key by finding
        // the modular inverse of e
        let d = mod_inv(&e, &phi_n);

        let private = PrivateKey {
            d,
        };

        KeyPair {
            public,
            private,
        }
    }
}

#[derive(Debug)]
pub struct PublicKey {
    pub e: BigInt,
    pub n: BigInt,
}

#[derive(Debug)]
pub struct PrivateKey {
    pub d: BigInt,
}

fn get_random_prime(approx_num_bits: u64) -> BigInt {
    // get some large random number
    let mut rng = rand::thread_rng();
    let mut random_num: BigUint = rng.sample(RandomBits::new(approx_num_bits));

    // some number theory says we can just increase
    // the value and we only have to check
    // at most log(n) before we find some prime
    // number
    loop {
        if is_prime(&random_num, None).probably() {
            break;
        }

        random_num = random_num + BigUint::one();
    }

    random_num.into()
}

fn mod_inv(n: &BigInt, p: &BigInt) -> BigInt {
    // modulo inverse will always be 1 if
    // p is 1
    if p.is_one() { return BigInt::one() }

    let (mut a, mut m, mut x, mut inv) = (n.clone(), p.clone(), BigInt::zero(), BigInt::one());
    while a > BigInt::one() {
        let (div, rem) = a.div_rem(&m);
        inv -= div * &x;
        a = rem;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x, &mut inv);
    }
 
    if inv < BigInt::zero() { inv += p }

    inv
}

// insecure - doesn't chunk text or anything
// pub fn encrypt(plaintext: &str, public_key: &PublicKey) -> Vec<BigInt> {
//     // get the string as bytes,
//     // then for each byte raise it to e and mod n
//     plaintext.bytes()
//         .map(|b| BigInt::from(b).modpow(&public_key.e, &public_key.n))
//         .collect()
// }

pub fn encrypt_num(num: BigInt, public_key: &PublicKey) -> BigInt {
    BigInt::from(num).modpow(&public_key.e, &public_key.n)
}

// insecure - doesn't chunk text or anything
// pub fn decrypt(ciphertext: &Vec<BigInt>, key_pair: &KeyPair) -> String {
//     // for each character in the ciphertext,
//     // raise to d and mod n,
//     // cast to u32,
//     // cast to char,
//     // collect into strng.
//     ciphertext.iter()
//         .map(|c| {
//             char::from_u32(c.modpow(&key_pair.private.d, &key_pair.public.n)
//                 .to_u32()
//                 .unwrap())
//                 .unwrap()
//         })
//         .collect::<String>()
// }

pub fn decrypt_num(ciphertext: BigInt, key_pair: &KeyPair) -> BigInt {
    ciphertext.modpow(&key_pair.private.d, &key_pair.public.n)
}
