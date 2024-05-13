use rsa::rsa::*;
use rand::{thread_rng, Rng};
use num::{BigUint, BigInt, bigint::RandomBits};
use std::io::stdin;

fn main() {
    println!("Enter an maximum number of bits p and q should use: ");
    let mut num_bits_str = String::new();
    stdin().read_line(&mut num_bits_str).expect("Input IO error.");
    let num_bits: u64 = num_bits_str.trim().parse::<u64>().expect("Invalid input.");

    println!("Generating keys...");
    let keys = KeyPair::generate(num_bits);
    println!("Generated!");
 
    // was going to add encrypted_string and an option
    // but haven't. check out the rng mod.rs for
    // functions that allow you to encrypt and decrypt
    // strings - if you use a small number of bits for
    // p and q it will probably break if the ascii
    // character set exceeds the size of the resulting
    // n.
    encrypted_number(keys, num_bits);
}

fn encrypted_number(keys: KeyPair, num_bits: u64) {
    let mut rng = thread_rng();
    let number: BigUint = rng.sample(RandomBits::new(num_bits));

    let encrypted_number = encrypt_num(number.into(), &keys.public);
    println!("Public key (e, n): ({}, {})", &keys.public.e, &keys.public.n);
    println!("Encrypted number: {}", encrypted_number);

    let mut num_decrypt_guess_str = String::new();
    println!("Enter your guess for the decrypted number: ");
    stdin().read_line(&mut num_decrypt_guess_str).expect("Input IO error.");
    let num_decrypt_guess: BigInt = num_decrypt_guess_str.trim().parse::<BigInt>().expect("Invalid input.");
    let num_decrypt = decrypt_num(encrypted_number, &keys);

    if num_decrypt_guess == num_decrypt {
        println!("Correct! Private key was: ({})", keys.private.d);
    } else {
        println!("Incorrect! Number was: {}, Private key was: ({})", num_decrypt, keys.private.d);
    }
}
