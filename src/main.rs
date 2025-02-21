//! # Multisignature System Example
//!
//! This Rust program demonstrates a simple implementation of a multisignature (multisig) system
//! using the `secp256k1` cryptographic library. The program generates cryptographic key pairs
//! for three participants and allows them to collectively sign a message. The multisig system
//! requires a threshold number of signatures to verify the message successfully.
//!
//! ## Key Components
//!
//! - **Key Generation**: The program generates a pair of secret and public keys for each participant
//!   using the `secp256k1` library.
//!
//! - **Multisig Structure**: The `Multisig` struct manages the public keys, collected signatures,
//!   and the threshold required for verification.
//!
//! - **Message Signing**: A message is hashed using SHA-256, and each participant signs the message
//!   with their secret key.
//!
//! - **Signature Verification**: The program verifies the collected signatures against the threshold.
//!   If the number of valid signatures meets or exceeds the threshold, the verification succeeds.
//!
//! ## Usage
//!
//! - **Main Function**: The main function orchestrates the key generation, message signing, and
//!   verification process. It outputs whether the multisignature verification succeeded or failed.
//!
//! - **Tests**: The program includes a test module to validate key generation and multisig functionality.
//!
//! ## Dependencies
//!
//! - **secp256k1**: A library for elliptic curve cryptography.
//! - **bitcoin_hashes**: A library for hashing, used here for SHA-256 hashing.
//!
//! This program serves as a basic example of implementing a multisignature system in Rust, suitable
//! for educational purposes or as a starting point for more complex cryptographic applications.

use bitcoin_hashes::sha256;
use multisig::Multisig;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1};

pub mod multisig;

fn main() {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    // Generate keys for participants
    let (secret_key1, public_key1) = secp.generate_keypair(&mut rng);
    let (secret_key2, public_key2) = secp.generate_keypair(&mut rng);
    let (secret_key3, public_key3) = secp.generate_keypair(&mut rng);

    let pub_keys = vec![public_key1, public_key2, public_key3];
    let threshold = 2;

    let mut multisig = Multisig::new(pub_keys, threshold);

    // Create a message for signing
    let message_hash = sha256::Hash::hash(b"Hello, multisig!");
    let message = Message::from_digest(message_hash.to_byte_array());

    // Sign the message by participants
    let signature1 = secp.sign_ecdsa(&message, &secret_key1);
    let signature2 = secp.sign_ecdsa(&message, &secret_key2);
    let signature3 = secp.sign_ecdsa(&message, &secret_key3);

    multisig.add_signature(signature1);
    multisig.add_signature(signature2);
    multisig.add_signature(signature3);

    // Verify the multisignature
    if multisig.verify(&message) {
        println!("Multisig verification succeeded!");
    } else {
        println!("Multisig verification failed!");
    }
}

#[cfg(test)]
mod tests;
