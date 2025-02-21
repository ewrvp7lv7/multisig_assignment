//! # Multisig Module
//!
//! This module provides the implementation of a multisignature (multisig) system.
//! It defines the `Multisig` struct, which manages the public keys, collected signatures,
//! and the threshold required for successful verification of a message.
//!
//! ## Key Features
//!
//! - **Public Key Management**: Stores the public keys of participants involved in the multisig.
//!
//! - **Signature Collection**: Collects signatures from participants and checks if the number
//!   of valid signatures meets the required threshold.
//!
//! - **Threshold Verification**: Verifies if the collected signatures are sufficient to meet
//!   the threshold, ensuring the message is validly signed by the required number of participants.
//!
//! ## Usage
//!
//! The `Multisig` struct can be used to create a new multisig instance, add signatures, and
//! verify if the signatures meet the threshold for a given message.
//!
//! This module is part of a larger example demonstrating a multisignature system using the
//! `secp256k1` cryptographic library in Rust.

use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};

#[derive(Debug)]
pub struct Multisig {
    pub_keys: Vec<PublicKey>,
    signatures: Vec<Signature>,
    threshold: usize,
}

impl Multisig {
    pub fn new(pub_keys: Vec<PublicKey>, threshold: usize) -> Self {
        Multisig {
            pub_keys,
            signatures: Vec::new(),
            threshold,
        }
    }

    pub fn add_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }

    pub fn verify(&self, message: &Message) -> bool {
        if self.signatures.len() < self.threshold {
            return false;
        }

        let secp = Secp256k1::new();
        let mut valid_signatures = 0;

        for (i, signature) in self.signatures.iter().enumerate() {
            if i >= self.threshold {
                break;
            }

            if secp
                .verify_ecdsa(message, signature, &self.pub_keys[i])
                .is_ok()
            {
                valid_signatures += 1;
            }
        }

        valid_signatures >= self.threshold
    }
}
