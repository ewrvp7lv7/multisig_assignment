use super::*;
use bitcoin_hashes::sha256;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1};

#[test]
fn test_key_generation() {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    // Generate a key pair
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);

    // Check that the public key corresponds to the private key
    let derived_public_key = PublicKey::from_secret_key(&secp, &secret_key);
    assert_eq!(public_key, derived_public_key);
}

#[test]
fn test_multisig_creation_and_verification() {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    // Generate keys for three participants
    let (secret_key1, public_key1) = secp.generate_keypair(&mut rng);
    let (secret_key2, public_key2) = secp.generate_keypair(&mut rng);
    let (secret_key3, public_key3) = secp.generate_keypair(&mut rng);

    let pub_keys = vec![public_key1, public_key2, public_key3];
    let threshold = 2;

    let mut multisig = Multisig::new(pub_keys, threshold);

    // Create a message for signing
    let message_hash = sha256::Hash::hash(b"Hello, multisig!");
    let message = Message::from_digest(message_hash.to_byte_array());

    // Sign the message by two participants
    let signature1 = secp.sign_ecdsa(&message, &secret_key1);
    let signature2 = secp.sign_ecdsa(&message, &secret_key2);

    multisig.add_signature(signature1);
    multisig.add_signature(signature2);

    // Check the multisignature
    assert!(multisig.verify(&message));

    // Add a third signature (not required for the threshold)
    let signature3 = secp.sign_ecdsa(&message, &secret_key3);
    multisig.add_signature(signature3);

    // Check that the multisignature is still valid
    assert!(multisig.verify(&message));

    // Check with insufficient number of signatures
    let mut multisig_invalid = Multisig::new(vec![public_key1, public_key2, public_key3], 2);
    multisig_invalid.add_signature(signature1);

    assert!(!multisig_invalid.verify(&message));
}

#[test]
fn test_invalid_multisig() {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    // Generate keys for two participants
    let (secret_key1, public_key1) = secp.generate_keypair(&mut rng);
    let (secret_key2, public_key2) = secp.generate_keypair(&mut rng);

    let pub_keys = vec![public_key1, public_key2];
    let threshold = 2;

    let mut multisig = Multisig::new(pub_keys, threshold);

    // Create a message for signing
    let message_hash = sha256::Hash::hash(b"Hello, multisig!");
    let message = Message::from_digest(message_hash.to_byte_array());

    // Sign the message
    let signature = secp.sign_ecdsa(&message, &secret_key1);
    multisig.add_signature(signature);

    // Create a wrong message for signing
    let message_hash = sha256::Hash::hash(b"Hello, multisig! Wrong");
    let message = Message::from_digest(message_hash.to_byte_array());

    // Sign the message
    let signature = secp.sign_ecdsa(&message, &secret_key2);
    multisig.add_signature(signature);

    // Check that the multisignature is invalid
    assert!(!multisig.verify(&message));
}
