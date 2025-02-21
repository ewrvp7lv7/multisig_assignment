# Multisignature System Example

This Rust program demonstrates a simple implementation of a multisignature (multisig) system using the `secp256k1` cryptographic library. The program generates cryptographic key pairs for three participants and allows them to collectively sign a message. The multisig system requires a threshold number of signatures to verify the message successfully.

## Key Components

- **Key Generation**: The program generates a pair of secret and public keys for each participant using the `secp256k1` library.

- **Multisig Structure**: The `Multisig` struct manages the public keys, collected signatures, and the threshold required for verification.

- **Message Signing**: A message is hashed using SHA-256, and each participant signs the message with their secret key.

- **Signature Verification**: The program verifies the collected signatures against the threshold. If the number of valid signatures meets or exceeds the threshold, the verification succeeds.

## Usage

- **Main Function**: The main function orchestrates the key generation, message signing, and verification process. It outputs whether the multisignature verification succeeded or failed.

- **Tests**: The program includes a test module to validate key generation and multisig functionality.

## Dependencies

- **secp256k1**: A library for elliptic curve cryptography.
- **bitcoin_hashes**: A library for hashing, used here for SHA-256 hashing.

This program serves as a basic example of implementing a multisignature system in Rust, suitable for educational purposes or as a starting point for more complex cryptographic applications.

## Building and Running

To build and run the project:

```bash
cargo build
cargo run
```

To run the tests:

```bash
cargo test
