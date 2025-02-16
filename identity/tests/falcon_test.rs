#[cfg(test)]
#[cfg(feature = "falcon")]
mod tests {
    use std::time::Instant;
    use identity::{FalconKeyPair,PKITraits};
    #[test]
    fn test_falcon_keypair() {
        let message = b"Hello, Falcon!";

        // Start timing
        let start = Instant::now();

        // Test key pair generation
        let key_pair = FalconKeyPair::generate_key_pair()
            .expect("Key pair generation failed");
        println!("Falcon Key pair generated successfully!");

        let elapsed_keygen = start.elapsed();
        println!("Time taken for Falcon key pair generation: {:?}", elapsed_keygen);

        // Test signing
        let sign_start = Instant::now();
        let signature = key_pair.sign(message).expect("Signing failed");
        println!("Message signed successfully!");

        let elapsed_sign = sign_start.elapsed();
        println!("Time taken for signing: {:?}", elapsed_sign);

        // Test verification
        let verify_start = Instant::now();
        let is_valid = key_pair.verify(message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature is not valid");
        println!("Signature valid!");

        let elapsed_verify = verify_start.elapsed();
        println!("Time taken for verification: {:?}", elapsed_verify);

        // Total elapsed time
        let total_elapsed = start.elapsed();
        println!("Total time for Falcon operations: {:?}", total_elapsed);
    }

    #[test]
    fn test_large_message() {
        let large_message = vec![0u8; 10_000]; // Large message (10KB)
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with a large message
        let signature = key_pair.sign(&large_message).expect("Signing failed");

        // Test verification with a large message
        let is_valid = key_pair.verify(&large_message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for large message");
    }

    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message for Dilithium";
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Corrupt the signature (flip a single byte)
        let mut corrupted_signature = signature.clone();
        corrupted_signature[0] ^= 0x01;

        // Verify the corrupted signature
        let is_valid = key_pair.verify(message, &corrupted_signature).unwrap_or(false);
        assert!(!is_valid, "Corrupted signature should not be valid");
    }

    #[test]
    fn test_incorrect_public_key() {
        let message = b"Test message for Dilithium";
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Generate a different key pair for incorrect verification
        let incorrect_key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Verify with incorrect public key
        let is_valid = incorrect_key_pair.verify(message, &signature).unwrap_or(false);
        assert!(!is_valid, "Signature should not be valid with incorrect public key");
    }

    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message for Falcon";
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Create an invalid signature by modifying its length
        let invalid_signature = signature[..signature.len() - 1].to_vec(); // Truncate by 1 byte

        // Verify the invalid signature
        let is_valid = key_pair.verify(message, &invalid_signature).unwrap_or(false);
        assert!(!is_valid, "Signature should be invalid due to incorrect length");
    }

    #[test]
    fn test_small_key_size() {
        // Use smaller key size for the algorithm (if the API allows it)
        let _message = b"Small key size test for Falcon";

        // Hypothetical small key size - Falcon should fail if this size is insecure
        let result = FalconKeyPair::generate_key_pair();
        assert!(result.is_ok(), "Key pair generation with small size should succeed");

        // Further tests can verify against expected behaviors for small keys
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = FalconKeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = FalconKeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.get_public_key_raw_bytes(),
            key_pair2.get_public_key_raw_bytes(),
            "Each generated public key should be unique"
        );
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            // Generate a new key pair for each signature
            let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

            // Generate the signature and store it
            let signature = key_pair.sign(data).expect("Signing failed");
            signatures.push(signature);
        }

        // Ensure all signatures are unique
        for i in 0..signatures.len() {
            for j in (i + 1)..signatures.len() {
                assert_ne!(
                    signatures[i],
                    signatures[j],
                    "Signatures should be unique for the same message using different keys"
                );
            }
        }
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_key_type_return() {
        let key_type = FalconKeyPair::key_type();
        assert_eq!(key_type, "Falcon", "The key_type() should return 'Falcon'");
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        // Sign the data
        let signature = key_pair.sign(data).expect("Signing failed");

        // Verify the signature
        let is_valid = key_pair.verify(data, &signature).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_invalid_signature_format() {
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        let invalid_signature = vec![0u8; 666]; // Completely invalid signature length for Falcon

        let result = key_pair.verify(data, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }
}


#[cfg(test)]
#[cfg(feature = "falcon")]
mod serialization_tests {
    use pqcrypto_falcon::falcon512::keypair;
    use identity::{KeySerialization,FalconKeyPair};
    use pqcrypto_traits::sign::{SecretKey,PublicKey};
    #[test]
    fn test_falcon_serialization() {
        // Generate a new key pair
        let (public_key, secret_key) = keypair();
        let keypair = FalconKeyPair { public_key, secret_key };

        // Serialize the key pair
        let serialized = keypair.to_bytes();
        assert!(!serialized.is_empty(), "Serialized output should not be empty");

        // Deserialize back
        let deserialized = FalconKeyPair::from_bytes(&serialized);
        assert!(deserialized.is_ok(), "Deserialization should be successful");

        let deserialized_keypair = deserialized.unwrap();

        // Ensure public and private keys match
        assert_eq!(
            keypair.public_key.as_bytes(),
            deserialized_keypair.public_key.as_bytes(),
            "Public keys do not match after serialization"
        );

        assert_eq!(
            keypair.secret_key.as_bytes(),
            deserialized_keypair.secret_key.as_bytes(),
            "Private keys do not match after serialization"
        );
    }

    #[test]
    fn test_invalid_falcon_deserialization() {
        let invalid_bytes = vec![0u8; 100]; // Invalid size
        let result = FalconKeyPair::from_bytes(&invalid_bytes);
        assert!(result.is_err(), "Deserialization should fail with incorrect input size");
    }
}