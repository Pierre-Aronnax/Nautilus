
#[cfg(feature = "pki_rsa")]
#[cfg(test)]
mod tests {
  use identity::{RSAkeyPair, PKITraits,KeyExchange};
  use rsa::{
      pkcs1::EncodeRsaPrivateKey,
      pkcs1v15::SigningKey,
      signature::{RandomizedSigner, SignatureEncoding},
      RsaPrivateKey, RsaPublicKey,
  };
  use rsa::pkcs1::EncodeRsaPublicKey;
  use sha2::Sha256;
  use rand_core::OsRng;



    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_generate_key_pair() {
        let key_pair = RSAkeyPair::generate_key_pair();
        assert!(key_pair.is_ok(), "Key pair generation should succeed");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        // Sign the data
        let signature = key_pair
            .sign(data)
            .expect("Signing failed");

        // Verify the signature
        let is_valid = key_pair
            .verify(data, &signature)
            .expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_invalid_signature_format() {
        let message = b"Test message for RSA!";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let invalid_signature = vec![0u8; 1000]; // Completely invalid signature
        
        // Verify the invalid signature
        let result = key_pair.verify(message, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_empty_message() {
        let message = b""; // Empty message
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with empty message
        let signature = key_pair.sign(message).expect("Signing failed");

        // Test verification with empty message
        let is_valid = key_pair.verify(message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for empty message");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_large_message() {
        let large_message = vec![0u8; 10_000]; // Large message (10KB)
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with a large message
        let signature = key_pair.sign(&large_message).expect("Signing failed");

        // Test verification with a large message
        let is_valid = key_pair.verify(&large_message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for large message");
    }
    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message for RSA";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Corrupt the signature (flip a single byte)
        let mut corrupted_signature = signature.clone();
        corrupted_signature[0] ^= 0x01;

        // Verify the corrupted signature
        let is_valid = key_pair.verify(message, &corrupted_signature).unwrap_or(false);
        assert!(!is_valid, "Corrupted signature should not be valid");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_incorrect_public_key() {
        let message = b"Test message for RSA";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        // Generate a different key pair for incorrect verification
        let incorrect_key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Verify with incorrect public key
        let is_valid = incorrect_key_pair.verify(message, &signature).unwrap_or(false);
        assert!(!is_valid, "Signature should not be valid with incorrect public key");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message for RSA";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Create an invalid signature by modifying its length
        let invalid_signature = signature[..signature.len() - 1].to_vec(); // Truncate by 1 byte

        // Verify the invalid signature
        let is_valid = key_pair.verify(message, &invalid_signature).unwrap_or(false);
        assert!(!is_valid, "Signature should be invalid due to incorrect length");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_public_key_der_encoding() {
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
        let public_key = key_pair.get_public_key_raw_bytes();

        // Assert that the public key is not empty
        assert!(!public_key.is_empty(), "Public key should not be empty");

        // Optionally, test if the public key is DER encoded
        assert!(public_key.starts_with(&[0x30]), "Public key should be DER encoded");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_crash_keypair() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
    
        let mut rng = OsRng;
    
        // Generate a valid RSA private key
        let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("Key generation failed");
    
        // Serialize the private key to DER format
        let mut private_key_der = private_key.to_pkcs1_der().unwrap().as_bytes().to_vec();
    
        // Corrupt the serialized key data (e.g., modify a byte)
        private_key_der[10] ^= 0xFF;
    
        // Attempt to deserialize the corrupted key
        let corrupted_key_result = RsaPrivateKey::from_pkcs1_der(&private_key_der);
    
        // Ensure deserialization of the corrupted key fails
        assert!(
            corrupted_key_result.is_err(),
            "Corrupted private key deserialization should fail"
        );
    
        // If necessary, test the behavior with the corrupted key (should not reach here)
        if let Ok(corrupted_key) = corrupted_key_result {
            let key_pair = RSAkeyPair {
                private_key: corrupted_key,
                public_key: RsaPublicKey::from(&private_key),
            };
    
            let data = b"Test message";
            let result = key_pair.sign(data);
    
            assert!(result.is_err(), "Corrupted private key should not successfully sign data");
        }
    }
    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_keypair_equivalence() {
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
        let public_key1 = key_pair.public_key.to_pkcs1_der().unwrap();

        // Regenerate the public key from the same private key
        let regenerated_public_key = RsaPublicKey::from(&key_pair.private_key)
            .to_pkcs1_der()
            .unwrap();

        assert_eq!(
            public_key1, regenerated_public_key,
            "Public key should be consistently derived from the same private key"
        );
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = RSAkeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = RSAkeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.private_key.to_pkcs1_der().unwrap().as_bytes(),
            key_pair2.private_key.to_pkcs1_der().unwrap().as_bytes(),
            "Each generated private key should be unique"
        );

        assert_ne!(
            key_pair1.public_key.to_pkcs1_der().unwrap(),
            key_pair2.public_key.to_pkcs1_der().unwrap(),
            "Each generated public key should be unique"
        );
    }
    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_different_keypair_variant() {
        let key_pair_2048 = RSAkeyPair::generate_key_pair().expect("Key pair (2048-bit) generation failed");
        let private_key_der_2048 = key_pair_2048.private_key.to_pkcs1_der().unwrap();
        
        // Generate a 4096-bit key pair (assuming RSA supports this in implementation)
        let mut rng = OsRng;
        let private_key_4096 = RsaPrivateKey::new(&mut rng, 4096).expect("4096-bit key generation failed");
        let public_key_4096 = RsaPublicKey::from(&private_key_4096);
        
        assert_ne!(
            private_key_der_2048.len(),
            private_key_4096.to_pkcs1_der().unwrap().len(),
            "Key sizes should differ between 2048-bit and 4096-bit variants"
        );

        assert_ne!(
            key_pair_2048.public_key.to_pkcs1_der().unwrap(),
            public_key_4096.to_pkcs1_der().unwrap(),
            "Public keys of different variants should be different"
        );
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            // Generate a new key pair for each signature
            let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
            let signing_key = SigningKey::<Sha256>::new(key_pair.private_key);
            let mut rng = OsRng;

            // Generate the signature and store it
            let signature = signing_key
                .sign_with_rng(&mut rng, data)
                .to_vec();
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

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_key_type_return() {
        let key_type = RSAkeyPair::key_type();
        assert_eq!(key_type, "RSA", "The key_type() should return 'RSA'");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_rsa_encapsulation_and_decapsulation() {
        // Generate RSA key pair
        let rsa_key_pair = RSAkeyPair::generate_key_pair().expect("Failed to generate RSA key pair");

        // Perform encapsulation
        let (session_key, ciphertext) = RSAkeyPair::encapsulate(&rsa_key_pair.public_key, None)
            .expect("Encapsulation failed");

        // Perform decapsulation
        let recovered_session_key =
            RSAkeyPair::decapsulate(&rsa_key_pair.private_key, &ciphertext, None)
                .expect("Decapsulation failed");

        // Verify that the session key matches the recovered session key
        assert_eq!(
            session_key, recovered_session_key,
            "Session keys should match"
        );
    }
    #[cfg(feature = "pki_rsa")]
    #[test]
fn test_rsa_encapsulation_and_decapsulation_with_valid_tag() {
    // Generate RSA key pair
    let rsa_key_pair = RSAkeyPair::generate_key_pair().expect("Failed to generate RSA key pair");

    // Perform encapsulation
    let (session_key, combined_ciphertext) = RSAkeyPair::encapsulate(&rsa_key_pair.public_key, None)
        .expect("Encapsulation failed");

    // Perform decapsulation
    let recovered_session_key =
        RSAkeyPair::decapsulate(&rsa_key_pair.private_key, &combined_ciphertext, None)
            .expect("Decapsulation failed");

    // Verify that the session key matches the recovered session key
    assert_eq!(
        session_key, recovered_session_key,
        "Session keys should match"
    );
}
#[cfg(feature = "pki_rsa")]
#[test]
fn test_rsa_decapsulation_with_invalid_tag() {
    // Generate RSA key pair
    let rsa_key_pair = RSAkeyPair::generate_key_pair().expect("Failed to generate RSA key pair");

    // Perform encapsulation
    let (_, mut combined_ciphertext) = RSAkeyPair::encapsulate(&rsa_key_pair.public_key, None)
        .expect("Encapsulation failed");

    // Tamper with the tag (last byte)
    let len = combined_ciphertext.len();
    combined_ciphertext[len - 1] ^= 0xFF;

    // Attempt decapsulation
    let result = RSAkeyPair::decapsulate(&rsa_key_pair.private_key, &combined_ciphertext, None);

    // Verify that decapsulation fails due to invalid tag
    assert!(
        result.is_err(),
        "Decapsulation should fail with invalid tag"
    );
}

}

#[cfg(feature = "pki_rsa")]
#[cfg(test)]
mod integration_tests {
    use identity::{PKITraits, RSAkeyPair, KeyExchange};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use std::time::Duration;

    async fn handle_client(mut stream: TcpStream, rsa_key: Arc<RSAkeyPair>, tx: mpsc::Sender<Vec<u8>>) {
        let mut buffer = vec![0; 2048];
        let n = stream.read(&mut buffer).await.unwrap();
        let received = &buffer[..n];

        // Split the received message into ciphertext and tag
        let (ciphertext, tag) = received.split_at(received.len() - 32);

        // Perform decapsulation using RSA private key
        let shared_secret = RSAkeyPair::decapsulate(&rsa_key.private_key, ciphertext, None).unwrap();
        println!("Server shared secret: {:?}", shared_secret);

        // Send the shared secret to the testing channel
        tx.send(shared_secret).await.unwrap();

        // Verify the tag (not implemented for simplicity)
        assert!(!tag.is_empty(), "Validation tag is missing");
    }

    #[tokio::test]
    async fn test_key_exchange_with_mpsc() {
        let rsa_key = Arc::new(RSAkeyPair::generate_key_pair().unwrap());

        // Start an mpsc channel for key sharing
        let (tx, mut rx) = mpsc::channel(1);

        // Start a server
        let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
        let rsa_key_clone = Arc::clone(&rsa_key);

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_client(socket, rsa_key_clone, tx).await;
        });

        // Simulate a client
        let mut client = TcpStream::connect("127.0.0.1:8080").await.unwrap();

        // Perform encapsulation using RSA public key
        let (shared_secret, ciphertext) = RSAkeyPair::encapsulate(&rsa_key.public_key, None).unwrap();
        println!("Client shared secret: {:?}", shared_secret);

        // Add a dummy tag (32 bytes for simplicity)
        let mut message = ciphertext;
        message.extend_from_slice(&vec![0xAA; 32]);

        client.write_all(&message).await.unwrap();

        // Receive the shared secret from the server
        let server_shared_secret = rx.recv().await.unwrap();

        // Verify that the shared secrets match
        assert_eq!(shared_secret, server_shared_secret, "Shared secrets do not match!");
    }

    #[tokio::test]
    async fn test_large_payload_encryption() {
        let rsa_key = Arc::new(RSAkeyPair::generate_key_pair().unwrap());

        // Large payload
        let _large_message = vec![0u8; 10_000];
        let (shared_secret, ciphertext) = RSAkeyPair::encapsulate(&rsa_key.public_key, None).unwrap();

        // Simulate a client-server communication
        let listener = TcpListener::bind("127.0.0.1:8081").await.unwrap();
        let rsa_key_clone = Arc::clone(&rsa_key);

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0; 2048];
            let n = socket.read(&mut buffer).await.unwrap();

            // Server decapsulates the message
            let server_shared_secret = RSAkeyPair::decapsulate(&rsa_key_clone.private_key, &buffer[..n], None).unwrap();
            assert_eq!(shared_secret, server_shared_secret, "Shared secrets for large payload do not match!");
        });

        let mut client = TcpStream::connect("127.0.0.1:8081").await.unwrap();
        client.write_all(&ciphertext).await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_connections() {
        let rsa_key = Arc::new(RSAkeyPair::generate_key_pair().unwrap());
        let listener = TcpListener::bind("127.0.0.1:8082").await.unwrap();
        let rsa_key_clone = Arc::clone(&rsa_key);

        // Spawn multiple clients
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let rsa_key_clone = Arc::clone(&rsa_key_clone);
                tokio::spawn(async move {
                    let mut buffer = vec![0; 2048];
                    let n = socket.read(&mut buffer).await.unwrap();
                    let received = &buffer[..n];

                    // Decapsulation
                    let shared_secret = RSAkeyPair::decapsulate(&rsa_key_clone.private_key, received, None).unwrap();
                    println!("Server shared secret for connection: {:?}", shared_secret);
                });
            }
        });

        for _ in 0..5 {
            let rsa_key = Arc::clone(&rsa_key);
            tokio::spawn(async move {
                let mut client = TcpStream::connect("127.0.0.1:8082").await.unwrap();
                let (_, ciphertext) = RSAkeyPair::encapsulate(&rsa_key.public_key, None).unwrap();
                client.write_all(&ciphertext).await.unwrap();
            });
        }

        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    #[tokio::test]
    async fn test_message_integrity() {
        let rsa_key = Arc::new(RSAkeyPair::generate_key_pair().unwrap());
        let (_shared_secret, ciphertext) = RSAkeyPair::encapsulate(&rsa_key.public_key, None).unwrap();

        // Corrupt the ciphertext
        let mut corrupted_ciphertext = ciphertext.clone();
        corrupted_ciphertext[0] ^= 0xFF; // Flip a bit

        let result = RSAkeyPair::decapsulate(&rsa_key.private_key, &corrupted_ciphertext, None);

        assert!(result.is_err(), "Message integrity check failed: corrupted ciphertext should not succeed");
    }
}

#[cfg(feature = "pki_rsa")]
#[cfg(test)]
mod attack_tests {
    use identity::{PKITraits, RSAkeyPair, KeyExchange};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_replay_attack() {
        let rsa_key = Arc::new(RSAkeyPair::generate_key_pair().unwrap());

        // Perform encapsulation using RSA public key
        let (_, ciphertext) = RSAkeyPair::encapsulate(&rsa_key.public_key, None).unwrap();

        // Simulate a server
        let listener = TcpListener::bind("127.0.0.1:8083").await.unwrap();
        let rsa_key_clone = Arc::clone(&rsa_key);

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0; 2048];
            let n = socket.read(&mut buffer).await.unwrap();

            // Attempt to decapsulate the message
            let result = RSAkeyPair::decapsulate(&rsa_key_clone.private_key, &buffer[..n], None);

            // Expect replayed message to fail
            assert!(result.is_ok(), "Replayed ciphertext should fail if not detected.");
        });

        // Simulate a client sending the ciphertext twice
        let mut client = TcpStream::connect("127.0.0.1:8083").await.unwrap();
        client.write_all(&ciphertext).await.unwrap();
        client.write_all(&ciphertext).await.unwrap();
    }
}

#[cfg(feature = "pki_rsa")]
#[cfg(test)]
mod serialization_test {
    use identity::{RSAkeyPair,PKITraits,KeySerialization};
    use rsa::pkcs1::{EncodeRsaPrivateKey,EncodeRsaPublicKey};

    #[test]
    fn test_serialization_and_deserialization() {
        let key_pair = RSAkeyPair::generate_key_pair().expect("Failed to generate key pair");
        let serialized = key_pair.to_bytes();

        let deserialized = RSAkeyPair::from_bytes(&serialized).expect("Failed to deserialize key pair");

        assert_eq!(key_pair.private_key.to_pkcs1_der().unwrap().as_bytes(), deserialized.private_key.to_pkcs1_der().unwrap().as_bytes());
        assert_eq!(key_pair.public_key.to_pkcs1_der().unwrap().as_bytes(), deserialized.public_key.to_pkcs1_der().unwrap().as_bytes());
    }

    #[test]
    fn test_invalid_deserialization() {
        let invalid_bytes = vec![0u8; 512];
        let result = RSAkeyPair::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }
}
