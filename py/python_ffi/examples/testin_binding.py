import nautilus_pki

# Message to sign
message = b"Hello, world! This is a test."

def check_and_test_keypair(class_name):
    """Check if the keypair class exists, generate keypair, sign, and verify."""
    if hasattr(nautilus_pki, class_name):
        print(f"\n[✅] {class_name} is available. Running tests...")

        # Dynamically get the class from python_ffi module
        KeyPairClass = getattr(nautilus_pki, class_name)

        # Generate Key Pair
        keypair = KeyPairClass()
        print(f"  [🔑] {class_name} Key Pair Generated.")

        # Get Public Key
        public_key = keypair.public_key
        print(f"  [📜] Public Key: {public_key[:10]}... (truncated)")

        # Sign message
        signature = keypair.sign(message)
        print(f"  [✍️] Signature: {signature[:10]}... (truncated)")

        # Verify signature
        is_valid = keypair.verify(message, signature)
        print(f"  [🔎] Signature valid? {'✅ Yes' if is_valid else '❌ No'}")

    else:
        print(f"[❌] {class_name} is NOT available!")

# List of Key Pair classes to check and test
key_classes = [
    "DilithiumKeyPair", 
    "FalconKeyPair",
]

# Run tests for each key pair class
for key_class in key_classes:
    check_and_test_keypair(key_class)
