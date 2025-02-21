import nautilus_pki

# Message to sign
message = b"Hello, world! This is a test."

# Directly use the class without hasattr
keypair = nautilus_pki.DilithiumKeyPair()  # No need for getattr
print("🔑 Key pair generated.")

# Get the public key
public_key = keypair.public_key  # Access as an attribute
print("📜 Public Key:", public_key.hex()[:20], "...")

# Sign the message
signature = keypair.sign(message)
print("✍️ Signature:", signature.hex()[:20], "...")

# Verify the signature
if keypair.verify(message, signature):
    print("✅ Signature is valid!")
else:
    print("❌ Signature verification failed.")
