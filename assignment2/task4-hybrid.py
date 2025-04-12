'''
Referencing:
Code Created by use of code found on:
>Cryptography Documentation: https://cryptography.io/en/latest/
>Week 6, 7 and 8
>Canvas Reference:
    Lectorial Number: 6.1, 6.2, 7.1, 7.2, 7.3, 8.1, 8.2
    FileName: rsa_with_signature.py and rsa_padding_file.py
    How its used: Used as a reference to understand the code and implement
    use of hybrid technique- symmetric (AES) and asymmetric encryption (RSA) 
'''

# Import necessary libraries
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom

# Making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# Generate the RSA keys for encryption and decryption
# Return the private and public keys
# The key size is 2048 bits and the public exponent is 65537
# The backend is the default backend
# The private key is used for decryption and signing
# The public key is used for encryption and verification
# The private key and public key are returned
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt the message using RSA and AES encryption
# Return the encrypted message, IV, and encrypted key
# The symmetric key is generated using os.urandom(32)
# The IV is generated using os.urandom(16)
# The AES cipher is created using the symmetric key and IV
# The encryptor is created using the cipher
# The message is padded using PKCS7 padding
# The padded data is encrypted using the encryptor
# The encrypted message is generated using the encryptor
# The symmetric key is encrypted using the public key
# The encrypted key is generated using the public key
# The encrypted message, IV, and encrypted key are returned
def encrypt_message(message, public_key):
    symmetric_key = urandom(32)
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message, iv, encrypted_key

# Decrypt the message using RSA and AES decryption
# Return the decrypted message
# The symmetric key is decrypted using the private key
# The AES cipher is created using the symmetric key and IV
# The decryptor is created using the cipher
# The encrypted message is decrypted using the decryptor
# The decrypted message is unpadded using PKCS7 padding
# The unpadded data is returned as the decrypted message
def decrypt_message(encrypted_message, iv, encrypted_key, private_key):
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(padded_message) + unpadder.finalize()
    return decrypted_message

# Sign the message using the private key
# Return the signature
# The message is signed using the private key
# The signature is generated using the private key
def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify the signature using the public key
# Return True if the signature is valid, False otherwise
# The message is verified using the public key
# The signature is verified using the public key
# If the signature is valid, True is returned
def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Main function to run the code and test the encryption and decryption
# Save the keys, encrypted message, and decrypted message to files
# Display the public and private keys
# Display the signature verification result
# Print the completion message
if __name__ == '__main__':
    # Generate the RSA keys for encryption and decryption
    private_key, public_key = generate_rsa_keys()

    # Save the private key to a file
    with open(os.path.join(BASE, 'keys', 'private_key.pem'), 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the public key to a file
    with open(os.path.join(BASE, 'keys', 'public_key.pem'), 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Read the input file for encryption
    with open(os.path.join(BASE, 'input', 'task1.txt'), 'rb') as f:
        message = f.read()

    # Sign the message
    signature = sign_message(message, private_key)

    # Encrypt the message using RSA and AES encryption
    encrypted_message, iv, encrypted_key = encrypt_message(message, public_key)

    # Save the encrypted message to a file
    with open(os.path.join(BASE, 'output', 'task4_encrypted_message.txt'), 'wb') as f:
        f.write(encrypted_key + iv + encrypted_message)

    # Save the signature to a file
    with open(os.path.join(BASE, 'output', 'task4_signature_message.txt'), 'wb') as f:
        f.write(signature)

    # Read the encrypted data for decryption
    with open(os.path.join(BASE, 'output', 'task4_encrypted_message.txt'), 'rb') as f:
        encrypted_key = f.read(256)
        iv = f.read(16)
        encrypted_message = f.read()

    # Decrypt the message using RSA and AES decryption
    decrypted_message = decrypt_message(encrypted_message, iv, encrypted_key, private_key)

    # Verify the signature
    is_valid = verify_signature(decrypted_message, signature, public_key)

    # Save the decrypted message to a file
    with open(os.path.join(BASE, 'output', 'task4_decrypted_message.txt'), 'wb') as f:
        f.write(decrypted_message)

    # Display the public key
    print("\nPublic Key:")
    print(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    # Display the private key
    print("\nPrivate Key:")
    print(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())

    # Display signature verification result
    print(f"Signature Verification: {is_valid}")

    # Print the completion message
    print("Decryption completed. Check the output folder for the decrypted message.")
    print("Check the keys folder for the private and public keys.")
