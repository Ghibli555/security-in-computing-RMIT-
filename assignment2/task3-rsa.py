'''
This code is written with reference
to the practice code from weeks 5 and 6.

Referencing: 
Code Created by use of code found on:
>Cryptography Documentation: https://cryptography.io/en/latest/ 
>Week 5,6
>Canvas Reference:
    Lectorial Number:5.1,5.2 and 6.1,6.2
    FileName:(All files in Asymmetric folder of Week 5) and Week 6 rsa_with_signature
    How its used: The lectorial and files aided in understanding how key pairs are generated 
    of different sizes to encrypt and decrypt data. rsa_with_signatures aided 
    how use RSA with signatures to sign and verify. 
'''

#import relevant libraries to use Rsa 
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

#In order to ensure code successfully runs on different Operating Systems,
#Relative path is converted to an absolute path (abspath).
BASE = os.path.dirname(os.path.abspath(__file__))

# Function defined to generate key pairs with the specified key size
#   and return the private and public keys
def generate_keys(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

# >Save the generated keys to files with the specified file names
#   in PEM format for both private and public keys
#   using serialization functions from cryptography library.
def save_keys(private_key, public_key, private_key_file, public_key_file):
    with open(private_key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(public_key_file, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# >Encrypt the message using the public key with OAEP padding
#   and return the ciphertext
# >The encryption is done using the SHA256 hash algorithm
#   and the MGF1 mask generation
def encrypt_message(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

#>Decrypt the message using the private key with OAEP padding
#   to return the plaintext and the MGF1 mask generation.
#>The salt length is set to the maximum length
def decrypt_message(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# >Sign the message using the private key with PSS padding
#   and return the signature
# >The signature is generated using the SHA256 hash algorithm
#   and the MGF1 mask generation
# >The salt length is set to the maximum length
# >The signature is generated using the SHA256 hash algorithm
def sign_message(message, private_key):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# >Verify the signature using the public key and return True if the signature is valid, False otherwise
# >The signature is verified using the SHA256 hash algorithm
#   and the MGF1 mask generation
# >If the signature is valid, the function returns True, otherwise False
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

# Main function to test the RSA encryption and decryption with different key sizes (1024-bit and 2048-bit)
#   and calculate the encryption and decryption time for each key size to 
#   verify the signature of the message
if __name__ == "__main__":
    # input file path
    input_file = os.path.join(BASE, "input", "task3.txt")

    # Read the input file
    with open(input_file, "rb") as f:
        message = f.read()

    # Test with 1024-bit and 2048-bit key sizes
    print('─' * 10)
    print("Lets compare how the 1024 bit key compares with 2048-bit key to encrypt and decrypt: ")
    for key_size in [1024, 2048]:
        
        print(f"\nTesting with {key_size}-bit key:")

        # Create private and public keys with specified key size
        # and save the keys to files
        private_key, public_key = generate_keys(key_size)
        private_key_file = os.path.join(BASE, "keys", f"private_key_{key_size}.pem")
        public_key_file = os.path.join(BASE, "keys", f"public_key_{key_size}.pem")
        save_keys(private_key, public_key, private_key_file, public_key_file)

        # Calculate Encryption Time.
        start_time = time.time()
        ciphertext = encrypt_message(message, public_key)
        encryption_time = time.time() - start_time
        print(f"Encryption time: {encryption_time:.4f} seconds")

        # Save the ciphertext to a file
        encrypted_file = os.path.join(BASE, "output", f"task3_encrypted_{key_size}.txt")
        with open(encrypted_file, "wb") as f:
            f.write(ciphertext)
        

        # Measuring the time to decrypt message.
        start_time = time.time()
        decrypted_message = decrypt_message(ciphertext, private_key)
        decryption_time = time.time() - start_time
        print(f"Decryption time: {decryption_time:.4f} seconds")

        # Save the decrypted message to a file
        decrypted_file = os.path.join(BASE, "output", f"task3_decrypted_{key_size}.txt")
        with open(decrypted_file, "wb") as f:
            f.write(decrypted_message)

        # Generate and verify signature
        signature = sign_message(message, private_key)
        is_valid = verify_signature(message, signature, public_key)
        print(f"Signature verification: {'Success' if is_valid else 'Failed'}")
        print('─' * 10)