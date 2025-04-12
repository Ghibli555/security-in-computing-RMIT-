'''
Referencing: 
Code Created by use of code found on:
>Cryptography Documentation: https://cryptography.io/en/latest/ 

>Canvas Reference:
    Lectorial Number:5.1, 5.2
    FileName:aes_cbc_file.py
    How its used: The lectorial and supporting code demonstrates similar AES CBC mode,
    It follows similar methods to derive key hashing salt and password. 
    Similar approach was used to decrypt and encrypt tast1-aes-cbc.
'''
#import relevant libraries to  generate Key and do AES encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import os
import os.path

#In order to ensure code successfully runs on different Operating Systems,
#Relative path is converted to an absolute path (abspath).
BASE = os.path.dirname(os.path.abspath(__file__))

#Key Generation Definitions: 
#[salt]: random 16 byte added to the generation process for added security and
#   to ensure different keys even with similar passwords. 
#[PBKDF2HMAC]:Password Based Key Derivation Function is used to derive a
#   cryptographic key

#Key Generation Process:
#>[PBKDF2HMAC] generates a key with SHA256 Hashing Algorithm
#   which processes the salt and password with the algorithm to generate a hash this is repeated
#   100,000 iterations) to derive the final key.

#Encrypt_file function is defined to encrypt a file; it takes in three parameters.
def encrypt_file(input_file_path, output_file_path, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
 
    #Encryption Definitions:
    #[IV]  : Initialization Vector containing a random 16 Byte Value generated for each encryption session

    #Decryption Process :
    #>IV a 16 bit random value is generated to encrypt the fist block, followed by all the remaining 
    #   blocks,this ensures similar key and plain text produce a cipher text thats different in each iteration.
    #>Cipher object is created from Cipher class from cryptography and is initialized with AES symmetric algorithm
    #   and with CBC mode with derived key earlier.   
    #>Plan text is opened in read mode to create ciphertext using the derived key and then amended to a 
    #   file.
    
    #IV created with random 16bytes
    iv = os.urandom(16)

    #Cipher object created
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) 
    encryptor = cipher.encryptor()

    # Open the plaintext by using the input file path and loading it in memory by f.read.
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()

        # AES operates on blocks of data, so PKCS7 padding is 
        # applied to ensure the plaintext is a multiple of the block size.
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

    #>ciphertext is created from plaintext by using the Cipher class encryptor
    #   update() which encrypts data in blocks,finalize() encrypts 
    #   any remaining data including any bytes not included in a complete
    #   AES encryption Block of 16 bytes. 
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()


    # The salt, IV, and encrypted data are all written to the output file.
    with open(output_file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    print('─' * 10)
    # Print the encryption KEy
    print(f"Encryption key is : {key.hex()}")

#--------------------------------------------------------------------------------------------------#

# Function to decrypt a cipher text file and produce decrypted file. 
def decrypt_file(input_file_path, output_file_path, password):
        
    #Decryption Process :
    #>Cipher text is opened in readmode and salt iv and cipthertext is separated
    #>PBKDF2 Hashing algorithm uses this information to regenerate the the key.
    #>Cipher is initialized in AES CBC mode and derived key
    #>Decryption of the ciphertext is done by decrypt function of the Cipher Class.

        #Ciphertext is opened in read mode and salt,iv and ciphertext are defined and separated. 
        with open(input_file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            ciphertext = f.read()

        # Key Derivation Function is used to recreate the original key with extracted salt and the password parameter. 
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(password.encode())

        
        # Cipher class is initialized with the key and iv and the ciphertext is decrypted with decryptor.  
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
    

        # Unpadder is used to extract and remove the padded text.
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        

        # Decryption Key is Printed(same as Encryption in AES Symmetric Encryption): 
        print(f"Decryption key: {key.hex()}")


        # The plaintext and decrypted data are all written to the output file.
        with open(output_file_path, 'wb') as f:
            f.write(plaintext)


print('─' * 10)

# Functions that were created earlier are now used to Encrypt and Decrypt Data 
# with password and with directories to amend the encryption and decryption information. 
# decrypted and encrypted text in relevant Directories.  

# Encrypt the file
encrypt_file(BASE + '/input/task1.txt', BASE + '/output/task1_encrypted', 's3492003')


print('─' * 10)
# Decrypt the file
decrypt_file(BASE + '/output/task1_encrypted', BASE + '/output/task1_decrypted', 's3492003')
print('─' * 10)

print('─' * 10)
# Display the contents of the encrypted file
with open(BASE + '/output/task1_encrypted', 'rb') as f:
    print("\nEncrypted file message:")
    print(f.read(50).hex())
    print("The encrypted files are saved in the output folder")

# Display the contents of the decrypted file
with open(BASE + '/output/task1_decrypted', 'rb') as f:
    print("\nDecrypted file message:")
    decrypted_content = f.read().decode('utf-8') # Decode the bytes to string
    print(decrypted_content.replace('\n\n', ' ')) # Replace the new line with space
    print("The decrypted files are saved in the output folder")

print('─' * 10)