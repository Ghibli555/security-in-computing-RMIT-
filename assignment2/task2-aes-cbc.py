'''
Referencing: 
Code Created by use of code found on:
>Cryptography Documentation: https://cryptography.io/en/latest/ 
>Week 5,7
>Canvas Reference:
    Lectorial Number:5.1, 5.2

    FileName:aes_cbc
    How its used: The lectorial and supporting code demonstrates similar AES CBC mode but
    it also includes a Function defined to encrypt as well as decrypt. For this code inspiration 
    was taken on how the decryption happens but a custom function had to be made as the input parameters 
    were changed with the key and ciphertext already existing within the running memory of code. 
    
    Furthermore, comparatively with aes_cbc original file there was no need to extract salt and password 
    and also enter password as as the key did not need to be derived. 
'''
#import relevant libraries to  generate Key and do AES encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import os.path

#--------------------------------------------------------------------------------------#
# A fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

#Initial Key and Ciphertext in Hexadecimal Representation
hexKey=("140b41b22a29beb4061bda66b6747e14")
hexCiphertext=("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
print("Hex key is: "+ hexKey,"Hex ciphertext "+hexCiphertext) 


#>Function defined to convert Hex string to Byte data as Cryptographic libraries require 
#   data to be represented in Bytes.
#>Conversion ensures the Algorithms run accurately and without errors.
def convert_to_byte(input_string):
    return bytes.fromhex(input_string)

print('─' * 100)

#Calling the function defined above and storing key and ciphertext Variables.

key=convert_to_byte(hexKey)
print("Byte key is:     ",key)

print('─' * 100) 

ciphertext=convert_to_byte(hexCiphertext)
print("ciphertext is:   ",ciphertext)

 
#--------------------------------------------------------------------------------------#

#Decryption Process :
    #>iv and ciphertext is split by separating after first 16 bytes. 
    #>cipher is initialized in AES CBC mode and given key.
    #>Decryption of the ciphertext is done by decrypt function of the Cipher Class.
    #>Padding is removed and decrypted text is amended to a directory. 

#Function defined that takes in a Key, Ciphertext and amends
#   decrypted text into an output folder.
def decrypt_text(key,ciphertext,output_file_path):

    #iv extracted as the first 16 bytes of the ciphertext. 
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    #>Plaintext is created from ciphertext by using the Cipher class decryptor
    #>At this state the plaintext still contains Padding. 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    #Remove Padding so that the filled data to complete a block is removed. 
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    #Decrypted plaintext is written to specified path. 
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
     
    print('─' * 100) 
    print("The Decrypted PlainText is: ",plaintext)
    print('─' * 100) 
     
    print("Decryption Completed at the following path: " + output_file_path)


print('─' * 100)

# call decryption function with converted key and ciphertext in byte code.
# choose any random password for the third argument.
#Base used to ensure file path is readable on different OS.
decrypt_text(key,ciphertext, BASE + '/output/task2_decrypted_text')
print("Please Review the Decrypted file in the Subdirectory for decrypted Text")

print('─' * 100)