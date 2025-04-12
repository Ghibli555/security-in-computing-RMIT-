'''
This code is written with reference belows links:

https://youtu.be/D_PfV_IcUdA?si=37gHXnXEgTOE4fvO

https://www.askpython.com/python/examples/rsa-algorithm-in-python

https://pythonmania.org/python-program-for-rsa-algorithm/

Since 'import os' already contains the os.path module and uses os.path functions directly in the code,
such as os.path.join(), a separate 'import os.path' is not required.
------------------------------------------------------------------------------
Referencing:

This code is written with reference belows links:
>URLReference:
    URL Reference:
    > https://youtu.be/D_PfV_IcUdA?si=37gHXnXEgTOE4fvO
    > https://www.askpython.com/python/examples/rsa-algorithm-in-python
    > https://pythonmania.org/python-program-for-rsa-algorithm/

    How its used:
    > The RSA algorithm's principles and mechanics are discussed for clarity. Specifically, it covers how to generate public and private keys, select prime numbers, calculate the modulus, and compute Euler's Totient function. The code also demonstrates how to encrypt and decrypt text using the RSA algorithm. The code is written in Python and uses the square-and-multiply algorithm for modular exponentiation. The code is well-commented and easy to understand, making it suitable for beginners who want to learn about the RSA algorithm.
    > how plaintext is transformed into a numerical format, followed by the application of modular exponentiation to create the ciphertext, and how this ciphertext is then converted back to plaintext through the reverse process.
    > This text also refers to an example implementation of the RSA algorithm in Python. It covers key generation, encryption, and decryption functions, providing insight into the code's structure and the implementation of the key functions.
'''

# Import the necessary libraries
import os
import random

# Making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# Calculate the greatest common divisor of two numbers using Euclid's algorithm
def gcd(a, b):
    while b: # while b is not 0
        a, b = b, a % b # a = b, b = a % b
    return a # return a

# Calculate the least common multiple of two numbers
def lcm(p, q): # p and q are two numbers
    return (p * q) // gcd(p, q) # return the least common multiple of p and q

# Generate public and private keys using the RSA algorithm
# The public key is (E, N) and the private key is (D, N)
# E is the public exponent, D is the private exponent, and N is the modulus
# The modulus N is the product of two large prime numbers p and q
# The public exponent E is a random number that is coprime with (p-1)(q-1)
# The private exponent D is the modular inverse of E modulo (p-1)(q-1)
def generate_keys(p, q): # p and q are two prime numbers
    N = p * q # N is the product of p and q
    L = lcm(p - 1, q - 1) # L is the least common multiple of p-1 and q-1

    E = random.randrange(1, L) # E is a random number between 1 and L
    while gcd(E, L) != 1: # while the greatest common divisor of E and L is not 1
        E = random.randrange(1, L) # generate a new random number for E

    D = pow(E, -1, L) # D is the modular inverse of E modulo L

    return (E, N), (D, N) # return the public key (E, N) and the private key (D, N)

# Square and multiply algorithm for modular exponentiation (a^b mod m)
def square_and_multiply(base, exponent, modulus): # base is a, exponent is b, modulus is m
    result = 1 # initialize the result to 1
    base = base % modulus # take the base modulo modulus
    while exponent > 0: # while the exponent is greater than 0
        if exponent % 2 == 1: # if the least significant bit of the exponent is 1
            result = (result * base) % modulus # multiply the result by the base and take the result modulo modulus
        exponent = exponent >> 1 # right shift the exponent by 1 bit
        base = (base * base) % modulus # square the base and take the result modulo modulus
    return result # return the result

# Encrypt a plain text using the public key (E, N)
def encrypt(plain_text, public_key): # plain_text is the text to be encrypted, public_key is the public key (E, N)
    E, N = public_key # E is the public exponent, N is the modulus
    cipher = [square_and_multiply(ord(char), E, N) for char in plain_text] # encrypt each character in the plain text
    return ','.join(map(str, cipher)) # return the encrypted text as a comma-separated string

# Decrypt a cipher text using the private key (D, N)
def decrypt(cipher_text, private_key): # cipher_text is the text to be decrypted, private_key is the private key (D, N)
    D, N = private_key # D is the private exponent, N is the modulus
    cipher = [int(x) for x in cipher_text.split(',')] # split the cipher text into a list of integers
    plain = [square_and_multiply(char, D, N) for char in cipher] # decrypt each integer in the cipher text
    return ''.join(chr(char) for char in plain) # return the decrypted text as a string


# Main function to demonstrate the RSA encryption and decryption
# The plain text is encrypted using the public key and then decrypted using the private key
# The original text, encrypted text, and decrypted text are printed to the console
if __name__ == '__main__':
    p = 101
    q = 3259
    # Generate public and private keys using the prime numbers p and q
    public_key, private_key = generate_keys(p, q)

    # Encrypt and decrypt a sample text
    # The plain text is '3973143'
    plain_text = '3973143'
    # Encrypt the plain text using the public key
    # and then decrypt the encrypted text using the private
    encrypted_text = encrypt(plain_text, public_key)
    decrypted_text = decrypt(encrypted_text, private_key)
    # print the original text, encrypted text, and decrypted text
    print(f"Original text: {plain_text}")
    print(f"Encrypted text: {encrypted_text}")
    print(f"Decrypted text: {decrypted_text}")
    # write the encrypted and decrypted text to files
    with open(os.path.join(BASE,'output', 'task5_encrypted.txt'), 'w') as f:
        f.write(encrypted_text)
    # write the decrypted text to a file
    with open(os.path.join(BASE,'output', 'task5_decrypted.txt'), 'w') as f:
        f.write(decrypted_text)
    # print a message to indicate that the process is completed
    print("The process is completed. Please check the output folder for the encrypted and decrypted text files.")

