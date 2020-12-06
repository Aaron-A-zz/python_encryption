#Encryption
from base64 import b64encode, b64decode
import base64
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
import getpass

def encrypt(message, password):
    # generate random salt
    salt = get_random_bytes(AES.block_size)

    # using the scrypt KDF we are going to get a private key from the password
    private_key = hashlib.scrypt(
    password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create a cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # Return a dictionary containing the encrypted message
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(message, 'utf-8'))

    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

def main():
    # get the message and password from the user
    message = input('Message: ')
    password = getpass.getpass('Password: ')

    # encrypt the message with the password
    encrypted = encrypt(message, password)
    print(encrypted)

main()
