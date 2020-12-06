#Decryption
from base64 import b64encode, b64decode
import base64
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
import getpass
import ast

def decrypt(message_dict, password):

    # convert the string to a dictionary
    dictionary = ast.literal_eval(message_dict)

    # parse & decode the dictionary entries from base64
    salt = b64decode(dictionary['salt'])
    cipher_text = b64decode(dictionary['cipher_text'])
    nonce = b64decode(dictionary['nonce'])
    tag = b64decode(dictionary['tag'])

    # generate the private key from the password & salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted_message = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted_message

def main():
    # get the encrypted message and password from the user
    encrypted_message = input('encrypted message: ')
    password = getpass.getpass('password: ')

    # decrypt the message using the password
    decrypted_message = decrypt(encrypted_message, password)
    print(bytes.decode(decrypted_message))

main()
