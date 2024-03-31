
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
import size


def get_aes_key():
    aes_key = get_random_bytes(size.aes_key)
    return aes_key

def generate_rsa_keys(key_size=2048):
    key_pair = RSA.generate(key_size)
    private_key = key_pair.export_key()
    public_key = key_pair.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, rsa_key):
    rsa_public_key = RSA.import_key(rsa_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(plaintext) # Encrypt AES key with RSA public key
    return encrypted_aes_key

def rsa_decrypt(encrypted_data, rsa_key):
    rsa_private_key = RSA.import_key(rsa_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data


def aes_decrypt(encrypted_contents, aes):
    cipher_aes = AES.new(aes, AES.MODE_CBC, b'\0'*AES.block_size)
    decrypted_message = cipher_aes.decrypt(encrypted_contents)
    # Remove PKCS#7 padding
    padding_length = decrypted_message[-1]
    decrypted_message = decrypted_message[:-padding_length]
    return decrypted_message
