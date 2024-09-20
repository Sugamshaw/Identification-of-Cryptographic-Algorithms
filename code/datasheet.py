import random
import binascii
import pandas as pd
from Crypto.Cipher import AES, Blowfish, DES3, DES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import PKCS1_OAEP

def generate_des_ciphertext(key, plaintext):
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes long for DES")
    
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return binascii.hexlify(ciphertext).decode()

def generate_aes_ciphertext(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return binascii.hexlify(ciphertext).decode()

def generate_blowfish_ciphertext(key, plaintext):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_text = pad(plaintext, Blowfish.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return binascii.hexlify(ciphertext).decode()

def generate_3des_ciphertext(key, plaintext):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_text = pad(plaintext, DES3.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return binascii.hexlify(ciphertext).decode()

def generate_rsa_ciphertext(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext)
    return binascii.hexlify(ciphertext).decode()

def generate_random_key(length):
    return get_random_bytes(length)

def generate_random_plaintext(length):
    return get_random_bytes(length)

def generate_dataset(num_samples, plaintext_length):
    data = []
    for _ in range(num_samples):
        plaintext = generate_random_plaintext(plaintext_length)
        
        # Generate keys
        aes_key = generate_random_key(16)  # AES key length
        blowfish_key = generate_random_key(16)  # Blowfish key length
        des3_key = generate_random_key(24)  # 3DES key length
        des_key = generate_random_key(8)  # DES key length
        rsa_key = RSA.generate(2048)
        rsa_public_key = rsa_key.publickey()
        
        # Generate ciphertexts
        aes_ciphertext = generate_aes_ciphertext(aes_key, plaintext)
        blowfish_ciphertext = generate_blowfish_ciphertext(blowfish_key, plaintext)
        des3_ciphertext = generate_3des_ciphertext(des3_key, plaintext)
        rsa_ciphertext = generate_rsa_ciphertext(rsa_public_key, plaintext)
        des_ciphertext = generate_des_ciphertext(des_key, plaintext)
        
        # Append to dataset
        data.append(['AES', aes_ciphertext])
        data.append(['Blowfish', blowfish_ciphertext])
        data.append(['3DES', des3_ciphertext])
        data.append(['RSA', rsa_ciphertext])
        data.append(['DES', des_ciphertext])
        print("generated : ",_)
    
    return data

# Parameters
num_samples = 2000  # Number of samples you want to generate
plaintext_length = 16  # Length of each plaintext (in bytes)

# Generate dataset
dataset = generate_dataset(num_samples, plaintext_length)

# Convert dataset to DataFrame
df = pd.DataFrame(dataset, columns=['Algorithm', 'Ciphertext'])

# Write dataset to a CSV file
df.to_csv('cipher_dataset_new.csv', index=False)

print(f'Dataset of {num_samples * 5} samples written to cipher_dataset.csv')
