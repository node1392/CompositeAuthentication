import Crypto.Random
from Crypto.Cipher import AES
import hashlib
import re


#############################################################
            #Encrypt/Decrypt Messages with Key#
#############################################################
def encrypt(plaintext,key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad_text(plaintext, 16)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt(ciphertext,key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad_text(padded_plaintext)
    return plaintext


#############################################################
                #Padding Helper Functions for AES#
#############################################################
def pad_text(text, multiple):
    extra_bytes = len(text) % multiple
    padding_size = multiple - extra_bytes
    padding = chr(padding_size) * padding_size
    padded_text = text + padding
    return padded_text

def unpad_text(text):
    num = text[len(text)-1]
    temp = text[len(text)-num:]
    xs = bytearray()
    for x in range(0,len(temp)):
        xs.append(num)
    if(temp == xs):
        te = text[:len(text)-num]
        return te
    else:
        return text
    return text
