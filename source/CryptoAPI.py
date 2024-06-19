import hashlib
import random
from CryptoInternals import CryptoWrapper


def gen_enc_keys():
    """generate key for use with AES-GCM-256
    """
    crypto = CryptoWrapper()
    keyString = crypto.generateAESKeystring()
    return keyString

def encrypt(key, data):
    """encrypt data using given key and return encrypted values
    """
    crypto = CryptoWrapper()
    data = str(data)
    cipher = crypto.aesEncrypt(key, data) 
    return cipher

def decrypt(key, cipher):
    """decrypt cipher using given key and return plain text values 
    """
    crypto = CryptoWrapper()
    plain_text = crypto.aesDecrypt(key, cipher)#.decode()
    # print(plain_text)
    if type(plain_text) is bytes:
        plain_text = eval(plain_text)
    elif type(plain_text) is str:
        try:
            plain_text = eval(plain_text)
        except Exception as e:
            pass
    return plain_text


def gen_sig_keys():
    """generate a private key for use with ML-DSA-65
    """
    crypto = CryptoWrapper()
    return crypto.DigitalSignGenerate()


def gen_sig(PR_key, data):
    """generate signature for given data using the given private key
    """
    crypto = CryptoWrapper()
    return crypto.DigitalSignSign(PR_key, data)


def verify_sig(PU_key, data, signature):
    """verify if the data matches with the signature
    """
    crypto = CryptoWrapper()
    return crypto.DigitalSignVerify(PU_key, data, signature)