import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import oqs
class CryptoWrapper():

    '''AES Cipher Specifics and ML-DSA-65 Digital Signature'''
    blockSize = 16          #Block Size
    keySize = 32            #keySize in Bytes - 32 bytes = 256bit Encryption
    mode =  AES.MODE_GCM    #Cipher Block Mode
    sigalg = "ML-DSA-65"    #ML-DSA-65 Signature Algorithm
    def __init__(self):
        pass
    
    def __extractCrypto__(self, encryptedContent):
        '''Decodes Base64 Encoded Crypto'''
        cipherText = base64.b64decode(encryptedContent)
        return cipherText
    
    def __encodeCrypto__(self, encryptedContent):
        '''Encodes Crypto with Base64'''
        encodedCrypto = base64.b64encode(encryptedContent)
        return encodedCrypto
    
    def generateAESKeystring(self):
        '''Generates Pseudo Random AES Key and Base64 Encodes Key - Returns AES Key'''
        key = os.urandom(self.keySize)
        return key
    
    def aesEncrypt(self, key, data):
        '''Encrypts Data w/ pseudo randomly generated key and base64 encodes cipher - Returns Encrypted Content and AES Key'''
        encryptionKey = key
        iv = get_random_bytes(self.blockSize)
        cipher = AES.new(encryptionKey, self.mode, nonce=iv)
        cipherText, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        encryptedContent = iv + tag + cipherText
        encryptedContent = self.__encodeCrypto__(encryptedContent).decode('utf-8')
        return encryptedContent


    def aesDecrypt(self, key, data):
        '''Decrypts AES(base64 encoded) Crypto - Returns Decrypted Data'''
        decryptionKey = key
        encryptedContent = self.__extractCrypto__(data)
        iv = encryptedContent[:self.blockSize]
        tag = encryptedContent[self.blockSize:self.blockSize+16]
        cipherText = encryptedContent[self.blockSize+16:]
        cipher = AES.new(decryptionKey, self.mode, nonce=iv)
        plainText = cipher.decrypt_and_verify(cipherText, tag)
        return plainText.decode('utf-8')
    
    def DigitalSignGenerate(self):
        '''Generates ML-DSA Key Pair (Public/Private Keys)'''

        
        with oqs.Signature(self.sigalg) as signer:

            publicKey = signer.generate_keypair()
            privateKey = signer.export_secret_key()
            return privateKey, publicKey

    def DigitalSignSign(self, privateKey, data):
        '''ML-DSA-65 Signing - Returns an ML-DSA-65 Signature'''

        with oqs.Signature(self.sigalg, privateKey) as signer:

            # data=data.encode()
            signature = signer.sign(data)

            return signature
        
    def DigitalSignVerify(self, publicKey, data, signature):
        '''Verifies ML-DSA-65 Signature based on Data received - Returns a Boolean Value'''

        with oqs.Signature(self.sigalg) as verifier:

            # data=data.encode()
            is_valid = verifier.verify(data, signature, publicKey)

            return is_valid

        
if __name__ == '__main__':
    print("==================== Test Encrypt And Decrypt AES-GCM-256 ====================")
    encrypts = CryptoWrapper()
    data = 'Hello World'
    secretKey = encrypts.generateAESKeystring()

    with open('prisecretkey.pem', 'w') as file:
        encoded = base64.b64encode(secretKey)
        file.write(encoded.decode('utf-8'))

    print("Length of Secret key:", len(secretKey))
    print(f"Secret Key: {secretKey}")
    print(f"Data: {data}")
    encrytedData = encrypts.aesEncrypt(secretKey, data)
    print(f"encrytedData: {encrytedData}")
    decrytedData = encrypts.aesDecrypt(secretKey, encrytedData)
    print(f"decrytedData: {decrytedData}")
    is_valid = (data == decrytedData)
    print(f"Is Valid: {is_valid}")

    print("====================== Test ML-DSA-65 Digital Signature ======================")
    signatures = CryptoWrapper()
    data = 'Hello World'
    privateKey, publicKey = signatures.DigitalSignGenerate()

    with open('priSignKey.pem', 'w') as file:
        encoded = base64.b64encode(privateKey)
        file.write(encoded.decode('utf-8'))
    with open('pubSignKey.pem', 'w') as file:
        encoded = base64.b64encode(publicKey)
        file.write(encoded.decode('utf-8'))

    print("Length of Private key:", len(privateKey))
    print(f"Private Key: {privateKey}")
    print("Length of public key:", len(publicKey))
    print(f"Public Key: {publicKey}")
    print(f"Data: {data}")
    sign = signatures.DigitalSignSign(privateKey, data)
    print(f"Signature: {sign}")
    print(f"encode sign with length {len(base64.b64encode(sign))}: {base64.b64encode(sign)}")
    is_valid = signatures.DigitalSignVerify(publicKey, data, sign)
    print(f"Is Valid: {is_valid}")