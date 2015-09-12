import os
import struct
import random
import hashlib
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES
import tempfile
try:
    import cStringIO as StringIO
except:
    from StringIO import StringIO
from base64 import b64encode, b64decode
from itertools import izip
import pbkdf2
from Crypto.Hash import SHA256


class PBKDKF2:

    # Used for sending encrypted password to server
    @staticmethod
    def pwsend(password):
        h = SHA256.new(password)
        return h.hexdigest()

    # Variables for PBKDF2 hashing
    SALT_LENGTH = 12
    KEY_LENGTH = 24
    HASH_FUNCTION = 'sha256'
    COST_FACTOR = 10000

    @staticmethod
    def make_hash(password):
        """Generate a random salt and return a new hash for the password."""
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        salt = b64encode(os.urandom(PBKDKF2.SALT_LENGTH))
        return 'PBKDF2${}${}${}${}'.format(
            PBKDKF2.HASH_FUNCTION,
            PBKDKF2.COST_FACTOR,
            salt,
            b64encode(pbkdf2.pbkdf2_bin(password, salt, PBKDKF2.COST_FACTOR,
                                        PBKDKF2.KEY_LENGTH,
                                        getattr(hashlib,
                                                PBKDKF2.HASH_FUNCTION))))

    @staticmethod
    def check_hash(password, hash_):
        """Check a password against an existing hash."""
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        algorithm, hash_function, cost_factor, salt, hash_a = hash_.split('$')
        assert algorithm == 'PBKDF2'
        hash_a = b64decode(hash_a)
        hash_b = pbkdf2.pbkdf2_bin(password, salt, int(cost_factor),
                                   len(hash_a),
                                   getattr(hashlib, hash_function))
        assert len(hash_a) == len(hash_b)
        diff = 0
        for char_a, char_b in izip(hash_a, hash_b):
            diff |= ord(char_a) ^ ord(char_b)
        return diff == 0


def getCipher(publickey):
    """Creates a cipher using the RSA public key for Aes encryption"""
    key = os.urandom(16)
    iv = os.urandom(16)
    tf = tempfile.NamedTemporaryFile(delete=True)
    # get public key from DB
    enc = AES.new(key, AES.MODE_CBC, iv)
    encrypt_RSA(publickey, key, tf)
    return enc, iv.encode('hex'), tf.read().encode('hex')


def getDecipher(iv, key):
    """Reverse of getCipher, uses private RSA key for decryption"""
    dec = AES.new(key, AES.MODE_CBC, iv)
    return dec


def generate_RSA(bits=2048):
    """Generates a pair of RSA keys"""
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    return public_key, private_key


def encrypt_RSA(rsa, i_file, o_file):
    """Uses a public RSA key to encrypt a file"""
    key = PKCS1_OAEP.new(rsa)
    o_file.write(key.encrypt(i_file))
    o_file.seek(0)


def decrypt_RSA(rsa, aes):
    """Uses a private RSA key to decrypt a file"""
    key = PKCS1_OAEP.new(rsa)
    return key.decrypt(aes)


def importkey_RSA(key):
    """Function for importing a RSA key"""
    return RSA.importKey(key)


def read_in_chunks(f, chunk_size=16*1024):
    """Not really related to security,
    just the Function that allows us
    to read a file in chunks"""
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data


def encrypt_AES(i_file, o_file, AESCipher, hasher, filesize):
    """Reads a file in chunks while hashing its content used for
    Integrity control and encrypting it to an output file """
    for chunk in read_in_chunks(i_file):
        hasher.update(chunk)

        if len(chunk) == 0 or len(chunk) % 16 != 0:
            padsize = 16 - (len(chunk) % 16)
            print padsize
            chunk += chr(padsize) * padsize
        o_file.write(AESCipher.encrypt(chunk))
    o_file.seek(0)


def encryptS_AES(inputString, key):

    if len(inputString) == 0 or len(inputString) % 16 != 0:
        padsize = 16 - (len(inputString) % 16)
        inputString += chr(padsize) * padsize
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(inputString)


def decrypt_AES(AESCipher, i_file, o_file, hasher):
    """Reads a encrypted file in chunks while hashing its content
    for Integrity control and decrypting it to an output file """
    finished = False
    next_chunk = ''
    while not finished:
        chunk, next_chunk = next_chunk, AESCipher.decrypt(i_file.read(16*1024))
        if len(next_chunk) == 0:
            pad = ord(chunk[-1])
            chunk = chunk[:-pad]
            finished = True
        o_file.write(chunk)
        hasher.update(chunk)

unpad = lambda s : s[0:-ord(s[-1])]
def decryptS_AES(cipherText, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(cipherText))


def signFile(priv, sha):
    """Uses a RSA public key to create a signature
    for the hash that was created by encrypt_AES"""
    signer = PKCS1_v1_5.new(priv)
    signature = signer.sign(sha)
    return signature


def verifyFile(pub, new, signature):
    """Uses an RSA private to verify the signature
    created in signFile against the hashing
    that was the result of decrypt_AES"""
    verifier = PKCS1_v1_5.new(pub)
    if verifier.verify(new, signature):
        return True
    else:
        return False


class Hasher(object):
    """Class object used for File Integrity
    Control (signature)"""
    def __init__(self, str=''):
        if str == '':
            self.sha = SHA256.new()
        else:
            self.sha = SHA256.new(str)

    def update(self, str):
        self.sha.update(str)

    def result(self):
        return self.sha.hexdigest()

    def get(self):
        return self.sha
