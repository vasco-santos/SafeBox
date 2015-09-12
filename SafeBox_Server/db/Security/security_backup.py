import os
import struct
import random
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
try:
    import cStringIO as StringIO
except:
    from StringIO import StringIO


def generate_RSA(bits=2048):
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    return public_key, private_key


def encrypt_RSA(rsa, i_file, o_file):
    key = PKCS1_OAEP.new(rsa)
    o_file.write(key.encrypt(i_file))


def decrypt_RSA(rsa, i_file):
    key = PKCS1_OAEP.new(rsa)
    return key.decrypt(i_file.read())
    

def encrypt_AES(rsa, i_file, o_file, chunksize=16*1024):
    key = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    iv = Random.new().read(AES.block_size)
    enc = AES.new(key, AES.MODE_CBC, iv)
    if type(i_file) is file:
        i_file = i_file.read()
    filesize = len(i_file)
    i = 0
    with open(o_file, 'wb') as out_file:
        out_file.write(struct.pack('<Q', filesize))
        out_file.write(iv)
        while(True):
            chunk = i_file[i:chunksize+i]
            if i+chunksize > filesize:
                i = filesize - i
            else:
                i += chunksize
            if len(chunk) == 0:
                    break
            elif len(chunk) % 16 != 0:
                chunk += ' ' * (16 - len(chunk) % 16)
            out_file.write(enc.encrypt(chunk))
    encrypt_RSA(rsa, key, open(o_file+'.key', 'wb'))

def decrypt_AES(key, i_file, chunksize=16*1024):

    output = StringIO.StringIO()

    filesize = struct.unpack('<Q', i_file.read(struct.calcsize('Q')))[0]
    iv = i_file.read(16)
    dec = AES.new(key, AES.MODE_CBC, iv)

    while True:
        chunk = i_file.read(chunksize)
        if len(chunk) == 0:
            break
        output.write(dec.decrypt(chunk))

    output.truncate(filesize)
    return output


def test():
    pub, priv = generate_RSA()
    """ Save in Database """
    with open('pub.key', 'wb') as f:
        f.write(pub)
    with open('priv.key', 'wb') as f:
        f.write(priv)
    """
            """
    encrypt_AES(RSA.importKey(pub), open('commandline.txt', 'rb'), 'encryptedfile')
    aeskey = decrypt_RSA(RSA.importKey(priv), open('encryptedfile.key', 'rb'))
    print decrypt_AES(aeskey, open('encryptedfile', 'rb')).getvalue()