#!/usr/bin/env python
# encoding: utf-8

import urllib
import urllib2
import os
import ast
from Crypto.Cipher import AES
from Crypto import Random
import shutil
import io
import struct
import tempfile
import time
import cookielib
import json
import unicodedata
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
from Security import security
from dh import DiffieHellman
import difflib
from authentication import Smartcard
import sys
from M2Crypto import X509

'''
Security - DETI UA (2014/2015)
@authors: Jose Sequeira 64645
         Vasco Santos 64191
'''



def diffchecker(f1, f2):
    """Returns the diff between the content of
    two files"""
    contextDiffSeq = difflib.ndiff(f1, f2)
    return contextDiffSeq


def upload(fp, user):
    """Upload function, creates a temporary file to which
    the data of the user file is encrypted to. That temp file
    is then read by chunks and sent to the CherryPy server

    Security:
        - Authentication
        - File is encrypt with AES
        - hasher is created for File Integrity Control
        - Public key is accessed for creating a signature
        - Private Key is accessed for encrypting the AES
          key
        - All relevant information is kept client-side"""

    (username, session) = user.getInfo()
    tf = tempfile.NamedTemporaryFile(delete=False)
    filesize = os.stat(fp).st_size
    hasher = security.Hasher()
    pu_key = getPubKey(username)
    enc, iv, aes = security.getCipher(security.importkey_RSA(pu_key))
    with open('PrivateKeys/Private_key_'+str(username), 'rb') as f:
            priv = security.importkey_RSA(f.read())
    security.encrypt_AES(open(fp, 'rb'), tf, enc, hasher, filesize)
    h = hasher.get()
    signature = security.signFile(priv, h)
    tf.close()
    f = FileLenIO(tf.name, 'rb')
    list_pu_key = getUsersPubkey(fp.split('/')[-1], username)
    message ={'filename': fp.split('/')[-1],
                'iv': iv,
                'sign': signature.encode('hex')
            }
    messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
    # New File
    if list_pu_key == []:
        try:
            request = urllib2.Request('https://localhost:8080/upload', f)
            request.add_header('Content-Type', 'application/octet-stream')
            request.add_header('username', username)
            request.add_header('aes', aes)
            request.add_header('data', messageToSend)
            request.add_header('Content-Length', os.stat(tf.name).st_size)
            response = urllib2.urlopen(request)
        except urllib2.URLError as e:
            print e.reason
            print 'Currently, you are not a valid user!\nSafeBox Team'
    # New File Version
    else:
        RsaAES = security.decrypt_RSA(priv, aes.decode('hex'))
        fileList = []
        for publickey in list_pu_key:
            tf2 = tempfile.NamedTemporaryFile(delete=True)
            security.encrypt_RSA(security.importkey_RSA(publickey.decode('hex')), RsaAES, tf2)
            fileList += [tf2.read().encode('hex')]
        try:
            request = urllib2.Request('https://localhost:8080/uploadExistingFile', f)
            request.add_header('Content-Type', 'application/octet-stream')
            request.add_header('username', username)
            request.add_header('aes', json.dumps(fileList))
            request.add_header('data', messageToSend)
            request.add_header('Content-Length', os.stat(tf.name).st_size)
            response = urllib2.urlopen(request)
        except urllib2.URLError as e:
            print e.reason
            print 'Currently, you are not a valid user!\nSafeBox Team'
    os.remove(tf.name)




def download(filename, destination, privpath, user):
    """Download function, creates a temporary file to
    where the encrypted file is streamed to, then it is read
    chunk by chunk and decrypted.

    Security:
        - Authentication
        - File is decrypted with AES
        - hasher is created for File Integrity Control
        - Public key is accessed for decrypting the AES
          key
        - Private Key is accessed for verifying the file signature
        - All relevant information is kept client-side"""

    (username, session) = user.getInfo()
    message = {'filename': filename}
    messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
    params = {'data': messageToSend, 'username': username}
    datagen, headers = multipart_encode(params)
    try:
        resp = urllib2.Request('https://localhost:8080/download',
                               datagen, headers)
        data = urllib2.urlopen(resp)
        fn = data.info().getheader('filename')
        date = json.loads(security.decryptS_AES(data.info().getheader('data').decode('hex'), session.decode('hex')))
        aes = data.info().getheader('aes').decode('hex')
        iv = date['iv'].decode('hex')
        signature = date['sign'].decode('hex')

        with open(privpath, 'rb') as f:
            priv = security.importkey_RSA(f.read())
        pub = security.importkey_RSA(getPubKey(username))
        RsaAES = security.decrypt_RSA(priv, aes)
        decipher = security.getDecipher(iv, RsaAES)
        tf = tempfile.NamedTemporaryFile(delete=True)

        CHUNK = 16 * 1024
        while True:
            chunk = data.read(CHUNK)
            if not chunk:
                break
            tf.write(chunk)
        tf.seek(0)

        hasher = security.Hasher()
        with open(os.path.join(str(destination),
                  filename), 'wb') as out:
            security.decrypt_AES(decipher, tf, out, hasher)
        new = hasher.get()
        if security.verifyFile(pub, new, signature):
            print 'The File was not changed!'
        else:
            print 'The File was changed!'
        tf.close()
    except urllib2.HTTPError as e:
        print str(e.code) + ': ' + e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'


def getPermission(user, filename):
    """ Function to ask for permission, to share a file """
    (username, session) = user.getInfo()
    message ={'filename': filename
        }
    messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
    params = {'data': messageToSend, 'username': username}
    datagen, headers = multipart_encode(params)
    try:
        resp = urllib2.Request('https://localhost:8080/permission',
                                                datagen, headers)
        if urllib2.urlopen(resp).read() == "1":
            return 1
        return 0
    except:
        return 0


def shareFile(user, filename, usr_dest, permission):
    """Share function, allows a file to be shared
    with another user. The file with the AES used to encrypt
    the file to be shared is sent from the server, it is
    decrypted and encrypted with the target user's public key

    Security:
        - Sharing user's private key is used for decrypting
        file with AES key
        - Target user's public key is used for encrypting
        file with AES key
        - Sharing client receives no information from the
        other user except username and public key
        - All relevant information is kept client-side"""

    (username, session) = user.getInfo()
    message ={'filename': filename,
            'usrdstname': usr_dest,
            }
    messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
    params = {'data': messageToSend, 'username': username}
    datagen, headers = multipart_encode(params)
    try:
        resp = urllib2.Request('https://localhost:8080/share',
                               datagen, headers)
        data = urllib2.urlopen(resp)
        date = json.loads(security.decryptS_AES(data.info().getheader('data').decode('hex'), session.decode('hex')))
        aes = date['aes'].decode('hex')
        pub_key = date['pubkey'].decode('hex')
        with open('PrivateKeys/Private_key_'+str(username), 'rb') as f:
            priv = security.importkey_RSA(f.read())
        RsaAES = security.decrypt_RSA(priv, aes)
        tf = tempfile.NamedTemporaryFile(delete=True)
        security.encrypt_RSA(security.importkey_RSA(pub_key), RsaAES, tf)
        message ={   
            'filename': filename,
            'usrdstname': usr_dest,
            'filekey': tf.read().encode('hex'),
            'permission': permission
            }
        messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
        request = urllib2.Request('https://localhost:8080/shareFile')
        request.add_header('username', username)
        request.add_header('data', messageToSend)
        response = urllib2.urlopen(request)
        tf.close()
        print response.read()
    except urllib2.HTTPError as e:
        print str(e.code) + ': ' + e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'


def unshare(user, filename, uns_username):
    """Function for unsharing a file with a user,
    since our approach for this problem is only removing the
    database entries, this function is handled server-side
    (Still a WIP and may be changed in the future)"""
    (username, session) = user.getInfo()
    message ={'filename': filename,
            'unshare': uns_username,
            }
    messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
    params = {'username': username,
        'data': messageToSend
    }
    try:
        datagen, headers = multipart_encode(params)
        resp = urllib2.Request('https://localhost:8080/unShare',
                               datagen, headers)
        response = urllib2.urlopen(resp).read()
        return response
    except urllib2.HTTPError as e:
        print str(e.code) + ': ' + e.reason
        return 'Currently, you are not a valid user!\nSafeBox Team'


def removeFile(user, filename):
    """Function for deleting a file, handled server side since no security
    measures other than Authentication are needed"""
    (username, session) = user.getInfo()
    try:
        message ={   
            'filename': filename
            }
        messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
        request = urllib2.Request('https://localhost:8080/removeFile')
        request.add_header('username', username)
        request.add_header('data', messageToSend)
        response = urllib2.urlopen(request)
    except urllib2.URLError as e:
        print e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'


def fileList(user):
    """Function for listing user files, handled server side since no security
    measures other than Authentication are needed"""
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    (username, session) = user.getInfo()
    params = {
        'username': username
    }
    try:
        datagen, headers = multipart_encode(params)
        resp = urllib2.Request('https://localhost:8080/listMyFiles',
                                  datagen, headers)
        files = urllib2.urlopen(resp).read()
        list_files = json.loads(security.decryptS_AES(files.decode('hex'), session.decode('hex')))
        return list_files
    except urllib2.HTTPError as e:
        print str(e.code) + ': ' + e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'
        return []


def getShareUsers(user, filename):
    """Function for getting the users that you can share with,
    handled server side since no security measures other
    than Authentication are needed"""
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    (username, session) = user.getInfo()
    message ={'filename': filename}
    messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
    params = {
        'username': username,
        'data': messageToSend
    }
    try:
        datagen, headers = multipart_encode(params)
        resp = urllib2.Request('https://localhost:8080/getShareUsers',
                               datagen, headers)
        response = urllib2.urlopen(resp).read()
        users = (json.loads(security.decryptS_AES(response.decode('hex'), session.decode('hex'))))
        list_users = [x.encode('latin-1') for x
                      in users]
        return list_users
    except urllib2.HTTPError as e:
        print str(e.code) + ': ' + e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'
        return []


def getSharedWith(user, filename):
    """Function for getting the usernames that have a certain
    user's file being shared with them, handled server side since no security
    measures other than Authentication are needed"""
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    (username, session) = user.getInfo()
    message ={'filename': filename}
    messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
    params = {
        'username': username,
        'data': messageToSend
    }
    try:
        datagen, headers = multipart_encode(params)
        resp = urllib2.Request('https://localhost:8080/getSharedWith',
                               datagen, headers)
        response = urllib2.urlopen(resp).read()
        users = (json.loads(security.decryptS_AES(response.decode('hex'), session.decode('hex'))))
        list_users = [x.encode('latin-1') for x in users]
        return list_users
    except urllib2.HTTPError as e:
        print str(e.code) + ': ' + e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'
        return []


def diff(user, filename, privpath, filefp):
    """Function for getting the difference between a file in
    the server and a user file, works like download except no file
    is written.

    Security:
        - Authentication
        - File is decrypted with AES
        - hasher is created for File Integrity Control
        - Public key is accessed for decrypting the AES
          key
        - Private Key is accessed for verifying the file signature
        - All relevant information is kept client-side"   """
    (username, session) = user.getInfo()
    message = {'filename': filename}
    messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
    params = {'data': messageToSend, 'username': username}
    datagen, headers = multipart_encode(params)

    try:
        resp = urllib2.Request('https://localhost:8080/download',
                               datagen, headers)
        data = urllib2.urlopen(resp)
        fn = data.info().getheader('filename')
        date = json.loads(security.decryptS_AES(data.info().getheader('data').decode('hex'), session.decode('hex')))
        aes = data.info().getheader('aes').decode('hex')
        iv = date['iv'].decode('hex')
        signature = date['sign'].decode('hex')
        with open(privpath, 'rb') as f:
            priv = security.importkey_RSA(f.read())
        pub = security.importkey_RSA(getPubKey(username))
        RsaAES = security.decrypt_RSA(priv, aes)
        decipher = security.getDecipher(iv, RsaAES)
        tf = tempfile.NamedTemporaryFile(delete=True)
        out = tempfile.NamedTemporaryFile(delete=True)
        CHUNK = 16 * 1024
        while True:
            chunk = data.read(CHUNK)
            if not chunk:
                break
            tf.write(chunk)
        tf.seek(0)

        hasher = security.Hasher()
        security.decrypt_AES(decipher, tf, out, hasher)
        out.seek(0)
        new = hasher.get()
        comp = open(filefp, 'rb').readlines()
        cenas = out.readlines()
        return diffchecker(comp, cenas)
    except urllib2.HTTPError as e:
        print str(e.code) + ': ' + e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'


def askForLogIn():
    """Function for contacting the Server and verify if he is available
    """
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    try:
        request = urllib2.Request('https://localhost:8080/askForLogIn')
        response = urllib2.urlopen(request)
        if response.read() == "OK":
            return True
        else:
            return False
    except urllib2.URLError as e:
        print e.reason
        print 'Currently, Server is not available!\nSafeBox Team'
        return False


def readCC(card):
    reply = card.connect(0l)
    if reply:
        if card.certificateChainVerify():
            uname= card.getUserName()
            BI = card.getUserBI()
            card.disconnect()
            return uname, BI
        else:
            card.disconnect()
            return "Error Validation Certificate Chain", ""
    else:
        card.disconnect()
        return "Error Connecting to Card", ""



def logInUser(userID, password, card):
    """Function for Logging into the server. handled server-side
    Security: Encrypted with Server Public Key
    """
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    try:
        pwd = security.PBKDKF2.pwsend(password)
        params = {
           'userID': userID,
           'password': pwd
        }
        sendparam = encryptMessageToSendRSA(params)
        datagen, headers = multipart_encode(sendparam)
        request = urllib2.Request('https://localhost:8080/logInUser', datagen, headers)
        result = urllib2.urlopen(request).read()
        if result == "ERROR":
            return False
        elif result == "REGIST_AGAIN":
            return False
        else:
            clientSession = DiffieHellman.DiffieHellman()
            # receive token and decrypt it with 
            private_file = os.path.join('PrivateKeys',
                                        'Private_key_'+str(userID))
            with open(private_file, 'rb') as f:
                private_key = security.importkey_RSA(f.read())
                loginMessage = json.loads(result)
                receivedMessage = security.decrypt_RSA(private_key, loginMessage['token'].decode('hex'))
                # sign token
                """ -----------------SIGN CC/PrivateKey By PWD -------------------- """
                reply = card.connect(0l)
                if reply:
                    tokenSigned = card.sign(receivedMessage)    
                    card.disconnect()
                else:
                    tokenSigned = ""
                """ -----------------SIGN CC/PrivateKey By PWD -------------------- """
                message = {'userID': userID,
                           'password': pwd}
                # send token back
                tokenchiphered = encryptMessageToSendRSA({'token': tokenSigned})
                sendparam = encryptMessageToSendRSA(message)
                messageToSend = {'message': sendparam,
                                 'session': json.dumps(clientSession.publicKey),
                                 'token': tokenchiphered}
                datagen, headers = multipart_encode(messageToSend)
                request = urllib2.Request('https://localhost:8080/authTokenValidation', datagen, headers)
                result = urllib2.urlopen(request).read()
                if result == "OK":
                    # Establish Session
                    clientSession.genKey(loginMessage['session'])
                    destination = os.path.join('download', 'session.txt')
                    user = User(userID, clientSession.getKey().encode('hex'))
                    print "Logged In: " + str(userID)

                    return user
                return False
    except urllib2.URLError as e:
        print e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'
        return False

def askForRegist():
    """Function for contacting the Server and verify if he is available
    """
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    try:
        request = urllib2.Request('https://localhost:8080/askForRegist')
        response = urllib2.urlopen(request)
        if response.read() == "OK":
            return True
        else:
            return False
    except urllib2.URLError as e:
        print e.reason
        print 'Currently, Server is not available!\nSafeBox Team'
        return False


def registUser(username, password, mail, card):
    """Function for contact the server and send the information
    of the user.
    Security: Encrypted with Server Public Key
    """
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    try:
        if card.connect(0l) == True:
            pwd = security.PBKDKF2.pwsend(password)
            mod, exp = card.getAuth()
            userID = username
            public_key, private_key = security.generate_RSA()
            params = {
                'userID': userID,
                'username': username,
                'password': pwd
            }
            sendparam = encryptMessageToSendRSA(params)
            sendparam['pub_key'] = public_key.encode('hex')
            sendparam['mod'] = mod
            sendparam['exp'] = exp
            datagen, headers = multipart_encode(sendparam)
            request = urllib2.Request('https://localhost:8080/registUser',
                                      datagen, headers)
            result = urllib2.urlopen(request).read()
            if result != "ERROR":
                token = security.decrypt_RSA(security.importkey_RSA(private_key), result.decode('hex'))
                """ -----------------SIGN CC/PrivateKey By PWD -------------------- """
                tokenSigned = card.sign(token)    
                card.disconnect()
                """ -----------------SIGN CC/PrivateKey By PWD -------------------- """
                # send token back
                message = {'userID': userID,
                       'password': pwd}
                # send token back
                tokenchiphered = encryptMessageToSendRSA({'token': tokenSigned})
                sendparam = encryptMessageToSendRSA(message)
                messageToSend = {'message': sendparam,
                                 'token': tokenchiphered}
                datagen, headers = multipart_encode(messageToSend)
                request = urllib2.Request('https://localhost:8080/registTokenValidation',
                                          datagen, headers)
                result = urllib2.urlopen(request).read()
                if result != "ERROR":
                    # Verify if the token was correct
                    """ SAVE PRIVATE KEY FILE -----> Cipher with Password"""
                    private_file = os.path.join('PrivateKeys',
                                                    'Private_key_'+str(userID))
                    #messageToSend = security.encryptS_AES(json.dumps(message), session.decode('hex')).encode('hex')
                    #ciphered_priv_key = security.encryptS_AES(json.dumps(private_key), pwd).encode('hex')
                    with open(private_file, 'wb') as f:
                        f.write(private_key)
                    return True
        return False
    except urllib2.URLError as e:
        print e.reason
        print 'Currently, you are not a valid user!\nSafeBox Team'
        return False


def logOut(user):
    """Function for logging a user out, handled server-side"""
    (username, session) = user.getInfo()
    params = {
        'username': username
    }
    sendparam = encryptMessageToSendRSA(params)
    try:
        datagen, headers = multipart_encode(sendparam)
        resp = urllib2.Request('https://localhost:8080/logOut',
                               datagen, headers)
        response = urllib2.urlopen(resp).read()
        return response
    except urllib2.HTTPError as e:
        print str(e.code) + ': ' + e.reason
        return 'Currently, you are not a valid user!\nSafeBox Team'


def getPubKey(username):
    """Get's a public key from the server. No Authentication needed
    or any type of security since public key access doesn't threaten
    the security of the server or files"""
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    params = {'username': username}
    datagen, headers = multipart_encode(params)
    request_pubKey = urllib2.Request('https://localhost:8080/getPublicKey',
                                     datagen, headers)
    result = urllib2.urlopen(request_pubKey)
    pub_key = result.read().decode('hex')
    result.close()
    return pub_key


def getUsersPubkey(filename, username):
    """Get's a list of public keys of the users who have access to the file
    from the Server. No Authentication needed
    or any type of security since public key access doesn't threaten
    the security of the server or files"""
    register_openers().add_handler(
        urllib2.HTTPCookieProcessor(cookielib.CookieJar()))
    params = {
        'filename': filename,
        'username': username
    }
    datagen, headers = multipart_encode(params)
    pubkeyList = urllib2.Request('https://localhost:8080/getPublicKeyFile',
                                     datagen, headers)
    result = urllib2.urlopen(pubkeyList)
    pub_key = json.loads(result.read())
    result.close()
    return pub_key


def encryptMessageToSendRSA(params):
    with open('PublicKey', 'rb') as f:
        serverPublicKey = security.importkey_RSA(f.read())
    tf = tempfile.NamedTemporaryFile(delete=True)
    security.encrypt_RSA(serverPublicKey, json.dumps(params), tf)
    sendparam = {
        'data': tf.read().encode('hex')
    }
    return sendparam


class FileLenIO(io.FileIO):
    """class used for sending files in chunks"""
    def __init__(self, name, mode='r', closefd=True):
        io.FileIO.__init__(self, name, mode, closefd)
        self.__size = statinfo = os.stat(name).st_size

    def __len__(self):
        return self.__size


class User(object):
    """client-side class used for maintaining a session"""
    def __init__(self, username, session):
        self.username = username
        self.session = session

    def getInfo(self):
        return (self.username, self.session)
