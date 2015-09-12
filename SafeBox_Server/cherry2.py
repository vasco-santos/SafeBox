#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cherrypy
import os
import ast
import re
import os.path
import tempfile
import shutil
import json
import time
from urllib2 import urlopen, HTTPError
from db import db_init
from db import DBmodule
from collections import defaultdict
from Security.security import PBKDKF2 as pw
from Security import security
from Security import pam
from dh import DiffieHellman
import PAM


'''
Security - DETI UA (2014/2015)
@authors: Jose Sequeira 64645
         Vasco Santos 64191
'''
'''
Server CherryPy Application
'''

config = {
    'global': {
        'server.socket_host': '127.0.0.1',
        'server.socket_port': 8080,
        'server.thread_pool': 8,
        # remove limit on the request body size; cherrypy's default is 100MB
        'server.max_request_body_size': 0,
        # increase server socket timeout to 60s; cherrypy's defult is 10s
        'server.socket_timeout': 120
    }
}

# SafeBox Application
class App:

    @cherrypy.config(**{'response.timeout': 3600})  # default is 300s
    @cherrypy.expose()
    def uploadExistingFile(self):
        """Server Side Upload Function for existing files
            Creates a new ciphertext and new access files to all
            users who have access to the file. DB File Information updated
            Security: Authenticate User Message by users session key
            Concurrency control"""
        lcHDRS = {}
        for key, val in cherrypy.request.headers.iteritems():
            lcHDRS[key.lower()] = val
        username = lcHDRS['username']
        sessionKey = um.getSessionKey(username)
        if sessionKey != -1:
            try:
                data = json.loads(security.decryptS_AES(lcHDRS['data'].decode('hex'), sessionKey.decode('hex')))
                usr_id = DBmodule.db_getUserID(username)
                fn = data['filename']
                iv = data['iv']
                aes = lcHDRS['aes']
                sign = data['sign']
                files = DBmodule.db_listMyFiles(usr_id)
                filenames = [x.encode('latin-1') for x in files]
                if fn in filenames:
                    file_id = DBmodule.db_getFileId(usr_id, fn)
                    # Concurrent Access
                    while (DBmodule.db_fileStatus(file_id) is True):
                        time.sleep(2)
                    status = DBmodule.db_fileInUse(file_id)
                    if status:
                        destination = os.path.join('storage', str(file_id) + '.file')
                        # Save Ciphertext
                        with open(destination, 'wb') as f:
                            shutil.copyfileobj(cherrypy.request.body, f)
                        userList = DBmodule.db_whoHasAccess(file_id)
                        # Save FILE Encrypted by RSA for every user
                        for i in range(0, len(userList)):
                            with open(destination+'.key'+str(userList[i]), 'wb') as f:
                                f.write(aes[i])
                        # Add File Information to DB
                        uni = iv.decode('hex').decode('latin-1')
                        DBmodule.db_fileInfoUpdate(file_id, usr_id, sign, uni)
                        statusF = DBmodule.db_fileNotInUse(file_id)
                        if statusF is True:
                            return 'Okay, File Updated'
                        else:
                            raise cherrypy.HTTPError(408, 'Request Timeout! Please Try Again\nSafeBox Team')
                    else:
                        raise cherrypy.HTTPError(408, 'Request Timeout! Please Try Again\nSafeBox Team')
            except:
                raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')


    @cherrypy.config(**{'response.timeout': 3600})  # default is 300s
    @cherrypy.expose()
    def upload(self):
        """Server Side Upload Function for new files
            Creates a new ciphertext and new access files to the user who
            wants to save the file. DB File Information updated
            Security: Authenticate User Message
            Concurrency control"""
        lcHDRS = {}
        for key, val in cherrypy.request.headers.iteritems():
            lcHDRS[key.lower()] = val
        username = lcHDRS['username']
        sessionKey = um.getSessionKey(username)
        if sessionKey != -1:
            try:
                data = json.loads(security.decryptS_AES(lcHDRS['data'].decode('hex'), sessionKey.decode('hex')))
                usr_id = DBmodule.db_getUserID(username)
                fn = data['filename']
                iv = data['iv']
                aes = lcHDRS['aes']
                sign = data['sign']
                files = DBmodule.db_listMyFiles(usr_id)
                filenames = [x.encode('latin-1') for x in files]
                # File does not exist. Add New File
                if fn not in filenames:
                    new_id = DBmodule.getNewFileId()
                    destination = os.path.join('storage', str(new_id) + '.file')
                    # Save Ciphertext
                    with open(destination, 'wb') as f:
                        shutil.copyfileobj(cherrypy.request.body, f)
                    # Save FILE Encrypted by RSA
                    with open(destination+'.key'+str(usr_id), 'wb') as f:
                        f.write(aes)
                    # Add File Information to DB
                    uni = iv.decode('hex').decode('latin-1')
                    DBmodule.db_insertFile(fn, '/', uni, 1, usr_id, sign)
                    return 'Okay, New File Add'
            except:
                raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')


    @cherrypy.expose
    def download(self, **kwargs):
        """Server Side Download a file
            Gets the ciphertext of the file by file ID, user access file by his
            user id from the File System and the IV from the DB
            Security: Authenticate User Message
            Concurrency control"""
        # Multipart aux function
        def read(i_file, chunk_size=16 * 1024):
            while True:
                ret = i_file.read(chunk_size)
                if not ret:
                    break
                yield ret
        
        username = kwargs['username']
        sessionKey = um.getSessionKey(username)
        if sessionKey != -1:
            try:
                data = json.loads(security.decryptS_AES(kwargs['data'].decode('hex'), sessionKey.decode('hex')))
                usr_id = DBmodule.db_getUserID(username)
                filename = data['filename']
                file_id = DBmodule.db_getFileId(usr_id, filename)
                # Concurrent Access
                while (DBmodule.db_fileStatus(file_id) is True):
                    time.sleep(2)
                status = DBmodule.db_fileInUse(file_id)
                # Verify if the user is valid and have permission to access the file
                if (status and um.validUser(username) and DBmodule.db_filePermission(usr_id, file_id)):
                    destination = os.path.join('storage', str(file_id)+'.file')
                    # Get User Access File
                    with open(destination+'.key'+str(usr_id)) as f:
                        aes = f.read()
                    iv = DBmodule.db_getFileIV(file_id).encode('latin-1').encode('hex')
                    sign = DBmodule.db_getFileHash(file_id)
                    message = {'iv': iv,
                                'sign': sign}
                    messageToSend = security.encryptS_AES(json.dumps(message), sessionKey.decode('hex')).encode('hex')
                    cherrypy.response.headers['data'] = messageToSend
                    cherrypy.response.headers['aes'] = aes
                    statusF = DBmodule.db_fileNotInUse(file_id)
                    if statusF is True:
                        return read(open(destination, 'rb'))
                    else:
                        raise cherrypy.HTTPError(408, 'Request Timeout! Please Try Again\nSafeBox Team')
                else:
                    raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
            except:
                raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
    download._cp_config = {'response.stream': True}


    @cherrypy.expose
    def permission(self, **kwargs):
        """ Verify if the user has permissions to share the file """
        username = kwargs['username']
        sessionKey = um.getSessionKey(username)
        if sessionKey != -1:
            try:
                data = json.loads(security.decryptS_AES(kwargs['data'].decode('hex'), sessionKey.decode('hex')))
                file_name = data['filename']
                usr_id = DBmodule.db_getUserID(username)
                file_id = DBmodule.db_getFileId(usr_id, file_name)
                if DBmodule.db_permission(file_id, usr_id) == "Y":
                    return "1"
                return "0"
            except:
                return "0"


    @cherrypy.expose
    def share(self, **kwargs):
        """Server Side Share Initial Commnunication
            Gets user access file by his user id from the File System and the
            user destination public key, from the DB, by his ID and sends the
            information to client
            Security: Authenticate User Message
            Concurrency control"""
        username = kwargs['username']
        sessionKey = um.getSessionKey(username)
        if sessionKey != -1:
            try:
                data = json.loads(security.decryptS_AES(kwargs['data'].decode('hex'), sessionKey.decode('hex')))
                file_name = data['filename']
                usr_dst_name = data['usrdstname']
                usr_id = DBmodule.db_getUserID(username)
                file_id = DBmodule.db_getFileId(usr_id, file_name)
                # Concurrent Access
                while (DBmodule.db_fileStatus(file_id) is True):
                    time.sleep(2)
                status = DBmodule.db_fileInUse(file_id)
                # Verify if the user is valid and have access to the file
                if status and um.validUser(username) and DBmodule.db_filePermission(usr_id, file_id):
                    destination = os.path.join('storage', str(file_id)+'.file')
                    # Get User Access File
                    with open(destination+'.key'+str(usr_id)) as f:
                        aes = f.read()
                    usr_dst_id = DBmodule.db_getUserID(usr_dst_name)
                    pub_key = DBmodule.db_getUserPubKey(usr_dst_id)
                    message = {'aes': aes,
                                'pubkey': pub_key}
                    messageToSend = security.encryptS_AES(json.dumps(message), sessionKey.decode('hex')).encode('hex')
                    cherrypy.response.headers['data'] = messageToSend
                    statusF = DBmodule.db_fileNotInUse(file_id)
                    if statusF is True:
                        return "Okay"
                    else:
                        raise cherrypy.HTTPError(408, 'Request Timeout! Please Try Again\nSafeBox Team')
                else:
                    raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
            except:
                raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')

    @cherrypy.expose
    def shareFile(self):
        """Server Side Share Final Commnunication
            Saves the access file of the new user and update
            Database Information of the AccessManagement Table
            Security: Authenticate User Message
            Concurrency control"""
        lcHDRS = {}
        for key, val in cherrypy.request.headers.iteritems():
            lcHDRS[key.lower()] = val
        username = lcHDRS['username']
        sessionKey = um.getSessionKey(username)
        if sessionKey != -1:
            try:
                data = json.loads(security.decryptS_AES(lcHDRS['data'].decode('hex'), sessionKey.decode('hex')))
                filename = data['filename']
                usr_dst_name = data['usrdstname']
                file_key = data['filekey']
                usr_id = DBmodule.db_getUserID(username)
                file_id = DBmodule.db_getFileId(usr_id, filename)
                # Concurrent Access
                while (DBmodule.db_fileStatus(file_id) is True):
                    time.sleep(2)
                status = DBmodule.db_fileInUse(file_id)
                # Verify if the user is valid and has permission to access the file
                if status and um.validUser(username) and DBmodule.db_filePermission(usr_id, file_id):
                    usr_dst_id = DBmodule.db_getUserID(usr_dst_name)
                    destination = os.path.join('storage', str(file_id) + '.file')
                    # Save FILE Encrypted by RSA
                    with open(destination+'.key'+str(usr_dst_id), 'wb') as f:
                        f.write(file_key)
                        # Add information to the Database
                    DBmodule.db_fileNewAccess(file_id, usr_dst_id, usr_id, data['permission'])
                    statusF = DBmodule.db_fileNotInUse(file_id)
                    if statusF is True:
                        return 'Okay'
                    else:
                        raise cherrypy.HTTPError(408, 'Request Timeout! Please Try Again\nSafeBox Team')
                else:
                    raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
            except:
                raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')

    @cherrypy.expose
    def unShare(self, **kwargs):
        """Server Side Unshare
            Remove user AccessFile to the File by its ID and update Database
            AccessManagement Table
            Security: Authenticate User Message
            Concurrency control"""
        username = kwargs['username']
        sessionKey = um.getSessionKey(username)
        if sessionKey != -1:
            try:
                data = json.loads(security.decryptS_AES(kwargs['data'].decode('hex'), sessionKey.decode('hex')))
                filename = data['filename']
                user_id = DBmodule.db_getUserID(username)
                # Concurrent Access
                file_id = DBmodule.db_getFileId(user_id, filename)
                while (DBmodule.db_fileStatus(file_id) is True):
                    time.sleep(2)
                status = DBmodule.db_fileInUse(file_id)
                # Verify if the user is valid and have access to the file
                if status and um.validUser(kwargs['username']) and DBmodule.db_filePermission(user_id, file_id):
                    unsharename = data['unshare']
                    unshareid = DBmodule.db_getUserID(unsharename)
                    userlist = [unshareid] + DBmodule.db_getAllShareDependencies(unshareid, file_id)
                    # Remove access permission from the database
                    DBmodule.db_removeShare(user_id, file_id, unshareid)
                    # Remoce user access file from the server
                    for usr in userlist:
                        os.remove('storage/'+str(file_id)+'.file.key'+str(usr))
                    statusF = DBmodule.db_fileNotInUse(file_id)
                    if statusF is True:
                        return 'Okay'
                    else:
                        raise cherrypy.HTTPError(408, 'Request Timeout! Please Try Again\nSafeBox Team')
                else:
                    raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
            except:
                raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')


    @cherrypy.expose
    def removeFile(self):
        """Server Side Remove
            Remove ciphertext of the file and all user AccessFiles to it
            by its ID and update Database AccessManagement Table
            Security: Authenticate User Message
            Concurrency control"""
        lcHDRS = {}
        for key, val in cherrypy.request.headers.iteritems():
            lcHDRS[key.lower()] = val
        username = lcHDRS['username']
        sessionKey = um.getSessionKey(username)
        if sessionKey != -1:
            try:
                data = json.loads(security.decryptS_AES(lcHDRS['data'].decode('hex'), sessionKey.decode('hex')))
                filename = data['filename']
                user_id = DBmodule.db_getUserID(username)
                file_id = DBmodule.db_getFileId(user_id, filename)
                # Concurrent Access
                while (DBmodule.db_fileStatus(file_id) is True):
                    time.sleep(2)
                status = DBmodule.db_fileInUse(file_id)
                # Verify if the user is valid and has access to the file
                if status and um.validUser(username) and DBmodule.db_filePermission(user_id, file_id):
                    # If the user is the owner of the file, all the users loose the file
                    if DBmodule.db_isOwner(user_id, file_id) == 1:
                        DBmodule.db_removeFile(file_id)
                        pattern = '^'+str(file_id)+'.file'
                        mypath = 'storage'
                        for root, dirs, files in os.walk(mypath):
                            for fileFound in filter(lambda x: re.match(pattern, x), files):
                                os.remove(os.path.join(root, fileFound))
                    # If the user is not the owner, only removes it's access to the file
                    else:
                        userlist = [user_id] + DBmodule.db_getAllShareDependencies(user_id, file_id)
                        for usr in userlist:
                            DBmodule.db_removeAccess(file_id, usr)
                            os.remove('storage/'+str(file_id)+'.file.key'+str(usr))
                        statusF = DBmodule.db_fileNotInUse(file_id)
                        if statusF is True:
                            return 'Okay'
                        else:
                            raise cherrypy.HTTPError(408, 'Request Timeout! Please Try Again\nSafeBox Team')
                else:
                    raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
            except:
                raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')

    @cherrypy.expose
    def listMyFiles(self, **kwargs):
        """Server Side List Files
            List all the files that can be accessed by the user
            Security: Authenticate User Message"""
        if um.validUser(kwargs['username']):
            sessionKey = um.getSessionKey(kwargs['username'])
            usr_id = DBmodule.db_getUserID(kwargs['username'])
            message = DBmodule.db_listMyFilesInfo(usr_id)
            messageToSend = security.encryptS_AES(json.dumps(message), sessionKey.decode('hex')).encode('hex')
            return messageToSend
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')

    @cherrypy.expose
    def getShareUsers(self, **kwargs):
        """Server Side Get Share Users
            Get all the users that are available to share a file
            filtered by favourite user or normal user
            Security: Authenticate User Message"""
        if um.validUser(kwargs['username']):
            sessionKey = um.getSessionKey(kwargs['username'])
            usr_id = DBmodule.db_getUserID(kwargs['username'])
            data = json.loads(security.decryptS_AES(kwargs['data'].decode('hex'), sessionKey.decode('hex')))
            filename = data['filename']
            file_id = DBmodule.db_getFileId(usr_id, filename)
            access = DBmodule.db_getUsersWithFile(file_id)
            every = DBmodule.db_getAllUsers()
            fav = [x for x in DBmodule.db_getPreviousUsersShared(usr_id)
                if x not in access]
            fav += ['@@@@@']
            fav += [x for x in every if x not in fav and 
                x != kwargs['username'] and x not in access]
            return security.encryptS_AES(json.dumps(fav), sessionKey.decode('hex')).encode('hex')
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')

    @cherrypy.expose
    def getSharedWith(self, **kwargs):
        """Server Side GetSharedWith (Users)
            Get all the users that have access to a file
            Security: Authenticate User Message"""
        if um.validUser(kwargs['username']):
            sessionKey = um.getSessionKey(kwargs['username'])
            usr_id = DBmodule.db_getUserID(kwargs['username'])
            data = json.loads(security.decryptS_AES(kwargs['data'].decode('hex'), sessionKey.decode('hex')))
            file_id = DBmodule.db_getFileId(usr_id, data['filename'])
            return security.encryptS_AES(json.dumps(DBmodule.db_getShareFileWith(usr_id, file_id)), sessionKey.decode('hex')).encode('hex')
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')


    @cherrypy.expose
    def askForLogIn(self):
        """Server Side User asks for Log In operation
            Send "OK" message to the user to accept Log In Operation
            From now on, the user has to communicate with ciphered messages
            using Servers Public Key
        """
        return "OK"


    @cherrypy.expose
    def logInUser(self, **kwargs):
        """Server Side logIn User
        User sends his username (Unique Identifier) and his password
        Security: Message from user ciphered with Server Public Key
        Session Management: Create a Public Key with DiffieHellman"""
        # Decipher the Message with Server Private Key
        receivedData = dm.decryptMessageReceived(kwargs['data'].decode('hex'))
        print receivedData['userID']
        # Verify if the user exists and has finished the regist process
        if DBmodule.db_registAuthenticate(receivedData['userID']) and \
            DBmodule.db_getLogIn(receivedData['userID'], receivedData['password']) == 1:
            # Create Session
            print receivedData['userID']
            print receivedData['password']
            serverSession = DiffieHellman.DiffieHellman()
            # Create challenge
            token = os.urandom(20)
            um.addSession(receivedData['userID'], serverSession, token)
            # Send to client the Token and the session public key
            tf = tempfile.NamedTemporaryFile(delete=True)
            pub_key = DBmodule.db_getUserPubKey(DBmodule.db_getUserID(receivedData['userID'])).decode('hex')
            security.encrypt_RSA(security.importkey_RSA(pub_key), token, tf)
            messageToSend = {'token': tf.read().encode('hex'),
                            'session': serverSession.publicKey}
            return json.dumps(messageToSend)
        elif DBmodule.db_registNotAuthenticate(receivedData['userID']):
            return "REGIST_AGAIN"
        else:
            return "ERROR"


    @cherrypy.expose
    def authTokenValidation(self, **kwargs):
        """Server Side LogIn Validation
        Receives a token signed by the user and validate it
        Security: Message from user ciphered with Server Public Key
        Session Management: Create a Session Key with DiffieHellman
        """
        message = ast.literal_eval(kwargs['message'])
        tokenSigned = ast.literal_eval(kwargs['token'])
        # Decipher the Message with Server Private Key
        receivedData = dm.decryptMessageReceived(message['data'].decode('hex'))
        receivedToken = dm.decryptMessageReceived(tokenSigned['data'].decode('hex'))
        """ ----------------- PAM -------------------- """
        user = receivedData['userID']
        auth = False
        path = DBmodule.getPubKeyPath()
        myPam = pam.pam_module(user)
        token = um.getUserToken(user).encode('base64')
        signed = receivedToken['token']
        if DBmodule.db_getLogIn(receivedData['userID'], receivedData['password']) == 1:
            match = "Gambiarra"
        else:
            match = "Menos Gambiarra"
        
        myPam.setItems(path, token, signed, match)
        try:
            myPam.auth.authenticate()
        except PAM.error, resp:
            print 'Go away! (%s)' % resp
        except:
            print 'Internal error'
        else:
            print 'Good to go!'
            auth = True    
        """ ----------------- PAM -------------------- """
        # If Correct establish a session
        if auth and um.existSession(user):
            # Inform Client that the session is established
            serverSession = um.getSession(receivedData['userID'])
            serverSession.genKey(long(json.loads(kwargs['session'])))
            um.addUser(receivedData['userID'], serverSession.getKey().encode('hex'))
            return "OK"
        # Else Delete User
        else:
            # Inform CLient that the session is not established
            return "ERROR"


    @cherrypy.expose
    def askForRegist(self):
        """Server Side User asks for regist
            Send "OK" message to the user to accept regist
            From now on, the user has to communicate with ciphered messages
            using Servers Public Key
        """
        return "OK"

    @cherrypy.expose
    def registUser(self, **kwargs):
        """Server Side Regist User
        User sends his username (Unique Identifier) and his Smart Card 
        Public Key information (MOD and EXP).
        Security: Message from user ciphered with Server Public Key"""
        # Decipher the Message with Server Private Key
        receivedData = dm.decryptMessageReceived(kwargs['data'].decode('hex'))
        # Verify if the user exists or has not finished the regist process
        if not DBmodule.db_existingUserBI(receivedData['userID']) or \
            DBmodule.db_registNotAuthenticate(receivedData['userID']):
            # Save User Public Key in a File
            destination = os.path.join('publicKey', str(receivedData['userID']) + '.pub')
            with open(destination, 'wb') as f:
                f.write("%s:%s" %(str(kwargs['exp']), str(kwargs['mod'])))
            # Update DB
            if not DBmodule.db_existingUserBI(receivedData['userID']):
                DBmodule.db_addNewUser(receivedData['username'], receivedData['userID'],
                                    pw.make_hash(receivedData['password']), kwargs['pub_key'])
            else:
                DBmodule.db_UserInfoUpdate(receivedData['username'], receivedData['userID'],
                                    pw.make_hash(receivedData['password']), kwargs['pub_key'])
            # Ask PAM what it needs to validate the user identity
            """ ----------------- PAM -------------------- """
            token = os.urandom(20)
            um.addRegist(receivedData['userID'], token)
            """ ----------------- PAM -------------------- """
            # Send to client the Token encrypted by User Public Key
            tf = tempfile.NamedTemporaryFile(delete=True)
            security.encrypt_RSA(security.importkey_RSA(kwargs['pub_key'].decode('hex')),
                token, tf)
            return  tf.read().encode('hex')
        else:
            return "ERROR"


    @cherrypy.expose
    def registTokenValidation(self, **kwargs):
        """Server Side Regist Validation with authentication
        Receives a token signed by the user and validate it
        Security: Message from user ciphered with Server Public Key
        """
        # Decipher the Message with Server Private Key
        message = ast.literal_eval(kwargs['message'])
        tokenSigned = ast.literal_eval(kwargs['token'])
        # Decipher the Message with Server Private Key
        receivedData = dm.decryptMessageReceived(message['data'].decode('hex'))
        receivedToken = dm.decryptMessageReceived(tokenSigned['data'].decode('hex'))
        # Send Token to PAM
        """ ----------------- PAM -------------------- """
        user = receivedData['userID']
        auth = False
        path = DBmodule.getPubKeyPath()
        myPam = pam.pam_module(user)
        token = um.getRegistToken(user).encode('base64')
        signed = receivedToken['token']
        pwd = pw.make_hash(receivedData['password']).encode('base64')
        serverpw = DBmodule.db_getUserPW(user).encode('base64')
        myPam.setItems(path, token, signed, "Menos Gambiarra")
        try:
            myPam.auth.authenticate()
        except PAM.error, resp:
            print 'Go away! (%s)' % resp
        except:
            print 'Internal error'
        else:
            print 'Good to go!'
            auth = True    
        # If Correct establish a session
        if auth:
            # Update Database User Table with register confirmation
            DBmodule.db_AuthUserRegist(user)
            # Inform Client that the session is established
            return "OK"
        else:
            # Inform CLient that the session is not established
            return "ERROR"


    @cherrypy.expose
    def logOut(self, **kwargs):
        """Server Side Logout User
            --------------------------
            Security: Destroy Session Key"""
        receivedData = dm.decryptMessageReceived(kwargs['data'].decode('hex'))
        if um.validUser(receivedData['username']):
            um.popUser(receivedData['username'])
            return '1'
        else:
            raise cherrypy.HTTPError(401, 'Currently, you are not a valid user!\nSafeBox Team')

    # Get user public key
    @cherrypy.expose
    def getPublicKey(self, **kwargs):
        """Server Side get User Publick Key from DB"""
        username = kwargs['username']
        userID = DBmodule.db_getUserId(str(username))
        if userID is None:
            pub_key = DBmodule.db_getUserPubKey(0)
        else:
            pub_key = DBmodule.db_getUserPubKey(userID)
        return pub_key

    @cherrypy.expose
    def getPublicKeyFile(self, **kwargs):
        """Server Side get Get list of public keys of users who have
        access to the file"""
        username = kwargs['username']
        usr_id = DBmodule.db_getUserID(username)
        filename = kwargs['filename']
        file_id = DBmodule.db_getFileId(usr_id, filename)
        if file_id is None:
            return json.dumps([])
        return json.dumps(DBmodule.db_whoHasAccessPub(file_id))


"""Class to manage receivedCipheredData"""


class DataManagement(object):
    def decryptMessageReceived(self, receivedCipheredData):
        with open('PrivateKey', 'rb') as f:
            serverPrivateKey = security.importkey_RSA(f.read())
        return json.loads(security.decrypt_RSA(serverPrivateKey, receivedCipheredData))

    def signToken(self, token):
        with open('PrivateKey', 'rb') as f:
            serverPrivateKey = security.importkey_RSA(f.read())
        return security.signFile(serverPrivateKey, token)

"""Class to manage the users session"""


class UserManagement(object):
    def __init__(self):
        self.connectedUsers = defaultdict()
        self.serverSessions = defaultdict()
        self.serverTokens = defaultdict()
        self.serverRegist = defaultdict()
        self.count = 0

    # New User Logged In
    def addUser(self, username, session):
        user_id = DBmodule.db_getUserID(username)
        self.connectedUsers[user_id] = session
        self.count += 1

    # Add Session Data
    def addSession(self, username, pub_key, token):
        user_id = DBmodule.db_getUserID(username)
        self.serverSessions[user_id] = pub_key
        self.serverTokens[user_id] = token


    def addRegist(self, username, token):
        self.serverRegist[username] = token

    def popRegist(self, username):
        if username in self.serverRegist.keys():
            del self.serverRegist[username]

    def getRegistToken(self, username):
        return self.serverRegist[username]
        
    # Get Session Pub Key
    def getSession(self, username):
        user_id = DBmodule.db_getUserID(username)
        pub = self.serverSessions[user_id]
        self.estSession(username)
        return pub

    def getUserToken(self, username):
        user_id = DBmodule.db_getUserID(username)
        token = self.serverTokens[user_id]
        return token

    # Verify if the user has a valid token
    def validUser(self, username):
        user_id = DBmodule.db_getUserID(username)
        if user_id in self.connectedUsers.keys():
            #if self.connectedUsers[user_id] == token.decode('hex'):
            return True
        return False

    def getSessionKey(self, username):
        user_id = DBmodule.db_getUserID(username)
        if user_id in self.connectedUsers.keys():
            return self.connectedUsers[user_id]
        else:
            return -1

    def existSession(self, username):
        user_id = DBmodule.db_getUserID(username)
        if user_id in self.serverSessions.keys():
            return True
        return False

    # User logged Out
    def popUser(self, username):
        user_id = DBmodule.db_getUserID(username)
        try:
            del self.connectedUsers[user_id]
        except KeyError:
            pass
        self.count -= 1
        return "Okay"


    # Session Establish
    def estSession(self, username):
        user_id = DBmodule.db_getUserID(username)
        try:
            del self.serverSessions[user_id]
            del self.serverTokens[user_id]
        except KeyError:
            pass
        return "Okay"


if __name__ == '__main__':
    # SSL Communications
    cherrypy.server.ssl_module = 'builtin'
    cherrypy.server.ssl_certificate = "cert2.pem"
    cherrypy.server.ssl_private_key = "privkey2.pem"
    # User Management
    um = UserManagement()
    dm = DataManagement()
    # CherryPy Server
    cherrypy.quickstart(App(), '/', config)
