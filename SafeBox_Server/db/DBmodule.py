from db import db_init
from sqlalchemy.orm import class_mapper
from sqlalchemy.sql import and_, or_, not_
from sqlalchemy import update
from sqlalchemy.sql import exists
from Security.security import PBKDKF2 as pw
import time
import os

'''
Security - DETI UA (2014/2015)
@authors: Jose Sequeira 64645
         Vasco Santos 64191
'''

'''
Database Session and Tables
'''
session = db_init.session
File = db_init.File
User = db_init.User
AccessManagement = db_init.AccessManagement
EditionManagement = db_init.EditionManagement

'''
File Table Query
'''


# File Initialization vector
def db_getFileIV(file_id):
    return session.query(File.iv).select_from(File).filter(
        File.id == file_id).scalar()


# Get File Hash
def db_getFileHash(file_id):
    return session.query(File.file_hash).select_from(File).filter(
        File.id == file_id).scalar()


# Verify if the user has permission to download the file
def db_filePermission(usr_id, f_id):
    print session.query(AccessManagement.file_id).select_from(AccessManagement).filter(and_(AccessManagement.user_id == usr_id, AccessManagement.file_id == f_id)).count()
    return session.query(AccessManagement.file_id).select_from(AccessManagement).filter(and_(AccessManagement.user_id == usr_id, AccessManagement.file_id == f_id)).count()


# Update the user's who have access to a file
def db_fileNewAccess(file_id, user_id, who_gave_access, permission):
    new_access = AccessManagement(file_id=int(file_id), user_id=int(user_id),
                    who_gave_access=int(who_gave_access), permission=str(permission))
    session.add(new_access)
    session.commit()


# Get User Permission to share a file
def db_permission(file_id, user_id):
    return session.query(AccessManagement.permission).select_from(AccessManagement).filter(and_(AccessManagement.user_id == user_id, AccessManagement.file_id == file_id)).scalar()


# Verify if a file is already in use
def db_fileInUse(file_id):
    if not db_fileStatus(file_id):
        session.execute(update(File).where(File.id == file_id).values(inUse=True))
        session.commit()
        return True
    else:
        return False


# Verify if a file is ready to use
def db_fileNotInUse(file_id):
    if db_fileStatus(file_id):
        session.execute(update(File).where(File.id == file_id).values(inUse=False))
        session.commit()
        return True
    else:
        return False


 # Verify File Status
def db_fileStatus(file_id):
    return session.query(File.inUse).select_from(File).filter(File.id == file_id).scalar()


# Insert new file information in Database
def db_insertFile(original_name, location, iv, version, usr_id, filehash):
    new_id = getNewFileId()
    new_file = File(id=int(new_id), name=str(original_name), location=str(location),
                iv=iv, version=int(version), file_hash=filehash, owner=int(usr_id))
    session.add(new_file)
    new_acess = AccessManagement(file_id=int(new_id), user_id=int(usr_id),
                                 who_gave_access=int(usr_id), permission=str("Y"))
    session.add(new_acess)
    new_edition = EditionManagement(file_id=int(new_id), user_id=int(usr_id),
                                change_datetime=(time.strftime("%d/%m/%Y") + ' ' + time.strftime("%H:%M")))
    session.add(new_edition)
    session.commit()


# Remove File information from Database
def db_removeFile(file_id):
    session.query(EditionManagement).filter(EditionManagement.file_id == file_id).delete()
    session.query(AccessManagement).filter(AccessManagement.file_id == file_id).delete()
    session.query(File).filter(File.id == file_id).delete()
    session.commit()


# Remove a user permission to a file
def db_removeAccess(file_id, usr_id):
    session.query(AccessManagement).filter(and_(AccessManagement.file_id == file_id,
        AccessManagement.user_id == usr_id)).delete()
    session.commit()


# Verify if a user is owner of a file
def db_isOwner(usr_id, file_id):
    return session.query(exists().where(and_(AccessManagement.file_id == file_id, AccessManagement.user_id == usr_id,
        AccessManagement.who_gave_access == usr_id))).scalar()


# Verify who has access to the file
def db_whoHasAccess(file_id):
    fileList = []
    for user in session.query(AccessManagement.user_id).select_from(
        AccessManagement).filter(AccessManagement.file_id == file_id):
        fileList += user
    return fileList


# Get List of Public Keys of users who have access to the file
def db_whoHasAccessPub(file_id):
    pubKeyList = []
    userList = []
    for user in session.query(AccessManagement.user_id).select_from(
        AccessManagement).filter(AccessManagement.file_id == file_id):
        userList += user
    for user_id in userList:
        pubKeyList += [db_getUserPubKey(user_id)]
    return pubKeyList


# List all the Files of the Server
def db_listAllFiles():

    fileList = []
    for user in session.query(File.id).select_from(File):
        fileList += user
    return fileList


# List all files of an user
def db_listMyFiles(user_id):
    fileList = []
    for usrfile \
            in session.query(File.name).select_from(File).join(
                AccessManagement).filter(
                AccessManagement.user_id == user_id).all():
        fileList += usrfile
    return fileList

# List all files information of an user
def db_listMyFilesInfo(user_id):
    fileList = []
    for usrFile \
            in session.query(File.name, File.owner, AccessManagement.who_gave_access, EditionManagement.user_id, EditionManagement.change_datetime
                ).select_from(File).join(AccessManagement).join(EditionManagement).filter(
                AccessManagement.user_id == user_id).all():
        fileList += [[usrFile[0], db_getUserName(usrFile[1]), db_getUserName(usrFile[2]), db_getUserName(usrFile[3]), usrFile[4]]]
    return fileList


# Get the next File ID
def getNewFileId():
    return session.query(File).count()


# Get the file ID by its name
def db_getFileId(usr_id, filename):
    return session.query(File.id).select_from(File).join(AccessManagement).filter(and_(AccessManagement.user_id ==
                                     usr_id, File.name == filename)).scalar()


# Update File information
def db_fileInfoUpdate(file_id, usr_id, filehash, iv):
    version = db_fileCurrentVersion(file_id)+1
    session.execute(update(File).where(File.id == file_id).values(
        version=version))
    session.execute(update(File).where(File.id == file_id).values(
        file_hash=filehash))
    session.execute(update(File).where(File.id == file_id).values(
        iv=iv))
    session.execute(update(EditionManagement).where(EditionManagement.file_id == file_id).values(
        user_id=usr_id, change_datetime=(time.strftime("%d/%m/%Y") + ' ' + time.strftime("%H:%M"))))

    session.commit()


# Get File Current Version
def db_fileCurrentVersion(file_id):
    return session.query(File.version).select_from(File).filter(
        File.id == file_id).scalar()

'''
User Table Query
'''


# Get User Public Key
def db_getUserPubKey(user_id):
    return session.query(User.pub_key).select_from(User).filter(
        User.id == user_id).scalar()


# Get user ID
""" DELETEEEEEE """
def db_getUserId(username):
    return session.query(User.id).select_from(User).filter(
        User.name == username).scalar()


def db_getUserID(bi):
    return session.query(User.id).select_from(User).filter(
        User.bi == bi).scalar()


# Get User name
def db_getUserName(user_id):
    return session.query(User.name).select_from(User).filter(
        User.id == user_id).scalar()


# Add a new User to Database
""" DELETEEEEEE """
def db_addUser(name, password, mail, pub_key):
    new_id = getNewUserId()
    new_user = User(id=int(new_id), name=str(name), password=str(password),
                    mail=str(mail), pub_key=str(pub_key))
    session.add(new_user)
    session.commit()


def db_addNewUser(name, bi, password, pub_key):
    new_id = getNewUserId()
    new_user = User(id=int(new_id), bi=str(bi), name=str(name),
        password=str(password), pub_key=str(pub_key))
    session.add(new_user)
    session.commit()


# Update File information
def db_UserInfoUpdate(name, bi, password, pub_key):
    session.execute(update(User).where(User.bi == bi).values(name=str(name), password=str(password),
        pub_key=str(pub_key)))
    session.commit()


# Authenticate User Regist
def db_AuthUserRegist(bi):
    session.execute(update(User).where(User.bi == bi).values(regist=1))
    session.commit()

# Get next user ID
def getNewUserId():
    return session.query(User).count()


# Verify if a user already exists
""" DELETEEEEEE """
def db_existingUser(username):
    return session.query(exists().where(User.name == username)).scalar()


def db_existingUserBI(bi):
    return session.query(exists().where(User.bi == bi)).scalar()


# verify if a user exists and has authenticate his register
def db_registAuthenticate(bi):
    return session.query(exists().where(and_(User.bi == bi, User.regist == 1))).scalar()


# verify if a user exists and has not authenticate his register
def db_registNotAuthenticate(bi):
    return session.query(exists().where(and_(User.bi == bi, User.regist == 0))).scalar()

# Verify Login Credentials
def db_getLogIn(username, password):
    tup = session.query(User.id, User.password).select_from(User).filter(User.name == username.encode('latin-1')).all()
    print tup
    if tup != []:
        if pw.check_hash(password, str(tup[0][1])):
            return 1
    return 0

def db_getUserPW(username):
    tup = session.query(User.password).select_from(User).filter(User.name == username.encode('latin-1')).scalar()
    return tup.encode('utf-8')


# List all users
def db_getAllUsers():
    userList = []
    for usr \
            in session.query(User.bi).select_from(User).all():
        userList += usr
    return userList


# List all the users that an user already has shared
def db_getPreviousUsersShared(usr_id):
    userList = []
    for usr \
        in session.query(User.bi).select_from(User).\
            join(AccessManagement).filter(and_(
                User.id != usr_id, AccessManagement.who_gave_access == usr_id)).all():
        print usr
        userList += usr
    return userList


# Verify who has access to the file
def db_getUsersWithFile(file_id):
    userList = []
    for user \
        in session.query(User.name).select_from(User).\
            join(AccessManagement).filter(AccessManagement.file_id == file_id):
        userList += user
    return userList


def db_getShareFileWith(usr_id, file_id):
    userList = []
    for usr \
        in session.query(User.bi).select_from(User).\
            join(AccessManagement).filter(and_(
                User.id != usr_id, AccessManagement.file_id == file_id)).all():
        userList += usr
    return userList


def db_getShareFileWithID(usr_id, file_id):
    userList = []
    for usr \
        in session.query(User.id).select_from(User).\
            join(AccessManagement).filter(and_(
                User.id != usr_id, AccessManagement.who_gave_access == usr_id,
                AccessManagement.file_id == file_id)).all():
        userList += usr
    return userList


# Unshare a file with an user
def db_removeShare(usr_id_sharing, file_id, usr_id_shared):

    usrs = [usr_id_shared] + db_getAllShareDependencies(usr_id_shared, file_id)
    for usr in usrs:
        session.query(AccessManagement).filter(and_(
                                  AccessManagement.file_id == file_id, AccessManagement.user_id ==
                                  usr)).delete()
        session.commit()
    return usrs


# Get all Sharing Dependencies to Unshare or Remove a file
def db_getAllShareDependencies(usr_sharing, file_id):
    if isinstance(usr_sharing, (int, long)):
        l = db_getShareFileWithID(usr_sharing, file_id)
        l += db_getAllShareDependencies(l, file_id)
    elif usr_sharing == []:
        return []
    else:
        l = db_getShareFileWithID(usr_sharing[0], file_id)
        l += db_getAllShareDependencies(usr_sharing[1:] + l, file_id)
    return l


'''
Public Key Folder
'''

def getPubKeyPath():
    if not os.path.exists('publicKey'):
        os.makedirs('publicKey')
    return os.path.abspath("publicKey")+"/"

