import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool
from sqlalchemy.pool import NullPool
from sqlalchemy.pool import StaticPool

'''
Secutity - DETI UA (2014/2015)
@authos: Jose Sequeira 64645
         Vasco Santos 64191
'''


Base = declarative_base()

'''
Database Tables Definition
'''


class User(Base):
    __tablename__ = 'User'
    # Here we define columns for the table User
    id = Column(Integer, primary_key=True)
    bi = Column(String(8), nullable=False)
    name = Column(String(250), nullable=False)
    password = Column(String(250), nullable=False)
    pub_key = Column(String(250), nullable=False)
    regist = Column(Boolean, nullable=False, default=False)


class File(Base):
    __tablename__ = 'File'
    # Here we define columns for the table File.
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    location = Column(String(250), nullable=False)
    iv = Column(String(250, convert_unicode=True), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    file_hash = Column(String(250), nullable=False)
    owner = Column(Integer, nullable=False)
    inUse = Column(Boolean, unique=False, default=False)


class AccessManagement(Base):
    __tablename__ = 'AccessManagement'
    file_id = Column(Integer, ForeignKey('File.id'), primary_key=True)
    user_id = Column(Integer, ForeignKey('User.id'), primary_key=True)
    who_gave_access = Column(Integer)
    permission = Column(String(5), nullable=False)


class EditionManagement(Base):
    __tablename__ = "EditionManagement"
    file_id = Column(Integer, ForeignKey('File.id'), primary_key=True)
    user_id = Column(Integer, ForeignKey('User.id'))
    change_datetime = Column(String, nullable=False)

# Create an engine that stores data in the local directory's
# sqlalchemy_example.db file.

engine = create_engine('sqlite:///SafeBox.db',
                    connect_args={'check_same_thread':False},
                    poolclass=StaticPool)

# Create all tables in the engine. This is equivalent to "Create Table"
# statements in raw SQL.
Base.metadata.create_all(engine)

# Create Database Session

Session = sessionmaker(bind=engine)
Session.configure(bind=engine)
session = Session()


def getSession(self):
    return session
