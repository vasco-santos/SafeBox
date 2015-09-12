#!/usr/bin/env python
"""
Security - DETI UA (2014/2015)
@authors: Jose Sequeira 64645
         Vasco Santos 64191

Based on:
- https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py
- http://tools.ietf.org/html/rfc3526
"""

import os
from random import getrandbits
from binascii import hexlify
import hashlib

class DiffieHellman(object):
	"""
	A implementation of the Diffie-Hellman Algorithm.
	This class uses the 1536-bit MODP Group (Group 5) from RFC 3526.
	"""
	prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF	
	generator = 2

	def __init__(self):
		"""
		Generate the public and private keys
		"""
		self.privateKey = self.genPrivateKey(540)
		self.publicKey = self.genPublicKey()

	def genPrivateKey(self, bits):
		"""
		Generate a random private key
		"""
		return getrandbits(bits)

	def genPublicKey(self):
		"""
		Generate a public key by: h g**x % p.
		"""
		return pow(self.generator, self.privateKey, self.prime)

	def checkPublicKey(self, key):
		"""
		Check the other party's public key to make sure it has a valid format
		"""
		if(key > 2 and key < self.prime - 1):
			if(pow(key, (self.prime - 1)/2, self.prime) == 1):
				return True
		return False

	def genSecret(self, privateKey, otherKey):
		"""
		Generate a shared secret to be used to generate the Session Key
		"""
		if(self.checkPublicKey(otherKey) == True):
			sharedSecret = pow(otherKey, privateKey, self.prime)
			return sharedSecret
		else:
			raise Exception("Invalid public key.")

	def genKey(self, otherKey):
		"""
		Derive the shared secret, and hash it to obtain the session key.
		"""
		self.sharedSecret = self.genSecret(self.privateKey, otherKey)
		s = hashlib.sha256()
		s.update(str(self.sharedSecret))
		self.key = s.digest()

	def getKey(self):
		"""
		Return the shared secret key
		"""
		return self.key
