#!/usr/bin/env python
# -*- coding: utf-8 -*-

import PyKCS11
import getopt
import sys
import platform
import datetime
from M2Crypto import X509
import re
import urllib2
import OpenSSL
from OpenSSL import crypto
from PyKCS11.LowLevel import CKA_ID, CKA_LABEL, CKA_CLASS, CKO_PRIVATE_KEY, CKO_CERTIFICATE, CKK_RSA, CKA_KEY_TYPE, CKA_VALUE

'''
Security - DETI UA (2014/2015)
@authors: Jose Sequeira 64645
         Vasco Santos 64191

Based on:
- http://ludovicrousseau.blogspot.pt/2011/04/pykcs11-provided-samples-dumpitpy.html
'''



def removeAttr(a):
    a.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
    a.remove(PyKCS11.CKA_PRIME_1)
    a.remove(PyKCS11.CKA_PRIME_2)
    a.remove(PyKCS11.CKA_EXPONENT_1)
    a.remove(PyKCS11.CKA_EXPONENT_2)
    a.remove(PyKCS11.CKA_COEFFICIENT)


def isSmartCardAvailable():
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load('/usr/local/lib/libpteidpkcs11.so')
    slots = pkcs11.getSlotList()
    if len(slots) == 0:
        return False
    else:
        return True

def pinCorrect(pin):
    try:
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load('/usr/local/lib/libpteidpkcs11.so')
        session = pkcs11.openSession(0l)
        session.login(pin)
        return 1
    except:
        return 0


class Smartcard:
    """ Class composed by Methods to interact with the Smartcard """
    def __init__(self, pin):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load('/usr/local/lib/libpteidpkcs11.so')
        self.pin = str(pin)
        self.session = None
        self.objects = None

    def smartCardAvailable(self, scSlot):
        """ Method to verify if there is a smartcard plugged in"""
        try:
            self.session = self.pkcs11.openSession(scSlot)
            return 1
        except:
            return 0

    def connect(self, scSlot):
        """ Method to connect the smartcard """
        try:
            self.session = self.pkcs11.openSession(scSlot)
            self.session.login(pin = self.pin)
            self.objects = self.session.findObjects()
        except:
            return False
        return True

    def disconnect(self):
        """ Method to disconnect the smartcard """
        try:
            self.session.logout()
            self.session.closeSession()
            return "Disconnected"
        except:
            return "Operation Failed"

    def getCertificates(self):
        try:
            certificateList = []
            for obj in self.objects:
                d = obj.to_dict()
                if d['CKA_CLASS'] == 'CKO_CERTIFICATE':
                    der = self._os2str(d['CKA_VALUE'])
                    certificate = X509.load_cert_string(der, X509.FORMAT_DER)
                    certificateList.append(certificate)
            return certificateList
        except:
            return "There was a problem loading your Certificate List"

    def _os2str(self, os):
        return ''.join(chr(c) for c in os)

    def getUserBI(self):
        """ Method to get the Identification Number from the Smartcard
        It is used the first certificate from the smartcard and a
        regular expression to get BI """
        try:
            certificateList = self.getCertificates()
            certificate = certificateList[0].as_text()
            p = re.compile("serialNumber=BI(\d+)", re.UNICODE)
            findBI = re.search(p, certificate)
            if findBI:
                return findBI.groups()[0]
            else:
                return None
        except:
            return "There was a problem loading your Smartcard data"

    def getUserName(self):
        """ Method to get the Name from the Smartcard
        It is used the first certificate from the smartcard and a
        regular expression to get Users name """
        try:
            certificateList = self.getCertificates()
            certificate = certificateList[0].as_text()
            p = re.compile("CN=([\w\s]+)\n", re.UNICODE)

            findName = re.search(p, certificate)
            if findName:
                return findName.groups()[-1]
            else:
                return None
        except:
            return "There was a problem loading your Smartcard data"

    def getCertificateVerification(self, certificate, keyToVerify):
        """ Verify if certificate signature is valid """
        if certificate.verify(keyToVerify):
            return True
        else:
            return False

    def certificateChainVerify(self):
        """ Verify if certificate chain is correct, analyse:
        - Certificate signature
        - Validity
        - Is not revoked """
        try:
            certificateList = self.getCertificates()
            result = True
            for (certificate, pubkey) in zip(certificateList[:3], certificateList[1:4]):
                i = 0
                result = result and self.getCertificateVerification(certificate, pubkey.get_pubkey())
                result = result and self.validCertificateCRLDELTA(self.getCertificateCRL(certificate.as_text()), self.getCertificateID(certificate.as_text()))
                result = result and self.validateDate(self.getCertificateValidation(certificate.as_text()))
            return result
        except Exception, e:
            return e
            return "There was a problem loading your Smartcard data"

    def validCertificateCRLDELTA(self, url, certID):
        """ Verify if certifcate ID is declared in CRL or Delta List """
        # Certificate ID
        certID = re.sub(r'\s+', '', certID)
        certID = re.sub(':', '', certID)
        # CRL
        crl = url[0]
        delta = url[1]
        
        if crl != None:
            response = urllib2.urlopen(crl)
            crlList = response.read()
            crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crlList)  
            revoked_objects_CRL = crl_object.get_revoked()
            if revoked_objects_CRL is not None:
                for rvk in revoked_objects_CRL:
                    if str(rvk.get_serial()) == certID.upper():
                        return False
        # Delta
        if delta != None:            
            response = urllib2.urlopen(delta)
            deltaList = response.read()
            delta_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, deltaList)
            revoked_objects_DELTA = delta_object.get_revoked()
            if revoked_objects_DELTA is not None:
                for rvk in revoked_objects_DELTA:
                    if str(rvk.get_serial()) == certID.upper():
                        return False
        
        return True

    def validateDate(self, date):
        """ Verify if certificate is within validity period """
        initDate = datetime.datetime.strptime(date[0].partition(" GMT")[0], '%b %d %H:%M:%S %Y')
        actualDate = datetime.datetime.today()
        endDate = datetime.datetime.strptime(date[1].partition(" GMT")[0], '%b %d %H:%M:%S %Y')
        if initDate > actualDate or actualDate > endDate:
            return False
        return True

    def getCertificateValidation(self, certificate):
        """ Get Certificate Validity Not Before and After """
        p = re.compile("Validity\s+Not Before:\s([\w\s:]+)\s+Not After :\s([\w\s:]+)\n", re.UNICODE)
        m = re.search(p, certificate)
        if m:
            before = m.groups()[0]
            after = m.groups()[1]
        else:
            before = after = None    
        return before, after


    def getCertificateCRL(self, certificate):
        """ Get CRL and DELTA list that are associated to the certificate """
        m = re.search("X509v3 CRL Distribution Points:\s+Full Name:\s+URI:([^\s]+)", certificate)
        n = re.search("X509v3 Freshest CRL:\s+Full Name:\s+URI:([^\s]+)", certificate)
        if m:
            cdp = m.groups()[0]
        else:
            cdp = None
        if n:
            fresh = n.groups()[0]
        else:
            fresh = None

        return (cdp, fresh)

    def getCertificateID(self, certificate):
        """ Get Certificate Serial Number """
        m = re.search("Serial Number:\s+([\d\w:]+)", certificate)
        if m:
            return m.groups()[0]
        else:
            return Nones

    def sign(self, value):
        objects = self.session.findObjects()
        all_attributes = PyKCS11.CKA.keys()
        # remove the CKR_ATTRIBUTE_SENSITIVE attributes since we can't get
        # their values and will get an exception instead
        all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
        all_attributes.remove(PyKCS11.CKA_PRIME_1)
        all_attributes.remove(PyKCS11.CKA_PRIME_2)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
        all_attributes.remove(PyKCS11.CKA_COEFFICIENT)
        # only use the integer values and not the strings like 'CKM_RSA_PKCS'
        all_attributes = [e for e in all_attributes if isinstance(e, int)]
        for o in objects:
            attributes = self.session.getAttributeValue(o, all_attributes)
            attrDict = dict(zip(all_attributes, attributes))
            if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY \
                and attrDict[PyKCS11.CKA_KEY_TYPE] == PyKCS11.CKK_RSA:
                    key = o;
                    break
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
        signature = self.session.sign(key, value, mech)
        s = ''.join(chr(c) for c in signature)
        res = s.encode('base64')
        return res


    def getAuth(self):

        objects = self.session.findObjects()
        all_attributes = PyKCS11.CKA.keys()
        # remove the CKR_ATTRIBUTE_SENSITIVE attributes since we can't get
        # their values and will get an exception instead
        all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
        all_attributes.remove(PyKCS11.CKA_PRIME_1)
        all_attributes.remove(PyKCS11.CKA_PRIME_2)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
        all_attributes.remove(PyKCS11.CKA_COEFFICIENT)
        # only use the integer values and not the strings like 'CKM_RSA_PKCS'
        all_attributes = [e for e in all_attributes if isinstance(e, int)]
        for o in objects:
            attributes = self.session.getAttributeValue(o, all_attributes)
            attrDict = dict(zip(all_attributes, attributes))
            if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY \
                and attrDict[PyKCS11.CKA_KEY_TYPE] == PyKCS11.CKK_RSA:
                    key = o;
                    break
        """key = self.find_object(self.session, [(CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (CKA_KEY_TYPE, PyKCS11.CKK_RSA)])
                                all_attributes = PyKCS11.CKA.keys()
                                all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
                                all_attributes.remove(PyKCS11.CKA_PRIME_1)
                                all_attributes.remove(PyKCS11.CKA_PRIME_2)
                                all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
                                all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
                                all_attributes.remove(PyKCS11.CKA_COEFFICIENT)
                                # only use the integer values and not the strings like 'CKM_RSA_PKCS'
                                all_attributes = [e for e in all_attributes if isinstance(e, int)]
                                attributes = self.session.getAttributeValue(key, all_attributes)
                                attrDict = dict(zip(all_attributes, attributes))
                                """
        m = attrDict[PyKCS11.CKA_MODULUS]
        e = attrDict[PyKCS11.CKA_PUBLIC_EXPONENT]
        if m and e:
            mx = (''.join(chr(c) for c in m))
            ex = (''.join(chr(c) for c in e))
        mx = mx.encode('hex')
        ex = ex.encode('hex')
        return mx, ex


    def find_object(self, session, template):
        objects = session.findObjects(template) 
        if len(objects) == 0:
            for o in objects:
                return o
        return None