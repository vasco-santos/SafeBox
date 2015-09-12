import PAM
import PyKCS11

def removeAttr(a):
    a.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
    a.remove(PyKCS11.CKA_PRIME_1)
    a.remove(PyKCS11.CKA_PRIME_2)
    a.remove(PyKCS11.CKA_EXPONENT_1)
    a.remove(PyKCS11.CKA_EXPONENT_2)
    a.remove(PyKCS11.CKA_COEFFICIENT)

class card_data(object):
 
    def __init__(self, lib="/usr/local/lib/libpteidpkcs11.so"):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)

        self.token_slot = None
        slots = self.pkcs11.getSlotList()
 
        for slot_index in slots:
            slot = self.pkcs11.getSlotInfo(slot_index)
            if 'CKF_TOKEN_PRESENT' in slot.flags2text():
                self.token_slot = slot_index
                break
        if self.token_slot == None:
            raise Exception('Couldn\'t find token slot. Make sure your smart card is inserted.')
     
    def login(self, pin='4654'):
        self.session = self.pkcs11.openSession(self.token_slot)
        self.session.login(pin)
 
    def logout(self):
        if self.session:
            self.session.logout()
 
    def _intarray2bytes(self, x):
        return ''.join(chr(i) for i in x)
 
    def _find_object(self, session, template):
        objects = session.findObjects(template)
         
        for o in objects:
            return o
        return None

    def _get_object_attributes(self, session, o):
        attributes = session.getAttributeValue(o, all_attributes)
        return dict(zip(all_attributes, attributes))

    def sign(self, value):
        key = self._find_object(self.session, [(CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (CKA_KEY_TYPE, PyKCS11.CKK_RSA)])
        all_attributes = PyKCS11.CKA.keys()
        removeAttr(all_attributes)

        # only use the integer values and not the strings like 'CKM_RSA_PKCS'
        all_attributes = [e for e in all_attributes if isinstance(e, int)]
        attributes = self.session.getAttributeValue(key, all_attributes)
        attrDict = dict(zip(all_attributes, attributes))
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
        signature = self.session.sign(key, value, mech)
        s = ''.join(chr(c) for c in signature)
        print "ORIGINAL SIGNATURE: " + s
        res = s.encode('base64')
        return res
