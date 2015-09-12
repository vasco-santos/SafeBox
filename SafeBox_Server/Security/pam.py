from PyKCS11.LowLevel import CKA_ID, CKA_LABEL, CKA_CLASS, CKO_PRIVATE_KEY, CKO_CERTIFICATE, CKK_RSA, CKA_KEY_TYPE, CKA_VALUE
import PAM

class pam_module:

    def pam_conv(self,auth, query_list, userData):
        resp = []
        print "Query list: " + str(query_list) + "\n"
        for i in range(len(query_list)): 
            query = query_list[i][0]
            type = query_list[i][1]
            if type == PAM.PAM_PROMPT_ECHO_ON:
                if query == "PATH":
                    resp.append((self.path, 0))
                else:  
                    resp.append((self.token, 0))
            elif type == PAM.PAM_PROMPT_ECHO_OFF:
                if query == "Match":
                    resp.append((self.match, 0))
                else:
                    resp.append((self.signed, 0))
            elif type == PAM.PAM_PROMPT_ERROR_MSG or type == PAM.PAM_PROMPT_TEXT_INFO:
                resp.append(('', 0))
            else:
                return None
        print resp
        return resp

    def setItems(self, p, t, s, m):
        self.path = p
        self.token = t
        if s != "":
            self.signed = s
        self.match = m


    def __init__(self, user):
        self.service = "safebox"
        self.auth = PAM.pam()
        self.auth.start(self.service)

        if user != None:
            self.auth.set_item(PAM.PAM_USER, user)

        self.auth.set_item(PAM.PAM_CONV, self.pam_conv)
        self.token = "!!!".encode('base64')
        self.signed = "!!!".encode('base64')
        self.match = "!!!"
        self.user = user
