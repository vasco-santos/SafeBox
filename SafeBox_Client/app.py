#!/usr/bin/env python
# -*- coding: utf-8 -*-

import npyscreen
from clientside import client
import curses
import os
import re
import time
from authentication import Smartcard

'''
Security - DETI UA (2014/2015)
@authors: Jose Sequeira 64645
         Vasco Santos 64191
'''

global LogUser
LogUser = None


def excludeFromDict(password):
    with open("FilterDic.txt", 'rb') as f:
        dictWords = [x.rstrip() for x in f.readlines()]
    if password in dictWords:
        return True
    return False    

class FileList(npyscreen.MultiLineAction):
    def __init__(self, *args, **keywords):
        super(FileList, self).__init__(*args, **keywords)
        self.add_handlers({
            "^X": self.exit
        })

    def display_value(self, vl):
        if vl != "You have no files, upload some or ask someone to share their secrets with you":
            return "File: %20s\t Owner: %10s Who Gave Acess: %10s Changed By: %10s Date: %16s" % (vl[0], vl[1], vl[2], vl[3], vl[4])
        else:
            return "%s" % vl
        #return "%20s\t %15s %20s %15s %18s" % (vl[0], vl[1], vl[2], vl[3], vl[4])

    def actionHighlighted(self, act_on_this, keypress):
        if act_on_this == "You have no files, upload some or ask someone to share their secrets with you":
            npyscreen.notify_wait("Man, that's not a file... It's just a warning... ")
        else:
            self.parent.parentApp.getForm("Options").filename.value = act_on_this[0]
            self.parent.parentApp.switchForm("Options")

    def exit(self, keypress):
        self.parent.parentApp.switchForm("Logged")


class FileListDisplay(npyscreen.FormMutt):
    MAIN_WIDGET_CLASS = FileList
    STATUS_WIDGET_CLASS = npyscreen.wgtextbox.Textfield
    STATUS_WIDGET_X_OFFSET = 0

    def beforeEditing(self):
        self.update_list()
        self.wStatus1.value = "Click 'Enter' for selected file options, " + \
                              "Click 'l' for searching, Ctrl+X for exiting\n\n"
        self.wStatus1.display()

    def update_list(self):
        self.wMain.values = list_all_usr_files()
        if self.wMain.values == []:
            self.wMain.values = ["You have no files, upload some or ask someone to share their secrets with you"]
        self.wMain.display()


class FileDiff(npyscreen.MultiLine):

    def __init__(self, *args, **keywords):
        super(FileDiff, self).__init__(*args, **keywords)
        self.add_handlers({
            "^X": self.exit
        })
    def display_value(self, vl):
        return "%s" % vl

    def exit(self, keypress):
        self.parent.parentApp.switchForm("List")


class FileDiffDisplay(npyscreen.FormMutt):
    MAIN_WIDGET_CLASS = FileDiff
    STATUS_WIDGET_CLASS = npyscreen.wgtextbox.Textfield
    STATUS_WIDGET_X_OFFSET = 0
    fp = ""
    fp2 = ""
    values = None

    def beforeEditing(self):
        self.update_list()
        self.wStatus1.value = "Diff %s ----- %s, Press ^X to exit" % (self.fp, self.fp2)
        self.wStatus1.display()

    def update_list(self):
        self.wMain.color = 'FORMDEFAULT'
        self.wMain.values = self.values
        self.wMain.display()


class UserList(npyscreen.MultiLine):

    def display_value(self, vl):
        return "%s" % vl

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.t1.value = act_on_this


class ShareUserList(npyscreen.SelectOne):

    def display_value(self, vl):
        if vl == '@@@':
            return "Favourite Users:\n"
        elif vl == '@@@@@':
            return "Other Users\n:"
        return "%s" % vl


class GetKeyAndFile(npyscreen.ActionPopup):

    def create(self):
        self.filename = self.add(npyscreen.TitleText, name="Filename", editable=False)
        self.fp = self.add(npyscreen.TitleFilenameCombo, name="Enter Private Key location:")
        self.fp2 = self.add(npyscreen.TitleFilenameCombo, name="Enter location of File to compare:")

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        if re.match(r'^Private_key_', self.fp.value.split('/')[-1]):
            fp = self.fp.value
            fp2 = self.fp2.value
            filename = self.filename.value
            npyscreen.notify("Loading")
            global LogUser
            diff = client.diff(LogUser, filename, fp, fp2)
            values = []
            try:
                while 1:
                    values.append(diff.next())
            except:
                pass
            self.parentApp.getForm("FileDiffDisplay").values = values
            self.parentApp.switchForm("FileDiffDisplay")
        else:
            npyscreen.notify_wait('Invalid Private key location/format (Private_key_<username>)')


class Unshare(npyscreen.ActionForm):
    def create(self):
        self.filename = self.add(npyscreen.TitleText, name="Filename", editable=False)
        self.t1 = self.add(npyscreen.TitleText, name="Unshare with:", editable=False)
        self.list = self.add(npyscreen.SelectOne, scroll_exit=True)
        self.shared = None

    def beforeEditing(self):
        self.list.values = self.shared

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        v = self.list.get_selected_objects()[0]
        if v != None or v != []:
            filename = self.filename.value
            global LogUser
            client.unshare(LogUser, filename, v)
            npyscreen.notify_wait("Un-Share Successful", form_color="VERYGOOD")
            self.parentApp.switchForm("List")


class Share(npyscreen.ActionForm):
    def create(self):
        self.filename = self.add(npyscreen.TitleText, name="Filename", editable=False)
        self.permission = self.add(npyscreen.TitleText, use_two_lines=False,
                                   begin_entry_at=22, name="Permission to Share:",)
        self.t = self.add(npyscreen.TitleText, name ="Select a User", editable=False)
        self.t1 = self.add(npyscreen.TitleText, name ="Favourites:", editable=False)

        self.ws = self.add(ShareUserList, max_height=5,
                              values=[],
                              scroll_exit=True, width=30)
        self.t2 = self.add(npyscreen.TitleText, name ="Other Users:", editable=False)

        self.ws1 = self.add(ShareUserList, values=[],
                              scroll_exit=True, width=30)
        self.shared = None

    def beforeEditing(self):
        global LogUser
        filename = self.filename.value
        l = client.getShareUsers(LogUser, filename)
        fav = [x for x in l[:l.index('@@@@@')] if x not in self.shared]
        fav = l[:l.index('@@@@@')]
        rest = [x for x in l[l.index('@@@@@')+1:] if x not in self.shared]
        if fav == []:
            self.ws.hidden = True
            self.ws.max_height = 0
        else:
            self.ws.max_height = len(fav)
            self.ws.hidden = False
            self.ws.values = fav
        if rest == []:
            self.ws1.hidden = True
        else:
            self.ws1.hidden = False
            self.ws1.values = rest
            #self.ws1.hidden = False
        #self.ws1.values = rest
        self.ws1.value = None
        self.ws.value = None
        self.permission.value = "Y"

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        self.t1.value = self.ws.get_selected_objects()
        self.t2.value = self.ws1.get_selected_objects()
        if self.permission.value == "Y" or self.permission.value == "N":
            global LogUser
            if self.ws1.get_selected_objects() not in [[], None, ""] and self.ws.get_selected_objects() not in [[], None, ""]:
                npyscreen.notify_wait("We're sorry, at the moment you can only share files with users one by one",
                        title='Work In Progress', form_color='CRITICAL')
            elif self.ws1.get_selected_objects() != []:
                usr = self.ws1.get_selected_objects()[0]
                filename = self.filename.value
                client.shareFile(LogUser, filename, usr, self.permission.value)
            elif self.ws.get_selected_objects() != []:
                usr = self.ws.get_selected_objects()[0]
                filename = self.filename.value
                client.shareFile(LogUser, filename, usr, self.permission.value)
            npyscreen.notify_wait("Share Successful", form_color="VERYGOOD")
            self.parentApp.switchForm("List")
        else:
            npyscreen.notify_wait("INVALID Share Permission, use 'Y' or 'N'", title='Failure',
                                  form_color='CRITICAL')


class WhoIsShared(npyscreen.ActionForm):
    def create(self):
        self.filename = self.add(npyscreen.TitleText, name="Filename")
        self.ws = self.add(npyscreen.SelectOne, max_height=2,
                              name='Options:',
                              values=['Share', 'Unshare'],
                              scroll_exit=True, width=20)
        self.t1 = self.add(npyscreen.TitleFixedText, name="Shared With:",
                            editable=False)
        self.list = self.add(UserList, editable=False)

    def beforeEditing(self):
        global LogUser
        self.list.values = [] +client.getSharedWith(LogUser, self.filename.value)

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        v = self.ws.get_selected_objects()[0]
        filename = self.filename.value
        if v == 'Share':
            self.parentApp.getForm("Share").filename.value = \
                filename
            self.parentApp.getForm("Share").shared = \
                self.list.values
            self.parentApp.switchForm("Share")
        if v == 'Unshare':
            self.parentApp.getForm("Unshare").filename.value = \
                filename
            self.parentApp.getForm("Unshare").shared = \
                self.list.values
            self.parentApp.switchForm("Unshare")


class Options(npyscreen.ActionPopup):
    def create(self):
        self.filename = self.add(npyscreen.TitleText, name="Filename")
        self.chose = self.add(npyscreen.SelectOne, max_height=4,
                              name='Options:',
                              values=['Download', 'Share', 'Delete', 'Diff'],
                              scroll_exit=True, width=20)

    def beforeEditing(self):
        self.chose.value = -1

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        v = self.chose.get_selected_objects()[0]
        filename = self.filename.value
        if v == "Download":
            self.parentApp.getForm("Download").filename.value = \
                self.filename.value
            self.parentApp.switchForm("Download")
        elif v == "Delete":
            # DELETE FROM DB
            confirm = npyscreen.notify_yes_no(
                "Are you sure you want to delete file %s?" % filename,
                title="Confimation", form_color='STANDOUT',
                wrap=True, editw=1)
            if confirm:
                global LogUser
                client.removeFile(LogUser, filename)
                self.parentApp.getForm("List").update_list()
                self.parentApp.switchForm("List")
        elif v == "Share":
            global LogUser
            if client.getPermission(LogUser, filename):
                self.parentApp.getForm("WhoIsShared").filename.value = \
                    self.filename.value
                self.parentApp.switchForm("WhoIsShared")
            else:
                npyscreen.notify_wait("You have no Permission to Share the File", title='Failure',
                                  form_color='CRITICAL')
        elif v == "Diff":
            self.parentApp.getForm("Get").filename.value = \
                self.filename.value
            self.parentApp.switchForm("Get")


class Upload(npyscreen.ActionForm):
    def create(self):
        self.file = self.add(npyscreen.TitleFilenameCombo,
                             name="File to Upload: (enter for path)")

    def beforeEditing(self):
        self.file.value = ''

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        fp = self.file.value
        if os.path.isdir(fp):
            npyscreen.notify_wait(
                "We're sorry, you can't upload folders - Yet :)",
                title='Work In Progress', form_color='CRITICAL')
        else:
            global LogUser
            client.upload(fp, LogUser)
            npyscreen.notify_wait("Upload successful", title="Upload",
                                              form_color="VERYGOOD")
            self.parentApp.switchFormPrevious()


class Download(npyscreen.ActionPopup):
    def create(self):
        self.filename = self.add(npyscreen.TitleText, name="Filename")
        self.wgDestination = self.add(npyscreen.TitleFilename,
                                      name="Download Destination: (auto-complete works [TAB])")
        self.wgPrivDest = self.add(npyscreen.TitleFilenameCombo,
                                   name="Private Key Location:")

    def beforeEditing(self):
        self.wgDestination.value = ''
        self.wgPrivDest.value = ''

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        filename = self.filename.value
        destination = self.wgDestination.value
        privpath = self.wgPrivDest.value
        global LogUser
        client.download(filename, destination, privpath, LogUser)
        npyscreen.notify_wait("Download Successful", title="Download",
                              form_color="VERYGOOD")
        self.parentApp.switchForm("List")


class Logged(npyscreen.ActionForm):
    def create(self):
        self.ms = self.add(npyscreen.TitleFixedText, name="Select Action:",
                           value="", editable=False)
        self.ms2 = self.add(npyscreen.SelectOne, max_height=3, name='Options:',
                            values=['List my Files', 'Upload'],
                            scroll_exit=True, width=20)

        self.CANCEL_BUTTON_TEXT = 'Logout'

    def logout(self):
        self.parentApp.switchForm("MAIN")
        global LogUser
        client.logOut(LogUser)
        LogUser = None

    def beforeEditing(self):
        self.ms2.value = -1

    def on_cancel(self):
        self.logout()

    def on_ok(self):
        if self.ms2.value:
            v = self.ms2.get_selected_objects()[0]
            if v == 'List my Files':
                self.parentApp.switchForm("List")
            elif v == 'Upload':
                self.parentApp.switchForm("Upload")


class LogIn(npyscreen.ActionPopup):
    def create(self):
        self.wgUsername = self.add(npyscreen.TitleText, use_two_lines=False,
                                   begin_entry_at=22, name="Your Name:",)
        self.bi = self.add(npyscreen.TitleText, use_two_lines=False,
                                    begin_entry_at=22, name="Username: ",)
        self.wgPass1 = self.add(npyscreen.TitlePassword,
                                use_two_lines=False, begin_entry_at=22,
                                name="Password: ",)
        self.text = self.add(npyscreen.FixedText, value="", hidden=True,
                             editable=False, color="CRITICAL")

        self.pin = self.add(npyscreen.TitlePassword, value = "", use_two_lines=False
                            , begin_entry_at=22, name="PIN: ", editable=False)


    def beforeEditing(self):
        self.name = "New User"
        # Give CC Username
        card = Smartcard.Smartcard(self.pin.value)
        if Smartcard.isSmartCardAvailable():
            self.wgUsername.value, self.bi.value = client.readCC(card)
            self.bi.editable = False
        else:
            self.bi.value = ''
            self.bi.editable = True
            self.wgUsername.hidden = True
            self.pin.hidden = True
        self.wgUsername.editable = False
        self.wgPass1.value = ''

    def on_cancel(self):
        self.text.value = ''
        self.text.hidden = True
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        pw = self.wgPass1.value
        global LogUser
        card = Smartcard.Smartcard(self.pin.value)
        LogUser = client.logInUser(self.bi.value, pw, card)
        if LogUser is not False:
            npyscreen.notify_wait("Valid Login", title='Sucess',
                                  form_color='VERYGOOD')
            self.parentApp.switchForm("Logged")
        else:
            self.text.value = "TRY AGAIN THE LOGIN"
            self.text.hidden = False
            npyscreen.notify_wait("INVALID LOGIN", title='Failure',
                                  form_color='CRITICAL')


class MainWindow(npyscreen.ActionFormWithMenus):
    def create(self):
        self.ms = self.add(npyscreen.TitleFixedText, name="Select Action:",
                           value="\n", editable=False)

        self.ms2 = self.add(npyscreen.SelectOne, max_height=3, name='Options:',
                            values=['Log In', 'Register', 'Info (uc)'],
                            scroll_exit=True, width=20)
        self.CANCEL_BUTTON_TEXT = 'Exit'

    def beforeEditing(self):
        self.ms2.value = -1

    def on_ok(self):
        # Verify Smart Card Available
        if self.ms2.value:
            v = self.ms2.get_selected_objects()[0]
            if v == 'Register':
                if client.askForRegist():
                    if Smartcard.isSmartCardAvailable():
                        self.parentApp.getForm("PIN").destination = "Register"
                        self.parentApp.switchForm("PIN")
                    else:
                        npyscreen.notify_wait("You have no Smartcard connected",
                                  title="Failure", form_color="WARNING")
                else:
                    print "ERROR MESSAGE"
            elif v == 'Log In':
                if client.askForLogIn():
                    if Smartcard.isSmartCardAvailable():
                        self.parentApp.getForm("PIN").destination = "Log In"
                        self.parentApp.switchForm("PIN")
                    else:
                        self.parentApp.switchForm("Log In")
                else:
                    print "ERROR MESSAGE"
            else:
                npyscreen.notify_wait(
                    "Project Safebox - Security UA\n\n-> José Sequeira 64645\n"
                    + "-> Vasco Santos 64191", title='Project Info',
                    form_color='CRITICAL')

    def on_cancel(self):
        confirm = npyscreen.notify_yes_no(
            "Are you sure you want to exit?", title="Confimation",
            form_color='STANDOUT', wrap=True, editw=1)

        if confirm:
            self.parentApp.switchForm(None)
        else:
            self.parentApp.switchFormPrevious()


class Pin(npyscreen.ActionForm):
    def create(self):
        self.destination = ""
        self.txt = self.add(npyscreen.Textfield, editable=False)
        self.pin = self.add(npyscreen.TitlePassword, use_two_lines= False,
                            begin_entry_at=22, name="Insert Pin: ")

    def beforeEditing(self):
        self.txt.value = self.destination
        self.pin.value = ""

    def on_ok(self):
        if len(self.pin.value) == 4 and self.pin.value.isdigit():
            if not Smartcard.pinCorrect(self.pin.value):
                npyscreen.notify_wait("WRONG PIN")
            else:
                self.parentApp.getForm(self.destination).pin.value = self.pin.value
                self.parentApp.switchForm(self.destination)
        else:
            npyscreen.notify_wait("WRONG PIN FORMAT")

    def on_cancel(self):
        self.parentApp.switchFormPrevious()



class Register(npyscreen.ActionForm):

    def create(self):
        self.value = None
        self.wgUsername = self.add(npyscreen.TitleText, use_two_lines=False,
                                   begin_entry_at=22, name="Your name:",)
        self.bi = self.add(npyscreen.TitleText, use_two_lines=False,
                                    begin_entry_at=22, name="Username: ",)
        self.wgPass1 = self.add(npyscreen.TitlePassword,
                                use_two_lines=False, begin_entry_at=22,
                                name="Password: ",)
        self.wgPass2 = self.add(npyscreen.TitlePassword,
                                begin_entry_at=22, use_two_lines=False,
                                name="Re-type Password:",)
        self.mail = self.add(npyscreen.TitleText, begin_entry_at=22,
                             use_two_lines=False, name="Your e-mail Adress:",)

        self.pin = self.add(npyscreen.TitlePassword, value='pin', use_two_lines=False
                            , begin_entry_at=22, name="PIN: ", editable=False)

        #self.BI = ""

    def beforeEditing(self):
        self.name = "New User"
        # Get CC Username
        card = Smartcard.Smartcard(self.pin.value)
        if Smartcard.isSmartCardAvailable():
            self.wgUsername.value, self.bi.value = client.readCC(card)
        else:
            self.bi.value = ''
            self.bi.editable = True
            self.wgUsername.hidden = True
            self.pin.hidden = True
        self.wgUsername.editable = False
        self.wgPass1.value = ''
        self.wgPass2.value = ''
        self.mail.value = ''

    def on_cancel(self):
        self.parentApp.switchFormPrevious()

    def on_ok(self):
        if self.wgPass1.value is '' or self.wgPass2.value is '' or\
           self.wgUsername is '':
            npyscreen.notify_wait("Please correctly fill in all fields",
                                  title='Error', form_color='WARNING')
        card = Smartcard.Smartcard(self.pin.value)

        if self.wgPass2.value != self.wgPass1.value:
            npyscreen.notify_wait("Not the same password",
                                  title='Password Error',
                                  form_color='WARNING')
        elif excludeFromDict(self.wgPass1.value) or len(self.wgPass1.value) < 5:
            npyscreen.notify_wait("Weak Password. You can do better. We believe in you")
        elif client.registUser(self.bi.value, self.wgPass1.value, self.mail.value, card):
            npyscreen.notify_wait("Register for user %s successful\nPrivate Key stored in PrivateKeys/Private_key_<username>" % self.wgUsername.value,
                                  title="Success", form_color="VERYGOOD")
            self.parentApp.switchForm("MAIN")
        else:
            npyscreen.notify_wait("There was a problem with your regist",
                                  title="Failure", form_color="WARNING")


def list_all_usr_files():
        global LogUser
        l = client.fileList(LogUser)
        return [x for x in l]


class SafeboxApplication(npyscreen.NPSAppManaged):
    def onStart(self):
        npyscreen.setTheme(npyscreen.Themes.ColorfulTheme)
        self.addForm("MAIN", MainWindow)
        self.addForm("Register", Register)
        self.addForm("Log In", LogIn)
        self.addForm("Logged", Logged)
        self.addForm("List", FileListDisplay)
        self.addForm("Download", Download)
        self.addForm("Options", Options)
        self.addForm("Upload", Upload)
        self.addForm("WhoIsShared", WhoIsShared)
        self.addForm("Share", Share)
        self.addForm("Unshare", Unshare)
        self.addForm("FileDiffDisplay", FileDiffDisplay)
        self.addForm("Get", GetKeyAndFile)
        self.addForm("PIN", Pin)

if __name__ == '__main__':
    myApp = SafeboxApplication()
    myApp.run()