# pylint: disable=W0601,W0201,C
import sys
import sqlite3
import hashlib
import os
import socket
import threading
import rsa
import pickle
import multiprocessing
import ast
import base64

from datetime import datetime
from cryptography.fernet import Fernet
from time import sleep, time
from PyQt5.QtWidgets import QMainWindow, QApplication, QListWidgetItem, QWidget, QPlainTextEdit, QPushButton, QFileDialog
from PyQt5 import QtCore, QtWidgets
from login_window import Ui_LoginWindow as login_window
from main_window import Ui_MainWindow as main_window

#The RSACrypt class provides in a simple interface the methods to encrypt or decrypt messages using the RSA algorithm
class RSACrypt():
    def __init__(self):
        #The key generation process can take a while, taking advantage of multiple cores in the system will speed it up
        self.number_of_cpu_cores = multiprocessing.cpu_count()
        self.public_key , self.__private_key = None, None

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.__private_key

    #Updates private and public key of this user
    def update_keys(self, public_key, private_key):
        self.public_key , self.__private_key = public_key, private_key

    #Generates a new pair of public and private keys
    def generate_new_keys(self):
        self.public_key , self.__private_key = rsa.newkeys(4096, poolsize=self.number_of_cpu_cores)
        return self.public_key , self.__private_key

    #Encrypts message using public key of receiever
    def encrypt_message(self, key, pub_key):
        encrypted_key = rsa.encrypt(key, pub_key)
        return encrypted_key

    #Decrypts message using this user's private key
    def decrypt_message(self, encrypted_message):
        decrypted_message_bytes = rsa.decrypt(encrypted_message, self.__private_key)
        decrypted_message = decrypted_message_bytes.decode("utf8")
        return decrypted_message

#This class implements the functionality of a stack
class Stack():
    def __init__(self):
        self.items = []

    def push(self, item):
        self.items.append(item)

    def pop(self):
        #Returns and removes last item from list
        return self.items.pop()

    def is_empty(self):
        # "not list" returns true for an empty list, false otherwise
        return not self.items

    def peek(self):
        return self.items[-1]

#Base class for objects to be sent over the network
class NetworkObject():
    def __init__(self):
        #Data is stored only in encrypted form in this class
        self._encrypted_username = None
        self._encrypted_data = None
        self._encrypted_rsa_signature = None
        self._encrypted_AES_key = None
        self._fernet_key = None

    def _encrypt_data(self, data: bytes, user: str):
        self._encrypted_data = CONTROLLER.get_fernet_key(user)[0].encrypt(data)

    def _encrypt_AES_key(self, key: bytes, public_key: bytes):
        self._encrypted_AES_key = CONTROLLER.RSA_ENCRYPTION.encrypt_message(key, public_key)

    def _encrypt_username(self, user: str):
        self._encrypted_username = CONTROLLER.get_fernet_key(user)[0].encrypt(bytes(CONTROLLER.username, encoding="utf-8"))

    def store_encrypted_rsa_signature(self, data, user: str):
        self._encrypted_rsa_signature = CONTROLLER.get_fernet_key(user)[0].encrypt(rsa.sign(data, CONTROLLER.RSA_ENCRYPTION.get_private_key(), "SHA-256"))

    def get_data(self):
        decrypted_AES_key = CONTROLLER.RSA_ENCRYPTION.decrypt_message(self._encrypted_AES_key)
        self._fernet_key = Fernet(decrypted_AES_key)
        return self._fernet_key.decrypt(self._encrypted_data)

    def get_username(self):
        return self._fernet_key.decrypt(self._encrypted_username).decode(encoding="utf-8")

    def get_signature(self):
        return self._fernet_key.decrypt(self._encrypted_rsa_signature)

#Message class stores the encrypted message to be sent over the network
class MessageObject(NetworkObject):
    def __init__(self, data: str, public_key, user: str):
        super(MessageObject, self).__init__()
        self._encrypt_data(bytes(data, encoding="utf-8"), user)
        self._encrypt_AES_key(CONTROLLER.get_fernet_key(user)[1], public_key)
        self._encrypt_username(user)
        self.store_encrypted_rsa_signature(data.encode(encoding="utf-8"), user)

#File class stores the encrypted contents and name of a file to be sent over the network
class FileObject(NetworkObject):
    def __init__(self, filename: str, public_key, user: str):
        super(FileObject, self).__init__()
        self.__encrypted_filename = None
        self._encrypt_AES_key(CONTROLLER.get_fernet_key(user)[1], public_key)
        self._encrypt_data(self.__get_file_contents(filename), user)
        self._encrypt_username(user)
        self.__encrypt_filename(filename, user)
        self.store_encrypted_rsa_signature(self.__get_file_contents(filename), user)

    def __encrypt_filename(self, filename, user):
        filename = os.path.split(filename)[1]
        self.__encrypted_filename = CONTROLLER.get_fernet_key(user)[0].encrypt(bytes(filename, encoding="utf-8"))

    def __get_file_contents(self, filename):
        with open(filename, "rb") as file_object:
            file_contents = file_object.read()

        return file_contents

    def get_filename(self):
        return self._fernet_key.decrypt(self.__encrypted_filename).decode(encoding="utf-8")

#Class for login window
class LoginWindow(QMainWindow, login_window):

    def __init__(self):
        super(LoginWindow, self).__init__()

        #Initialises the GUI
        self.setupUi(self)
        self.show()

        #On click of these buttons, the function named as a parameter is executed
        self.LoginButton.clicked.connect(self.login)
        self.RegisterButton.clicked.connect(self.register)
        self.actionExit.triggered.connect(exit_program)
        self.actionDark_Mode.triggered.connect(self.enable_dark_mode)
        self.actionLight_Mode.triggered.connect(self.enable_light_mode)

    #This function checks if the username and password entered are suitable
    def input_checks(self, username: str, password: str) -> bool:
        #List of characters not allowed in username
        illegal_characters = [" ", ",", "\"", "\'", "\\", "/"]

        #Returns true when an illegal character was detected
        iterable = [True for x in illegal_characters if x in username]

        if username == "" or password == "":
            #Updating message box in the GUI
            self.InformationLabel.setText("Values must be entered for both fields")
            self.InformationLabel.setStyleSheet('color: red')
            return True

        #If any illegal characters are in the username, then this will return True, else False
        if any(iterable):
            self.InformationLabel.setText("Illegal characters in username. No spaces, commas, slashes or speech marks are permitted")
            self.InformationLabel.setStyleSheet('color: red')
            return True

        return False

    #Executed when login button pressed
    def login(self):

        #User entered values are stored to the variables username and password
        username = self.UsernameLine.text()
        password = self.PasswordLine.text()

        #Evaluates to True when input check fails
        if self.input_checks(username, password):
            return

        #Establishing a connection with the database in the file "User-details.db"
        connection = sqlite3.connect("User-details.db")
        cursor = connection.cursor()

        if not table_exists(cursor, "Users"):
            #Updating message box in the GUI
            self.InformationLabel.setText("Database file missing or empty. Make a new account.")
            self.InformationLabel.setStyleSheet('color: red')
            connection.close()
            return

        #SQL query to retrieve the salted-hashed password and the salt used
        cursor.execute("""SELECT PasswordHash, Salt
                        FROM Users
                        WHERE Username=?""", (username,))

        #Retrieving results from the query just executed
        payload = cursor.fetchone()

        if payload is None:
            #Updating message box in the GUI
            self.InformationLabel.setText("Incorrect Username")
            self.InformationLabel.setStyleSheet('color: red')
            connection.close()
            return

        password_hash, salt = payload[0], payload[1]

        #hashing the password with the retrieved salt using the method hash_password
        hashed_password = hash_password(password, salt)[0]

        #Comparing newly hashed password to the existing hashed password in the database
        if password_hash == hashed_password:
            #Updating message box in the GUI
            self.InformationLabel.setText("Login successful")
            self.InformationLabel.setStyleSheet('color: green')
            self.InformationLabel.repaint()

        else:
            #Updating message box in the GUI
            self.InformationLabel.setText("Incorrect password")
            self.InformationLabel.setStyleSheet('color: red')
            self.PasswordLine.setText("")
            connection.close()
            return

        connection.close()
        self.username = username
        self.password = password
        CONTROLLER.main_window()

    #Executed when register button pressed
    def register(self):
        username = self.UsernameLine.text()
        password = self.PasswordLine.text()

        if self.input_checks(username, password):
            return

        connection = sqlite3.connect("User-details.db")
        cursor = connection.cursor()

        if not table_exists(cursor, "Users"):
            #Tables doesn't exist so we recreate it
            create_database(cursor)

        else:
            #Checking if the username is already in use by someone else
            cursor.execute("""SELECT Username
                            FROM Users
                            WHERE Username=?""", (username,))
            payload = cursor.fetchone()

            #If the username already exists, then payload will have a value
            if payload is not None:
                self.InformationLabel.setText("Username already exists, try a different one")
                self.InformationLabel.setStyleSheet('color: red')
                connection.close()
                return

        hashed_password, salt = hash_password(password)

        cursor.execute("""INSERT INTO Users (Username, PasswordHash, Salt)
                        VALUES (?,?,?)""", (username, hashed_password, salt))

        connection.commit()
        connection.close()
        #Updating message box in the GUI
        self.InformationLabel.setText("Registration complete!")
        self.InformationLabel.setStyleSheet('color: green')

    #Executed when dark mode button pressed
    #Updates stylesheets of GUI objects
    def enable_dark_mode(self):
        self.centralwidget.setStyleSheet("background: '#212121'")
        self.menubar.setStyleSheet("QMenuBar {"
                                   "color: white;"
                                   "background: #363636"
                                   "}"

                                   "QMenuBar:selected {"
                                   "color: white"
                                   "}"

                                   "QMenuBar::item::selected {"
                                   "background-color: #424242;"
                                   "}")
        self.menuOptions.setStyleSheet("QMenu {"
                                       "background: #525252;"
                                       "color: white"
                                       "}"

                                       "QMenu:selected {"
                                       "background: #636363;"
                                       "}")
        self.PasswordLabel.setStyleSheet("color: '#ccc'")
        self.UsernameLabel.setStyleSheet("color: '#ccc'")
        self.PasswordLine.setStyleSheet("QLineEdit {"
                                        "color: '#ccc';"
                                        "background: '#1a1a1a'"
                                        "}"
                                        
                                        "QLineEdit:focus {"
                                        "border: 1px solid red;"
                                        "}")
        self.UsernameLine.setStyleSheet("QLineEdit {"
                                        "color: '#ccc';"
                                        "background: '#1a1a1a'"
                                        "}"
                                        
                                        "QLineEdit:focus {"
                                        "border: 1px solid red;"
                                        "}")
        self.LoginButton.setStyleSheet("QPushButton {"
                                       "color: #CCC;"
                                       "background: #1a92c9;"
                                       "border: 1px solid #1a92c9;"
                                       "border-radius: 10px"
                                       "}"

                                       "QPushButton:hover {"
                                       "border: 1px solid red"
                                       "}")
        self.RegisterButton.setStyleSheet("QPushButton {"
                                          "color: #CCC;"
                                          "background: #1a92c9;"
                                          "border: 1px solid #1a92c9;"
                                          "border-radius: 10px"
                                          "}"

                                          "QPushButton:hover {"
                                          "border: 1px solid red"
                                          "}")

    #Executed when light mode button pressed
    #Updates stylesheets of GUI objects
    def enable_light_mode(self):
        self.centralwidget.setStyleSheet("background: #F0F0F0")
        self.menubar.setStyleSheet("QMenuBar {"
                                   "color: black;"
                                   "background: white"
                                   "}")
        self.menuOptions.setStyleSheet("QMenu {"
                                       "background: white;"
                                       "color: black"
                                       "}"

                                       "QMenu:selected {"
                                       "background: #90C8F6;"
                                       "}")
        self.PasswordLabel.setStyleSheet("color: 'black'")
        self.UsernameLabel.setStyleSheet("color: 'black'")
        self.PasswordLine.setStyleSheet("color: #7A7A7A; background: white")
        self.UsernameLine.setStyleSheet("color: #7A7A7A; background: white")
        self.LoginButton.setStyleSheet("QPushButton {"
                                       "color: 'black';"
                                       "background: #E1E1E1;"
                                       "border: 1px solid #ADADAD;"
                                       "border-radius: 10px"
                                       "}"

                                       "QPushButton:hover {"
                                       "border-color: blue"
                                       "}")
        self.RegisterButton.setStyleSheet("QPushButton {"
                                          "color: 'black';"
                                          "background: #E1E1E1;"
                                          "border: 1px solid #ADADAD;"
                                          "border-radius: 10px"
                                          "}"

                                          "QPushButton:hover {"
                                          "border-color: blue"
                                          "}")

#Class for main window
class MainWindow(QMainWindow, main_window):
    create_a_tab = QtCore.pyqtSignal(str)
    save_file = QtCore.pyqtSignal(bytes, QtWidgets.QTextEdit)
    def __init__(self):
        super(MainWindow, self).__init__()

        #Initialises the GUI
        self.setupUi(self)
        self.show()

        #On click of these buttons, the function named as a parameter is executed
        self.actionExit.triggered.connect(exit_program)
        self.listWidget.itemDoubleClicked.connect(self.item_changed)

        self.create_a_tab.connect(self.create_tab)
        self.save_file.connect(self.save_file_dialog)

        #This dictionary is used to keep track of dynamically generated objects
        self.tabs = {}

        #Pressing pg up or dn will retrieve messages sent, similar to the way command history works in terminals
        self.stack_up = Stack()
        self.stack_down = Stack()

    #This function manages the up and down message history stack
    #You go up the history by pressing CTRL - PGUP, and CTRL - PGDN to go down
    def keyPressEvent(self, event):
        #CTRL- PG UP event
        if event.key() == 16777238:
            focus = QApplication.focusObject()
            if "QPlainTextEdit" in str(focus):
                if not self.stack_up.is_empty():
                    selected_user = self.tabWidget.tabText(self.tabWidget.currentIndex())
                    latest_message = self.stack_up.pop()
                    text_entry = self.tabs.get(selected_user)[1]
                    previous_message = text_entry.toPlainText()
                    self.stack_down.push(previous_message)
                    focus.setPlainText(latest_message)

        #CTRL - PG DOWN event
        elif event.key() == 16777239:
            focus = QApplication.focusObject()
            if "QPlainTextEdit" in str(focus):
                if not self.stack_down.is_empty():
                    latest_message = self.stack_down.pop()
                    selected_user = self.tabWidget.tabText(self.tabWidget.currentIndex())
                    text_entry = self.tabs.get(selected_user)[1]
                    previous_message = text_entry.toPlainText()
                    self.stack_up.push(previous_message)
                    focus.setPlainText(latest_message)

    #Function called when item is double clicked in list
    #Tab is changed to user clicked, unless they're already selected
    def item_changed(self, item):
        selected_user = item.text()
        tab_count = self.tabWidget.count()
        for x in range(tab_count):
            if self.tabWidget.tabText(x) == selected_user:
                if self.tabWidget.currentIndex != x:
                    self.tabWidget.setCurrentIndex(x)
                return

        self.create_tab(selected_user)

    #Creates a new tab for each new user
    #GUI generation
    def create_tab(self, selected_user):
        tab_count = self.tabWidget.count()
        tab_object_name = "object " + str(self.tabWidget.count())
        tab = QWidget()
        tab.setObjectName(tab_object_name)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(tab.sizePolicy().hasHeightForWidth())
        tab.setSizePolicy(sizePolicy)
        
        verticalLayout_4 = QtWidgets.QVBoxLayout(tab)
        verticalLayout_4.setObjectName("verticalLayout_4")

        message_box, vertlayout_2 = self.create_messagebox(tab)
        text_entry, horizlayout_2 = self.create_text_edit_box(tab)
        send_file_button = self.create_send_file_button(tab, horizlayout_2)
        enter_button = self.create_enter_button(tab, horizlayout_2)

        vertlayout_2.addLayout(horizlayout_2)
        verticalLayout_4.addLayout(vertlayout_2)

        send_file_button.clicked.connect(lambda: self.open_file_dialog(selected_user))
        enter_button.clicked.connect(lambda: self.message_entered(text_entry, selected_user))
        message_box.verticalScrollBar().rangeChanged.connect(lambda minimum, maximum: message_box.verticalScrollBar().setSliderPosition(maximum))

        self.tabWidget.addTab(tab, selected_user)
        self.tabWidget.setCurrentIndex(tab_count)

        #Saving dynamically generated object in a dictionary so we can access it later
        self.tabs[selected_user] = (message_box, text_entry)

        retrieve_messages(selected_user)

    #This created a message box where messages appear when sent or received
    def create_messagebox(self, tab):
        verticalLayout_2 = QtWidgets.QVBoxLayout()
        verticalLayout_2.setObjectName("verticalLayout_2")
        text_edit = QtWidgets.QTextEdit(tab)
        text_edit.setReadOnly(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(text_edit.sizePolicy().hasHeightForWidth())
        text_edit.setSizePolicy(sizePolicy)
        text_edit.setObjectName("text_edit")
        verticalLayout_2.addWidget(text_edit)
        return text_edit, verticalLayout_2

    #This creates a text edit box where you type messages to send
    def create_text_edit_box(self, tab):
        horizontalLayout_2 = QtWidgets.QHBoxLayout()
        horizontalLayout_2.setObjectName("horizontalLayout_2")
        plainTextEdit = QPlainTextEdit(tab)
        plainTextEdit.setStyleSheet("background-color: #707070; border-top-left-radius: 10px; border-bottom-left-radius: 10px; border-top-right-radius: 0px; border-bottom-right-radius: 0px")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(plainTextEdit.sizePolicy().hasHeightForWidth())
        plainTextEdit.setSizePolicy(sizePolicy)
        plainTextEdit.setMaximumSize(QtCore.QSize(16777215, 75))
        plainTextEdit.setObjectName("plainTextEdit")
        horizontalLayout_2.addWidget(plainTextEdit)
        return plainTextEdit, horizontalLayout_2

    def create_send_file_button(self, tab, horizontalLayout_2):
        pushButton = QPushButton(tab)
        pushButton.setStyleSheet("QPushButton {"
                                 "background-color: #990099;"
                                 "border-color: rgb(225, 85, 0);"
                                 "border-top-left-radius: 0px; border-bottom-left-radius: 0px; border-top-right-radius: 0px; border-bottom-right-radius: 0px;"
                                 "}"
        
                                 "QPushButton::hover {"
                                 "background-color: #890099;"
                                 "border-top-left-radius: 0px; border-bottom-left-radius: 0px; border-top-right-radius: 0px; border-bottom-right-radius: 0px;"
                                 "}")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(pushButton.sizePolicy().hasHeightForWidth())
        pushButton.setSizePolicy(sizePolicy)
        pushButton.setMaximumSize(QtCore.QSize(75, 75))
        pushButton.setObjectName("pushButton2")
        horizontalLayout_2.addWidget(pushButton)
        pushButton.setText("SEND \n FILE")
        return pushButton

    #This created an enter button that sends the message you type in the text edit box
    def create_enter_button(self, tab, horizontalLayout_2):
        pushButton = QPushButton(tab)
        pushButton.setStyleSheet("QPushButton {"
                                 "background-color: #00bf0a;"
                                 "border-color: rgb(225, 85, 0);"
                                 "border-top-left-radius: 0px; border-bottom-left-radius: 0px; border-top-right-radius: 10px; border-bottom-right-radius: 10px;"
                                 "}"
        
                                 "QPushButton::hover {"
                                 "background-color: #00a609;"
                                 "border-top-left-radius: 0px; border-bottom-left-radius: 0px; border-top-right-radius: 10px; border-bottom-right-radius: 10px;"
                                 "}")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(pushButton.sizePolicy().hasHeightForWidth())
        pushButton.setSizePolicy(sizePolicy)
        pushButton.setMaximumSize(QtCore.QSize(75, 75))
        pushButton.setObjectName("pushButton")
        horizontalLayout_2.addWidget(pushButton)
        pushButton.setText("SEND \n MESSAGE")
        return pushButton

    #This opens the file dialog where the user can select a file
    def open_file_dialog(self, selected_user):
        filename = QFileDialog.getOpenFileName(self)[0]
        if not filename:
            return

        send_file(selected_user, filename)

    #This opens the file dialog where the user can select a location to save the file
    def save_file_dialog(self, file_contents, message_box):
        save_file_name = QFileDialog.getSaveFileName(self)[0]
        if not save_file_name:
            message = f"<font color = #F00>File discarded</color>"
            message_box.append(message)
            return
        
        with open(save_file_name, "wb") as file_object:
            file_object.write(file_contents)

        message = f"<font color = #0F0>File saved</color>"
        message_box.append(message)

    #This function is run when a message is sent
    def message_entered(self, text_entry, selected_user):
        message = text_entry.toPlainText()
        text_entry.clear()

        #Handles putting messages in the stack
        if self.stack_up.is_empty() or self.stack_up.peek() != message:
            self.stack_up.push(message)

        send_message(selected_user, message)

#Controls several things, such as which windows appear when and when to start multiple threads
class WindowController():
    def __init__(self):
        self.login()

        #For every user you communicate with, new AES keys are generated and stores in AES_KEYS
        self.__AES_KEYS = {}

    #Generates AES key which is used to encrypt private key and then stored in the database
    def make_database_fernet_key(self):
        connection = sqlite3.connect("User-details.db")
        cursor = connection.cursor()
    
        cursor.execute("""SELECT RSASalt 
                FROM Users
                WHERE Username=?""",
                (CONTROLLER.username,))

        salt = cursor.fetchone()[0]
        AES_KEY = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", bytes(CONTROLLER.password, encoding="utf-8"), salt, 100000, dklen=32))
        self.fernet_database_key = Fernet(AES_KEY)

        connection.close()

    #Generates a new AES fernet key, returning the fernet object and key
    def make_message_fernet_key(self):
        AES_KEY = Fernet.generate_key()
        return Fernet(AES_KEY), AES_KEY

    #Returns the fernet key object and key for a specific user, generates new keys if not available
    def get_fernet_key(self, user):
        if user in self.__AES_KEYS:
            return self.__AES_KEYS.get(user)
        
        fernet_key, AES_KEY = self.make_message_fernet_key()
        self.__AES_KEYS[user] = fernet_key, AES_KEY 

        return fernet_key, AES_KEY

    def login(self):
        self.WINDOW1 = LoginWindow()

    def main_window(self):
        #Thread lock prevents multiple threads from accessing certain variables simultaneously
        self.clients_online = {}
        self.clients_online_lock = threading.Lock()
        self.database_lock = threading.Lock()

        self.dict_list_items = {}
        self.username = self.WINDOW1.username
        self.password = self.WINDOW1.password

        self.RSA_ENCRYPTION = RSACrypt()

        #Checks if keys are available in database and updates them in RSACrypt class, else generates new keys
        keys = check_rsa_keys_available()
        if keys is False:
            self.WINDOW1.InformationLabel.setText("Generating RSA keys...")
            self.WINDOW1.InformationLabel.setStyleSheet('color: blue')
            self.WINDOW1.InformationLabel.repaint()
            public_key, __private_key = self.RSA_ENCRYPTION.generate_new_keys()
            save_rsa_keys(public_key, __private_key)
            CONTROLLER.make_database_fernet_key()
        else:
            self.WINDOW1.InformationLabel.setText("Loading RSA keys...")
            self.WINDOW1.InformationLabel.setStyleSheet('color: blue')
            self.WINDOW1.InformationLabel.repaint()
            self.RSA_ENCRYPTION.update_keys(keys[0], keys[1])

        self.WINDOW1.close()

        #Opens a socket that's used to send and receive messages on a specified port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((socket.getfqdn(), 8000))

        #Runnings these functions in their own threads as they need to be running constantly and shouldn't be blocked by other code
        #These threads are "daemons", so when the main program thread is killed these threads will also be killed.
        #This makes sure no threads are left alive accidentally is the program is force closed.
        t1 = threading.Thread(target=broadcast_self, args=(self.username, sock), daemon=True)
        t2 = threading.Thread(target=detect_other_clients, args=(sock,), daemon=True)
        t3 = threading.Thread(target=remove_offline_clients, daemon=True)
        t4 = threading.Thread(target=receive_messages, daemon=True)
        t5 = threading.Thread(target=receive_files, daemon=True)

        self.WINDOW2 = MainWindow()

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()

#Creates the PairID for 2 users based on how many records exist
def create_pair_id(cursor, OtherParty):
    cursor.execute("""SELECT Count(*)
                    FROM CommunicationPairs""")
    PairID = cursor.fetchone()
    cursor.execute("""INSERT INTO CommunicationPairs (PairID, OtherParty, Username) 
                    VALUES (?,?,?)""", (PairID[0], OtherParty, CONTROLLER.username))

    return PairID

#Returns the PairID of 2 users
def get_pair_id(cursor, OtherParty):
    cursor.execute("""SELECT PairID
                    FROM CommunicationPairs
                    WHERE Username=?
                    AND OtherParty=?""", (CONTROLLER.username, OtherParty))

    PairID = cursor.fetchone()

    if PairID is None:
        PairID = create_pair_id(cursor, OtherParty)

    return PairID[0]

def create_database(cursor):
    cursor.execute("""CREATE TABLE Users
                (Username TEXT PRIMARY KEY,
                PasswordHash BLOB,
                Salt BLOB,
                Public_Key BLOB,
                Encrypted_Private_Key BLOB,
                RSASalt BLOB)""")

    cursor.execute("""CREATE TABLE CommunicationPairs
                (PairID INTEGER PRIMARY KEY,
                OtherParty TEXT,
                Username TEXT,
                FOREIGN KEY(Username) REFERENCES Users(Username))""")

    cursor.execute("""CREATE TABLE Messages
                (MessageID INTEGER PRIMARY KEY,
                PairID INTEGER,
                Date BLOB,
                Message BLOB,
                FOREIGN KEY(PairID) REFERENCES CommunicationPairs(PairID))""")

#Merge sort algorithm
def merge_sort(data: list) -> list:
    if len(data) == 1:
        return data

    middle = len(data) // 2
    left = data[:middle]
    right = data[middle:]

    if len(left) != 1:
        left = merge_sort(left)
    
    if len(right) != 1:
        right = merge_sort(right)

    new_order = []

    while len(left) > 0 and len(right) > 0:
        if left[0] < right[0]:
            new_order.append(left[0])
            left.remove(left[0])
        else:
            new_order.append(right[0])
            right.remove(right[0])

    if len(left) == 0:
        new_order.extend(right)
    else:
        new_order.extend(left)
    return new_order

#This retrieves all the messages for a user pair from previous conversations saved to the database
def retrieve_messages(user: str) -> None:
    tab = CONTROLLER.WINDOW2.tabs
    message_box = tab.get(user)[0]

    CONTROLLER.database_lock.acquire()
    connection = sqlite3.connect("User-details.db")
    cursor = connection.cursor()

    cursor.execute("""SELECT Date, Message
                    FROM Messages, CommunicationPairs
                    WHERE Messages.PairID = CommunicationPairs.PairID
                    AND CommunicationPairs.Username=?
                    AND CommunicationPairs.OtherParty=?""", (CONTROLLER.username, user))

    time_message = []

    for payload in cursor.fetchall():
        date = payload[0]
        date = pickle.loads(date)
        message = payload[1]
        message = CONTROLLER.fernet_database_key.decrypt(message).decode(encoding="utf8")
        time_message.append([date, message])
        
    connection.close()
    CONTROLLER.database_lock.release()
    
    #No messages available
    if not time_message:
        return

    #Messages are sorted in ascending order based on their timestamps
    sorted_messages = merge_sort(time_message)

    for x in sorted_messages:
        message_box.append(x[1])

#Saves a message to the database
def save_message(message: str, OtherParty: str) -> None:
    CONTROLLER.database_lock.acquire()
    connection = sqlite3.connect("User-details.db")
    cursor = connection.cursor()

    date = datetime.now()
    date = pickle.dumps(date)

    encrypted_message = CONTROLLER.fernet_database_key.encrypt(bytes(message, encoding="utf8"))

    PairID = get_pair_id(cursor, OtherParty)

    cursor.execute("""SELECT Count(*)
                    FROM Messages""")

    MessageID = cursor.fetchall()[0][0]

    cursor.execute("""INSERT INTO Messages (MessageID, PairID, Date, Message)
                    VALUES (?,?,?,?)""", (MessageID, PairID, date, encrypted_message))

    connection.commit()
    connection.close()
    CONTROLLER.database_lock.release()

#Checks if a table exists in the database (No tables exist on a fresh install)
def table_exists(cursor: object, table_name: str) -> bool:
    cursor.execute("""SELECT name 
                    FROM sqlite_master 
                    WHERE type='table' 
                    AND name=?""", (table_name,))

    table = cursor.fetchone()

    if table is None:
        return False
    
    return True

#Executed when exit button pressed
def exit_program():
    sys.exit()

#Sends file objects over the network
def send_file(selected_user: str, filename: str):
    PORT = 8002
    MAGIC_PASS = b"IJ6d5J,"
    tab = CONTROLLER.WINDOW2.tabs
    message_box = tab.get(selected_user)[0]
    selected_user_ip = selected_user.split(" ")[-1]

    CONTROLLER.clients_online_lock.acquire()
    client = CONTROLLER.clients_online.get(selected_user_ip)
    CONTROLLER.clients_online_lock.release()

    if client[3] is False:
        message = "<font color = #F00>" + "File not sent: User offline" + "</color>"
        message_box.append(message)
        return

    PUBLIC_KEY = client[2]

    encrypted_message = MAGIC_PASS + pickle.dumps(FileObject(filename, PUBLIC_KEY, selected_user))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sending_socket:
        # Connect to server and send data
        sending_socket.settimeout(2)
        try:
            sending_socket.connect((selected_user_ip, PORT))
            length_of_data = str(len(encrypted_message)) + ":"
            data = bytes(length_of_data, encoding="utf-8") + encrypted_message
            sending_socket.sendall(data)
        except socket.timeout:
            message = "<font color = #F00>" + "File not sent: User offline" + "</color>"
            message_box.append(message)
            return

    message = f"<font color = #0F0>File sent successfully: {os.path.split(filename)[1]}</color>"
    message_box.append(message)

#Sends message objects over the network
def send_message(selected_user: str, message: str) -> None:
    PORT = 8001
    MAGIC_PASS = b"iJ9d2J,"
    tab = CONTROLLER.WINDOW2.tabs
    message_box = tab.get(selected_user)[0]
    selected_user_ip = selected_user.split(" ")[-1]

    CONTROLLER.clients_online_lock.acquire()
    client = CONTROLLER.clients_online.get(selected_user_ip)
    CONTROLLER.clients_online_lock.release()

    if client[3] is False:
        message = "<font color = #F00>" + "Message not sent: User offline" + "</color>"
        message_box.append(message)
        return

    PUBLIC_KEY = client[2]

    encrypted_message = MAGIC_PASS + pickle.dumps(MessageObject(message, PUBLIC_KEY, selected_user))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sending_socket:
        # Connect to server and send data
        sending_socket.settimeout(2)
        try:
            sending_socket.connect((selected_user_ip, PORT))
            length_of_data = str(len(encrypted_message)) + ":"
            data = bytes(length_of_data, encoding="utf-8") + encrypted_message
            sending_socket.sendall(data)
        except socket.timeout:
            message = "<font color = #F00>" + "Message not sent: User offline" + "</color>"
            message_box.append(message)
            return

    message = "<font color = #0F0>" + CONTROLLER.username + "</color>" + ": " + "<font color = 'white'>" + message + "</color>"
    message_box.append(message)
    save_message(message, selected_user)

#Receive file objects from the network
def receive_files():
    PORT = 8002
    MAGIC_PASS = b"IJ6d5J,"
    receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiving_socket.bind(("", PORT))
    receiving_socket.listen(5)

    while True:
        sender, address = receiving_socket.accept()

        with sender:
            #Incoming bytes from network stored in a byte array (good efficiency)
            incoming_data = bytearray()
            incoming_data.extend(sender.recv(4096))

            #Data sent over the network is formatted like such:
            #  data_langth:data
            while b":" not in incoming_data:
                incoming_data.extend(sender.recv(4096))

            index = incoming_data.index(b":")
            file_size = int(incoming_data[:index])
            incoming_data = incoming_data[index+1:]

            while len(incoming_data) != file_size:
                incoming_data.extend(sender.recv(4096))

            data = incoming_data

            #Making sure the message is meant for us
            if data.startswith(MAGIC_PASS):
                data = data.split(b",", maxsplit=1)[1]

                file_object = pickle.loads(data)
                file_contents = file_object.get_data()
                file_name = file_object.get_filename()
                username = file_object.get_username()
                signature = file_object.get_signature()

                selected_user = username + " " + address[0]

                CONTROLLER.clients_online_lock.acquire()
                user_pub_key = CONTROLLER.clients_online.get(address[0])[2]
                CONTROLLER.clients_online_lock.release()

                try:
                    rsa.verify(file_contents, signature, user_pub_key)
                except rsa.pkcs1.VerificationError:
                    print("Verification Failed")
                    continue

                message = f"<font color = #00F>File recieved: {file_name}</color>"

                tab = CONTROLLER.WINDOW2.tabs
                client = tab.get(selected_user)

                if client is None:
                    CONTROLLER.WINDOW2.selected_user_arg = selected_user
                    CONTROLLER.WINDOW2.create_a_tab.emit(selected_user)
                    #The tab variable is being modified in a different thread
                    #Sometimes it isn't updated fast enough so we get a None value
                    #Using a while loop here is safe as it's guaranteed that
                    #tab.get(selected-user) will eventually return a none None value
                    while client is None:
                        client = tab.get(selected_user)
                    message_box = client[0]
                else:
                    message_box = client[0]
                
                message_box.append(message)
                CONTROLLER.WINDOW2.save_file.emit(file_contents, message_box)

#Receive message objects from the network
def receive_messages():
    PORT = 8001
    MAGIC_PASS = b"iJ9d2J"
    receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiving_socket.bind(("", PORT))
    receiving_socket.listen(5)

    while True:
        sender, address = receiving_socket.accept()

        with sender:
            incoming_data = bytearray()
            incoming_data.extend(sender.recv(4096))

            while b":" not in incoming_data:
                incoming_data.extend(sender.recv(4096))

            index = incoming_data.index(b":")
            message_size = int(incoming_data[:index])
            incoming_data = incoming_data[index+1:]

            while len(incoming_data) != message_size:
                incoming_data.extend(sender.recv(4096))

            data = incoming_data

            #Making sure the message is meant for us
            if data.startswith(MAGIC_PASS):
                data = data.split(b",", maxsplit=1)[1]

                message_object = pickle.loads(data)
                message = message_object.get_data().decode(encoding="utf-8")
                username = message_object.get_username()
                signature = message_object.get_signature()

                selected_user = username + " " + address[0]

                CONTROLLER.clients_online_lock.acquire()
                user_pub_key = CONTROLLER.clients_online.get(address[0])[2]
                CONTROLLER.clients_online_lock.release()

                try:
                    rsa.verify(message.encode(encoding="utf-8"), signature, user_pub_key)
                except rsa.pkcs1.VerificationError:
                    print("Verification Failed")
                    continue

                message = "<font color = #0FF>" + username + ": " + "</color>" + "<font color = 'white'>" + message + "</color>"

                save_message(message, selected_user)

                tab = CONTROLLER.WINDOW2.tabs
                client = tab.get(selected_user)

                if client is None:
                    CONTROLLER.WINDOW2.selected_user_arg = selected_user
                    CONTROLLER.WINDOW2.create_a_tab.emit(selected_user)
                else:
                    message_box = client[0]
                    message_box.append(message)

#Function to hash password with supplied salt, or randomly generated one if not supplied
def hash_password(password: str, salt: bytes=None) -> bytes:
    password_bytes = bytes(password, encoding="utf-8")
    if salt is None:
        salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 200000)
    return hashed_password, salt

#This function announces itself on the local network to anyone listening on port 8000
#This allows us and other clients to see who's online.
def broadcast_self(username, sock):
    PORT = 8000
    USERNAME = username + ","

    #Other users on the network need this key to encrypt their messages and send them to you
    PUBLIC_KEY = CONTROLLER.RSA_ENCRYPTION.get_public_key()

    #The variable MAGIC_PASS is used so we don't accidentally get confused with other applications that are broadcasting on port 8000
    #When detecting broadcasts, we can check if the MAGIC_PASS value is at the beginning, so we know that the message is meant for us
    MAGIC_PASS = "GywBVeCg2Z,"
    #pickling python objects turns them into byte streams, allowing us to send them over the network
    MESSAGE = bytes(str(MAGIC_PASS + USERNAME) + str([pickle.dumps(PUBLIC_KEY)]), encoding="utf8")

    #Broadcast the message every 2 seconds
    while True:
        sock.sendto(MESSAGE, ('<broadcast>', PORT))
        sleep(0.2)

#This function detects broadcasts on port 8000 made by other instances of this program.
def detect_other_clients(sock):
    MAGIC_PASS = "GywBVeCg2Z"
    HOST_NAME = socket.gethostname()
    IP_ADDRESS = socket.gethostbyname(HOST_NAME)

    while True:
        data, addr = sock.recvfrom(4096)
        #Making sure the broadcast is meant for us, and we aren't just detecting our own broadcast
        if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")) and addr[0] != IP_ADDRESS:
            data = data.decode("utf-8").split(",", maxsplit=2)
            username = data[1]
            PUBLIC_KEY = pickle.loads(ast.literal_eval(data[2])[0])
            update_online_clients([addr[0], username, PUBLIC_KEY])

#Remove clients that haven't broadcasted in the last 1 second from our dictionary
def remove_offline_clients():
    while True:
        CONTROLLER.clients_online_lock.acquire()
        for key, value in CONTROLLER.clients_online.items():
            #If broadcast hasn't been received in the last second, this condition is true
            #The client is then removed from our dictionary
            if (time()-value[0]) > 1:
                value[3] = False
                CONTROLLER.clients_online[key] = value
                client_data = [key, value[1]]
                remove_client_from_online_list(client_data)

        number_of_clients_online = 0
        for item in CONTROLLER.clients_online.items():
            if item[1][3] == True:
                number_of_clients_online += 1

        CONTROLLER.WINDOW2.numberOfClientsLabel.setText(str(number_of_clients_online))
        CONTROLLER.clients_online_lock.release()
        sleep(0.1)

#Everytime a broadcast is detected, this function is run
#Existing clients will have the time stamp of their last broadcast updated
#New clients will be added to our dictionary
def update_online_clients(client_data):
    CONTROLLER.clients_online_lock.acquire()

    number_of_clients_online = 0
    for item in CONTROLLER.clients_online.items():
        if item[1][3] == True:
            number_of_clients_online += 1

    for key, value in CONTROLLER.clients_online.items():
        if key == client_data[0]:
            if value[3] == True:
                #Updating the timestamp and online status
                value[0] = time()
                CONTROLLER.clients_online[key] = value
                CONTROLLER.clients_online_lock.release()
                return
            
            value[0] = time()
            value[3] = True
            CONTROLLER.clients_online[key] = value
            add_client_to_online_list(client_data)
            CONTROLLER.WINDOW2.numberOfClientsLabel.setText(str(number_of_clients_online))
            CONTROLLER.clients_online_lock.release()
            return

    #Adding client to dictionary
    CONTROLLER.clients_online[client_data[0]] = [time(), client_data[1], client_data[2], True]
    add_client_to_online_list(client_data)
    number_of_clients_online += 1
    CONTROLLER.WINDOW2.numberOfClientsLabel.setText(str(number_of_clients_online))
    CONTROLLER.clients_online_lock.release()

#Updating the list users click on in the GUI
def remove_client_from_online_list(client_data):
    item = CONTROLLER.dict_list_items.get(client_data[1] + " " + client_data[0])
    CONTROLLER.WINDOW2.listWidget.takeItem(CONTROLLER.WINDOW2.listWidget.row(item))

def add_client_to_online_list(client_data):
    item = QListWidgetItem(client_data[1] + " " + str(client_data[0]))
    CONTROLLER.WINDOW2.listWidget.addItem(item)
    CONTROLLER.dict_list_items[client_data[1] + " " + client_data[0]] = item

#Return (PublicKey, PrivateKey) | (False)
def check_rsa_keys_available():
    connection = sqlite3.connect("User-details.db")
    cursor = connection.cursor()
    cursor.execute("""SELECT Public_Key, Encrypted_Private_Key 
                      FROM Users
                      WHERE Username=?""",
                      (CONTROLLER.username,))
    public_key, encrypted_private_key = cursor.fetchone()
    if public_key is None:
        return False
    CONTROLLER.make_database_fernet_key()
    private_key = decrypt_key(encrypted_private_key)
    public_key = pickle.loads(public_key)
    return public_key, private_key

#Decrypt keys
def decrypt_key(encrypted_private_key):
    private_key = pickle.loads(CONTROLLER.fernet_database_key.decrypt(encrypted_private_key))
    return private_key

#Encrypt keys
def encrypt_key(private_key):
    salt = os.urandom(16)
    AES_KEY = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", bytes(CONTROLLER.password, encoding="utf-8"), salt, 100000, dklen=32))
    f = Fernet(AES_KEY)
    bytes_priv_key = pickle.dumps(private_key)
    encrypted_private_key = f.encrypt(bytes_priv_key)
    return encrypted_private_key, salt

#Save keys to database
def save_rsa_keys(public_key, private_key):
    encrypted_private_key, salt = encrypt_key(private_key)
    bytes_pub_key = pickle.dumps(public_key)
    connection = sqlite3.connect("User-details.db")
    cursor = connection.cursor()
    cursor.execute("""UPDATE Users 
                    SET Public_Key=?, Encrypted_Private_Key=?, RSASalt=? 
                    WHERE Username=?""", (
                    bytes_pub_key, encrypted_private_key, salt, CONTROLLER.username))
    connection.commit()
    connection.close()

if __name__ == '__main__':
    APP = QApplication(sys.argv)
    CONTROLLER = WindowController()
    sys.exit(APP.exec_())
    