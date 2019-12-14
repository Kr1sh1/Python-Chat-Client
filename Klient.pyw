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
from cryptography.fernet import Fernet
from copy import deepcopy
from time import sleep, time
from PyQt5.QtWidgets import QMainWindow, QApplication, QListWidgetItem, QWidget, QPlainTextEdit, QPushButton
from PyQt5 import QtCore, QtWidgets
from login_window import Ui_MainWindow as login_window
from main_window import Ui_MainWindow as main_window

#The RSACrypt class provides in a simple interface the methods to encrypt or decrypt messages using the RSA algorithm
class RSACrypt():
    def __init__(self):
        #The key generation process can take a while, taking advantage of multiple cores in the system will speed it up
        self.number_of_cpu_cores = multiprocessing.cpu_count()

        if self.number_of_cpu_cores >= 8:
            self.number_of_cpu_cores = 4
        elif self.number_of_cpu_cores >= 4:
            self.number_of_cpu_cores = 2
        else:
            self.number_of_cpu_cores = 1
        
        self.__public_key , self.__private_key = None, None

    def get_public_key(self):
        return self.__public_key

    def get_private_key(self):
        return self.__private_key

    #Updates private and public key of this user
    def update_keys(self, public_key, private_key):
        self.__public_key , self.__private_key = public_key, private_key

    #Generates a new pair of public and private keys
    def generate_new_keys(self):
        self.__public_key , self.__private_key = rsa.newkeys(4096, poolsize=self.number_of_cpu_cores)
        return self.__public_key , self.__private_key

    #Encrypts message using public key of receiever
    def encrypt_message(self, message, pub_key):
        message_bytes = message.encode("utf8")
        encrypted_message = rsa.encrypt(message_bytes, pub_key)
        return encrypted_message

    #Decrypts message using this user's private key
    def decrypt_message(self, encrypted_message):
        decrypted_message_bytes = rsa.decrypt(encrypted_message, self.__private_key)
        decrypted_message = decrypted_message_bytes.decode("utf8")
        return decrypted_message


#T0D0 - Make commas illegal characters in a username DONE + other characters
#Main class for the login window
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
    def input_checks(self, username, password):
        #List of characters not allowed in username
        illegal_characters = [" ", ",", "\"", "\'", "\\", "/"]

        #Returns true when an illegal character was detected
        iterable = [True for x in illegal_characters if x in username]

        if username == "" or password == "":
            #Updating message box in the GUI
            self.InformationLabel.setText("Values must be entered for both fields")
            self.InformationLabel.setStyleSheet('color: red')
            print("Values must be entered for both fields")
            return True

        #If any illegal characters are in the username, then this will return True
        if any(iterable):
            self.InformationLabel.setText("Illegal characters in username. No spaces, commas or speech marks are permitted")
            self.InformationLabel.setStyleSheet('color: red')
            print("Illegal characters in username")
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

        try:
            #SQL query to retrieve the salted-hashed password and the salt used
            cursor.execute("""SELECT passwordHash, salt
                         FROM users
                         WHERE username=?""", (username,))

            #Error thrown when database doesn't exist.
        except sqlite3.DatabaseError:
            #Updating message box in the GUI
            self.InformationLabel.setText("Database file missing or empty. Make a new account.")
            self.InformationLabel.setStyleSheet('color: red')
            print("Database file missing or empty. Make a new account.")
            return

        try:
            #Retrieving results from the query just executed
            password_hash, salt = cursor.fetchone()
            #Type error thrown when there weren't any matches for the condition username=username

        except TypeError:
            #Updating message box in the GUI
            self.InformationLabel.setText("Incorrect Username")
            self.InformationLabel.setStyleSheet('color: red')
            print("Incorrect username")
            return

        #hashing the password with the retrieved salt using the method hash_password
        hashed_password, salt = hash_password(password, salt)

        #Comparing newly hashed password to the existing hashed password in the database
        if password_hash == hashed_password:
            #Updating message box in the GUI
            self.InformationLabel.setText("Login successful")
            self.InformationLabel.setStyleSheet('color: green')
            print("login successful")

        else:
            #Updating message box in the GUI
            self.InformationLabel.setText("Incorrect password")
            self.InformationLabel.setStyleSheet('color: red')
            print("Incorrect password")
            self.PasswordLine.setText("")
            return

        connection.close()
        self.username = username
        self.password = password
        CONTROLLER.mainWindow()

    #Executed when register button pressed
    def register(self):
        username = self.UsernameLine.text()
        password = self.PasswordLine.text()

        if self.input_checks(username, password):
            return

        connection = sqlite3.connect("User-details.db")
        cursor = connection.cursor()

        #Checking if the username is already in use by someone else
        try:
            cursor.execute("""SELECT username
                         FROM users
                         WHERE username=?""", (username,))
            payload = cursor.fetchone()

            #If the username already exists, then payload will have a value
            if payload is not None:
                self.InformationLabel.setText("Username already exists, try a different one")
                self.InformationLabel.setStyleSheet('color: red')
                print("Username already exists, try a different one")

                return
        except sqlite3.DatabaseError:
            cursor.execute("""CREATE TABLE users
                         (username text, passwordHash text, salt text, public_key text, encrypted_private_key text, salt_2 text)""")

        hashed_password, salt = hash_password(password)

        cursor.execute("""INSERT INTO users (username, passwordHash, salt)
                        VALUES (?,?,?)""", (username, hashed_password, salt))

        connection.commit()
        connection.close()
        #Updating message box in the GUI
        self.InformationLabel.setText("Registration complete!")
        self.InformationLabel.setStyleSheet('color: green')
        print("registration complete!")

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

#T0D0 - Create stacks for history feature - DONE TEST PROPERLY

#T0D0 - Update stylesheets to better color scheme for dynamically created objects DONE
class MainWindow(QMainWindow, main_window):
    def __init__(self):
        super(MainWindow, self).__init__()

        #Initialises the GUI
        self.setupUi(self)
        self.show()
        self.USER = CONTROLLER.username

        #On click of these buttons, the function named as a parameter is executed
        self.actionExit.triggered.connect(exit_program)
        self.listWidget.itemDoubleClicked.connect(self.item_changed)

        #This dictionary is used to keep track of dynamically generated objects
        self.tabs = {}

        #Pressing pg up or dn will retrieve messages sent, similar to the way command history works in terminals
        self.stack_up = []
        self.stack_down = []

    #This function manages the up and down message history stack
    #You go up the history by pressing CTRL - PGUP, and CTRL - PGDN to go down
    def keyPressEvent(self, event):
        #CTRL- PG UP event
        if event.key() == 16777238:
            focus = QApplication.focusObject()
            if "QPlainTextEdit" in str(focus):
                print(focus)
                if len(self.stack_up) != 0:
                    selected_user = self.tabWidget.tabText(self.tabWidget.currentIndex())
                    latest_message = self.stack_up.pop()
                    text_entry = self.tabs.get(selected_user)[1]
                    previous_message = text_entry.toPlainText()
                    self.stack_down.append(previous_message)
                    focus.setPlainText(latest_message)

        #CTRL - PG DOWN event
        elif event.key() == 16777239:
            focus = QApplication.focusObject()
            if "QPlainTextEdit" in str(focus):
                if len(self.stack_down) != 0:
                    latest_message = self.stack_down.pop()
                    selected_user = self.tabWidget.tabText(self.tabWidget.currentIndex())
                    text_entry = self.tabs.get(selected_user)[1]
                    previous_message = text_entry.toPlainText()
                    self.stack_up.append(previous_message)
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

        self.create_tab(selected_user, tab_count)

    #Creates a new tab for each new user
    #GUI generation
    def create_tab(self, selected_user, tab_count):
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
        enter_button = self.create_enter_button(tab, horizlayout_2)

        vertlayout_2.addLayout(horizlayout_2)
        verticalLayout_4.addLayout(vertlayout_2)

        enter_button.clicked.connect(lambda: self.message_entered(text_entry, selected_user, message_box))

        self.tabWidget.addTab(tab, selected_user)
        self.tabWidget.setCurrentIndex(tab_count)

        #Saving dynamically generated object in a dictionary so we can access it later
        self.tabs[selected_user] = (message_box, text_entry)

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
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(plainTextEdit.sizePolicy().hasHeightForWidth())
        plainTextEdit.setSizePolicy(sizePolicy)
        plainTextEdit.setMaximumSize(QtCore.QSize(16777215, 75))
        plainTextEdit.setObjectName("plainTextEdit")
        horizontalLayout_2.addWidget(plainTextEdit)
        return plainTextEdit, horizontalLayout_2

    #This created an enter button that sends the message you type in the text edit box
    def create_enter_button(self, tab, horizontalLayout_2):
        pushButton = QPushButton(tab)
        pushButton.setStyleSheet("QPushButton {"
                                 "background-color: #00bf0a;"
                                 "border-color: rgb(225, 85, 0);"
                                 "}"
        
                                 "QPushButton::hover {"
                                 "background-color: #00a609;"
                                 "}")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(pushButton.sizePolicy().hasHeightForWidth())
        pushButton.setSizePolicy(sizePolicy)
        pushButton.setMaximumSize(QtCore.QSize(75, 75))
        pushButton.setObjectName("pushButton")
        horizontalLayout_2.addWidget(pushButton)
        pushButton.setText("SND \n MSG")
        return pushButton

    #Adds message to message box and calls function to send message
    def message_entered(self, text_entry, selected_user, message_box):
        message = text_entry.toPlainText()
        text_entry.clear()

        #Handles putting messages in the stack
        if len(self.stack_up) == 0 or self.stack_up[-1] != message:
            self.stack_up.append(message)

        print(f"The following message will be sent to: {selected_user} \n\n {message}")
        send_message(selected_user, message)
        message = "<font color = #0F0>" + CONTROLLER.username + "</color>" + ": " + "<font color = 'white'>" + message + "</color>"
        message_box.append(message)

#TODO - InformationLabel won't update correctly, maybe try and fix (low priority)
#Controls several things, such as which windows appear when and when to start multiple threads
class WindowController():
    def __init__(self):
        self.login()

    def login(self):
        self.WINDOW1 = LoginWindow()

    def mainWindow(self):
        global dict_list_items
        global sock
        global RSA_ENCRYPTION

        dict_list_items = {}
        self.username = self.WINDOW1.username

        RSA_ENCRYPTION = RSACrypt()

        #Checks if keys are available in database and updates them in RSACrypt class, else generates new keys
        keys = check_rsa_keys_available()
        if keys[0] == False:
            self.WINDOW1.InformationLabel.setText("Generating RSA keys...")
            self.WINDOW1.InformationLabel.setStyleSheet('color: blue')
            __public_key, __private_key = RSA_ENCRYPTION.generate_new_keys()
            save_rsa_keys(__public_key, __private_key)
        else:
            self.WINDOW1.InformationLabel.setText("Loading RSA keys...")
            RSA_ENCRYPTION.update_keys(keys[1], keys[2])

        self.WINDOW1.close()

        #Opens a socket that's used to send and receive messages on a specified port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((socket.getfqdn(), 8000))

        #Runnings these functions in their own threads as they need to be running constantly and shouldn't be blocked by other code
        #This thread is a "daemon", so when the main program thread is killed this thread will also be killed.
        #This makes sure no threads are left alive accidentally is the program is force closed.
        t1 = threading.Thread(target=broadcast_self, args=(self.username,), daemon=True)
        t2 = threading.Thread(target=detect_other_clients, daemon=True)
        t3 = threading.Thread(target=remove_offline_clients, daemon=True)
        t4 = threading.Thread(target=receive_messages, daemon=True)

        self.WINDOW2 = MainWindow()

        t1.start()
        t2.start()
        t3.start()
        t4.start()

#Executed when exit button pressed
def exit_program():
    sys.exit()

#TODO - Messages are limited to 501 bytes with current implementation
#Probably should do something about that. Possible fix is exchanging AES keys through RSA, then using those to encrypt and decrypt data
#As there is no max to amount of data when encrypting with AES

#TODO - Don't attempt to send messages if the user went offline
def send_message(selected_user, message):
    PORT = 8001
    MAGIC_PASS = "iJ9d2J,"
    IP_ADDRESS = socket.gethostbyname(socket.gethostname())
    USER = bytes(CONTROLLER.username + " " + IP_ADDRESS, encoding="utf-8")
    message = CONTROLLER.username + "," + message
    selected_user_ip = selected_user.split(" ")[-1]
    PUBLIC_KEY = clients_online.get(selected_user_ip)[2]
    RSA_SIGNATURE = rsa.sign(USER, RSA_ENCRYPTION.get_private_key(), "SHA-256")
    encrypted_message = bytes(MAGIC_PASS + str([RSA_ENCRYPTION.encrypt_message(message, PUBLIC_KEY), RSA_SIGNATURE]), encoding="utf8")
    try:
        sending_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sending_sock.sendto(encrypted_message, (selected_user_ip, PORT))
    except Exception as e:
        print(f"Exception :{e}")

#TODO - Implement verification of message to ensure the sender isn't lying about their identity - DONE NEEDS TESTING

#T0D0-FIXED#
#Test eval replacement ast.literal_eval is functioning correctly

#T0D0-FIXED#
#Fix colour of text appearing in message box
def receive_messages():
    PORT = 8001
    MAGIC_PASS = "iJ9d2J"
    IP_ADDRESS = socket.gethostbyname(socket.gethostname())

    receiving_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiving_sock.bind(('', PORT))

    while True:
        data, addr = receiving_sock.recvfrom(4096)
        #print(f"Recieved some data, not sure if relevant: {data}{addr}")
        print(IP_ADDRESS)
        #Making sure the broadcast is meant for us, and we aren't just detecting our own broadcast
        if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")) and addr[0] != IP_ADDRESS:
        #if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")):
            data = data.decode("utf-8").split(",", maxsplit=1)

            #Previously I was using eval to turn a string representation of a list into a list
            #Use of eval can be dangerous as it evaluates everything as python code, so code injections are a risk
            #So I found an alternative, ast.literal_eval
            #ast.literal_eval is incapable of operating on anything but python data types
            #So while it can turn "[]" into [], it cannot turn "5+5" into 10, instead resulting in a thrown exception
            try:
                encrypted_data = ast.literal_eval(data[1])[0]
                signature = ast.literal_eval(data[1])[1]
            except Exception as e:
                print(f"Exception: {e}\n Possible corrupted message or injection attempt")
            
            decrypted_data = RSA_ENCRYPTION.decrypt_message(encrypted_data)
            decrypted_data = decrypted_data.split(",", maxsplit=1)
            username = decrypted_data[0]
            message = "<font color = #0FF>" + username + ": " + "</color>" + "<font color = 'white'>" + decrypted_data[1] + "</color>"
            selected_user = username + " " + addr[0]

            user_pub_key = clients_online.get(addr[0])[2]
            if rsa.verify(bytes(selected_user, encoding="utf-8"), signature, user_pub_key):
                print("Message verified")
            else:
                print("Received possibly tampered message")
                return

            tab = CONTROLLER.WINDOW2.tabs
            message_box = tab.get(selected_user)[0]
            message_box.append(message)

    return

#Function to hash password

#If the function hashPassword is only given one arguement, the password, a random salt is chosen
#Else if a salt in also given, the password is hashed with that salt.
#This is so new passwords can be created with a new salt, and so existing passwords can be hashed
#with their salt to check against a hash in the database.

def hash_password(password, salt=None):
    password_bytes = bytes(password, encoding="utf-8")
    if salt is None:
        salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 200000)
    return hashed_password, salt

#This function announces itself on the local network to anyone listening on port 8000
#This allows us and other clients to see who's online.
def broadcast_self(username):
    PORT = 8000
    USERNAME = username + ","

    #Other users on the network need this key to encrypt their messages and send them to you
    PUBLIC_KEY = RSA_ENCRYPTION.get_public_key()

    #The variable MAGIC_PASS is used so we don't accidentally get confused with other applications that are broadcasting on port 8000
    #When detecting broadcasts, we can check if the MAGIC_PASS value is at the beginning, so we know that the message is meant for us
    MAGIC_PASS = "o8H1s7,"
    #pickling python objects turns them into byte streams, allowing us to send them over the network
    MESSAGE = bytes(str(MAGIC_PASS + USERNAME) + str([pickle.dumps(PUBLIC_KEY)]), encoding="utf8")

    #Broadcast the message every 2 seconds
    while True:
        sock.sendto(MESSAGE, ('<broadcast>', PORT))
        print("Broadcasting...")
        sleep(2)

    return

#T0D0-FIXED#
#Test eval replacement ast.literal_eval is functioning correctly

#This function detects broadcasts on port 8000 made by other instances of this program.
def detect_other_clients():
    MAGIC_PASS = "o8H1s7"
    HOST_NAME = socket.gethostname()
    IP_ADDRESS = socket.gethostbyname(HOST_NAME)

    while True:
        data, addr = sock.recvfrom(4096)
        #print(f"Recieved some data, not sure if compatible: {data}{addr}")
        print(IP_ADDRESS)
        #Making sure the broadcast is meant for us, and we aren't just detecting our own broadcast
        if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")) and addr[0] != IP_ADDRESS:
        #if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")):
            data = data.decode("utf-8").split(",", maxsplit=2)
            username = data[1]
            try:
                PUBLIC_KEY = pickle.loads(ast.literal_eval(data[2])[0])
            except Exception as e:
                print(f"Exception: {e}\n Possible corrupted broadcast or injection attempt")
            print(f"got service announcement from: {username}")
            update_online_clients([addr[0], username, PUBLIC_KEY])

#Remove clients that haven't broadcasted in the last 3 seconds from our dictionary
def remove_offline_clients():
    #Global variable lets us access this variable outside of this function
    global clients_online
    clients_online = {}
    while True:
        #Creating a copy of the dictionary, deepcopies prevent the original copy from being modified
        #Deepcopies are necessary here to prevent race conditions from occuring due to multiple threads attempting to access the same variable
        clone_clients_online = deepcopy(clients_online)
        for key, value in clone_clients_online.items():
            #If broadcast hasn't been received in the last 4 seconds, this condition is true
            #The client is then removed from our dictionary
            if (time()-value[0]) > 4:
                clients_online.pop(key)
                client_data = [key, value[1]]
                remove_client_from_online_list(client_data)
                CONTROLLER.WINDOW2.numberOfClientsLabel.setText(str(len(clients_online)))

        sleep(1)

#Everytime a broadcast is detected, this function is run
#Existing clients will have the time stamp of their last broadcast updated
#New clients will be added to our dictionary
def update_online_clients(client_data):
    global clients_online
    
    clone_clients_online = deepcopy(clients_online)
    for key in clone_clients_online.items():
        if key[0] == client_data[0]:
            #Updating only the timestamp
            clients_online[key[0]] = [time(), client_data[1], client_data[2]]
            return

    #Adding client to dictionary
    clients_online[client_data[0]] = [time(), client_data[1], client_data[2]]
    add_client_to_online_list(client_data)
    CONTROLLER.WINDOW2.numberOfClientsLabel.setText(str(len(clients_online)))

#T0D0-FIXED#
#Make sure new implementation of saving item objects in dictionary is working
#Updating the list users click on in the GUI
def remove_client_from_online_list(client_data):
    global dict_list_items
    item = dict_list_items.get(client_data[1] + " " + client_data[0])
    CONTROLLER.WINDOW2.listWidget.takeItem(CONTROLLER.WINDOW2.listWidget.row(item))

def add_client_to_online_list(client_data):
    global dict_list_items
    item = QListWidgetItem(client_data[1] + " " + str(client_data[0]))
    CONTROLLER.WINDOW2.listWidget.addItem(item)
    dict_list_items[client_data[1] + " " + client_data[0]] = item

#T0D0 DONE
#Check if keys are available in database
#Decrypt them if available
#Return list [True/False, PublicKey/None, PrivateKey/None]
def check_rsa_keys_available():
    connection = sqlite3.connect("User-details.db")
    cursor = connection.cursor()
    cursor.execute("""SELECT public_key, encrypted_private_key, salt_2 
                      FROM users 
                      WHERE username=?""",
                      (CONTROLLER.username,))
    public_key, encrypted_private_key, salt = cursor.fetchone()
    if salt is None:
        return [False, None, None]
    private_key = decrypt_key(encrypted_private_key, salt)
    public_key = pickle.loads(public_key)
    return [True, public_key, private_key]

#T0D0 - Test decryption of RSA keys DONE
#Decrypt keys
def decrypt_key(encrypted_private_key, salt):
    AES_KEY = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", bytes(CONTROLLER.WINDOW1.password, encoding="utf-8"), salt, 100000, dklen=32))
    f = Fernet(AES_KEY)
    private_key = pickle.loads(f.decrypt(encrypted_private_key))
    return private_key

#T0D0 - RSA keys encryption needs to be tested DONE
#Encrypt keys
def encrypt_key(private_key):
    salt = os.urandom(16)
    AES_KEY = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", bytes(CONTROLLER.WINDOW1.password, encoding="utf-8"), salt, 100000, dklen=32))
    f = Fernet(AES_KEY)
    bytes_priv_key = pickle.dumps(private_key)
    encrypted_private_key = f.encrypt(bytes_priv_key)
    return encrypted_private_key, salt

#T0D0 - Saving encrypted RSA keys to database needs to be tested DONE
#Save keys to database
#columns public_key and private_key
def save_rsa_keys(public_key, private_key):
    encrypted_private_key, salt = encrypt_key(private_key)
    bytes_pub_key = pickle.dumps(public_key)
    connection = sqlite3.connect("User-details.db")
    cursor = connection.cursor()
    cursor.execute("""UPDATE users 
                    SET public_key=?, encrypted_private_key=?, salt_2=? 
                    WHERE username=?""", (
                    bytes_pub_key, encrypted_private_key, salt, CONTROLLER.username))
    connection.commit()
    connection.close()

def main():
    global APP
    global CONTROLLER

    APP = QApplication(sys.argv)
    CONTROLLER = WindowController()
    sys.exit(APP.exec_())

if __name__ == '__main__':
    main()
    