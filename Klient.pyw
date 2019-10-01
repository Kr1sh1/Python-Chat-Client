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
from copy import deepcopy
from time import sleep, time
from PyQt5.QtWidgets import QMainWindow, QApplication, QListWidgetItem, QWidget, QPlainTextEdit, QPushButton
from PyQt5 import QtCore, QtWidgets
from login_window import Ui_MainWindow as Window1
from main_window import Ui_MainWindow as Window2

class RSACrypt():
    def __init__(self):
        number_of_cpu_cores = multiprocessing.cpu_count()
        (self.__public_key , self.__private_key) = rsa.newkeys(4096, poolsize=number_of_cpu_cores)

    def get_public_key(self):
        return self.__public_key
    def encrypt_message(self, message, pub_key):
        message_bytes = message.encode("utf8")
        encrypt_message = rsa.encrypt(message_bytes, pub_key)
        return encrypt_message

    def decrypt_message(self, encrypt_message):
        decrypt_message_bytes = rsa.decrypt(encrypt_message, self.__private_key)
        decrypt_message = decrypt_message_bytes.decode("utf8")
        return decrypt_message


#TODO
#Make commas illegal characters in a username
#Main class for the login window
class LoginWindow(QMainWindow, Window1):

    def __init__(self):
        super(LoginWindow, self).__init__()

        #Uncheck next comment to enable borderless mode. Also import QtCore from PyQt5
        #self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setupUi(self)
        self.show()

        #On click of these buttons, the function named as a parameter is executed
        self.LoginButton.clicked.connect(self.login)
        self.RegisterButton.clicked.connect(self.register)
        self.actionExit.triggered.connect(exit_program)
        self.actionDark_Mode.triggered.connect(self.enable_dark_mode)
        self.actionLight_Mode.triggered.connect(self.enable_light_mode)

    #Executed when login button pressed
    def login(self):

        #User entered values are stored to the variables username and password
        username = self.UsernameLine.text()
        password = self.PasswordLine.text()

        if username == "" or password == "":
            #Updating message box in the GUI
            self.InformationLabel.setText("Values must be entered for both fields")
            self.InformationLabel.setStyleSheet('color: red')
            print("Values must be entered for both fields")
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
        except sqlite3.OperationalError:
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
        CONTROLLER.mainWindow()

    def get_username(self):
        return self.username

    #Executed when register button pressed
    def register(self):

        username = self.UsernameLine.text()
        password = self.PasswordLine.text()

        if username == "" or password == "":
            #Updating message box in the GUI
            self.InformationLabel.setText("Values must be entered for both fields")
            self.InformationLabel.setStyleSheet('color: red')
            print("Values must be entered for both fields")
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
            pass

        hashed_password, salt = hash_password(password)

        try:
            cursor.execute("""INSERT INTO users
                         VALUES (?,?,?)""", (username, hashed_password, salt))
        except sqlite3.DatabaseError:
            cursor.execute("""CREATE TABLE users
                         (username text, passwordHash text, salt text)""")

            cursor.execute("""INSERT INTO users
                         VALUES (?,?,?)""", (username, hashed_password, salt))

        connection.commit()
        connection.close()

        #Updating message box in the GUI
        self.InformationLabel.setText("Registration complete!")
        self.InformationLabel.setStyleSheet('color: green')
        print("registration complete!")

    #Executed when dark mode button pressed
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


class MainWindow(QMainWindow, Window2):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.setupUi(self)
        self.show()
        self.USER = CONTROLLER.username

        #On click of these buttons, the function named as a parameter is executed
        self.actionExit.triggered.connect(exit_program)
        self.listWidget.itemDoubleClicked.connect(self.item_changed)

        self.tabs = {}
    def item_changed(self, item):
        selected_user = item.text()
        tab_count = self.tabWidget.count()
        for x in range(tab_count):
            if self.tabWidget.tabText(x) == selected_user:
                if self.tabWidget.currentIndex != x:
                    self.tabWidget.setCurrentIndex(x)

                return

        self.create_tab(selected_user, tab_count)

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

        self.tabs[selected_user] = message_box
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

    def message_entered(self, text_entry, selected_user, message_box):
        message = "<font color = 'white'>" + text_entry.toPlainText() + "</color>"
        text_entry.clear()
        message_box.append(message)

        print(f"The following message will be sent to: {selected_user} \n\n {message}")
        send_message(selected_user, message)


class ControllerClass():
    def __init__(self):
        self.login()

    def login(self):
        self.WINDOW1 = LoginWindow()

    def mainWindow(self):
        global dict_list_items
        dict_list_items = {}
        self.username = self.WINDOW1.get_username()
        self.WINDOW1.close()

        #Running the broadcast function in a separate thread so the main program can continue
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

#TODO
#Messages are limited to 501 bytes with current implementation
#Probably should do something about that

#TODO
#Don't attempt to send messages if the user went offline
def send_message(selected_user, message):
    PORT = 40001
    MAGIC_PASS = "iJ9d2J,"
    message = CONTROLLER.username + "," + message
    selected_user_ip = selected_user.split(" ")[-1]
    PUBLIC_KEY = clients_online.get(selected_user_ip)[2]
    encrypted_message = bytes(MAGIC_PASS + str([RSA_ENCRYPTION.encrypt_message(message, PUBLIC_KEY)]), encoding="utf8")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(encrypted_message, (selected_user_ip, PORT))
    except Exception as e:
        print(f"Exception :{e}")

#TODO
#Fix colour of text appearing in message box
def receive_messages():
    PORT = 40001
    MAGIC_PASS = "iJ9d2J"
    IP_ADDRESS = socket.gethostbyname(socket.getfqdn())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PORT))

    while 1:
        data, addr = sock.recvfrom(2048)
        #print(f"Recieved some data, not sure if relevant: {data}{addr}")
        print(IP_ADDRESS)
        #Making sure the broadcast is meant for us, and we aren't just detecting our own broadcast
        if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")) and addr[0] != IP_ADDRESS:
        #if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")):
            data = data.decode("utf-8").split(",", maxsplit = 1)
            encrypted_data = eval(data[1])[0]
            decrypted_data = RSA_ENCRYPTION.decrypt_message(encrypted_data)
            username = decrypted_data.split(",")[0]
            message = "<font color = 'blue'>" + ",".join(decrypted_data.split(",")[1:]) + "</color>"
            selected_user = username + " " + addr[0]
            tab = CONTROLLER.WINDOW2.tabs
            message_box = tab.get(selected_user)
            message_box.append(message)

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

#This function announces itself on the local network to anyone listening on port 40000
#This allows us and other clients to see who's online.
def broadcast_self(username):
    PORT = 40000
    USERNAME = username + ","

    #Other users on the network need this key to encrypt their messages and send them to you
    PUBLIC_KEY = RSA_ENCRYPTION.get_public_key()

    #The variable MAGIC_PASS is used so we don't accidentally get confused with other applications that are broadcasting on port 40000
    #When detecting broadcasts, we can check if the MAGIC_PASS value is at the beginning, so we know that the message is meant for us
    MAGIC_PASS = "o8H1s7,"
    MESSAGE = bytes(str(MAGIC_PASS + USERNAME) + str([pickle.dumps(PUBLIC_KEY)]), encoding="utf8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    #Broadcast the message every 2 seconds
    while True:
        sock.sendto(MESSAGE, ('<broadcast>', PORT))
        print("Broadcasting...")
        sleep(2)

#This function detects broadcasts on port 40000 made by other instances of this program.
def detect_other_clients():
    PORT = 40000
    MAGIC_PASS = "o8H1s7"
    IP_ADDRESS = socket.gethostbyname(socket.getfqdn())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PORT))

    while 1:
        data, addr = sock.recvfrom(4096)
        #print(f"Recieved some data, not sure if compatible: {data}{addr}")
        print(IP_ADDRESS)
        #Making sure the broadcast is meant for us, and we aren't just detecting our own broadcast
        if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")) and addr[0] != IP_ADDRESS:
        #if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")):
            data = data.decode("utf-8").split(",", maxsplit=2)
            username = data[1]
            PUBLIC_KEY = pickle.loads(eval(data[2])[0])
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
                update_online_clients_list(client_data, "rm")
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
    update_online_clients_list(client_data, "add")
    CONTROLLER.WINDOW2.numberOfClientsLabel.setText(str(len(clients_online)))

#TODO
#Make sure new implementation is working
#Updating the list users click on in the GUI
def update_online_clients_list(client_data, action):
    global dict_list_items
    if action == "rm":
        item = dict_list_items.get(client_data[1] + " " + client_data[0])
        CONTROLLER.WINDOW2.listWidget.takeItem(CONTROLLER.WINDOW2.listWidget.row(item))
        y = 0
    else:
        item = QListWidgetItem(client_data[1] + " " + str(client_data[0]))
        CONTROLLER.WINDOW2.listWidget.addItem(item)
        dict_list_items[client_data[1] + " " + client_data[0]] = item
        y = 0

if __name__ == '__main__':
    print("Generating keys for asymmetric encryption...")
    RSA_ENCRYPTION = RSACrypt()
    print("Keys generated")
    APP = QApplication(sys.argv)
    CONTROLLER = ControllerClass()
    sys.exit(APP.exec_())
    