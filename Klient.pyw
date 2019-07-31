# pylint: disable=W0601,W0201,C
import sys
import sqlite3
import hashlib
import os
import socket
import threading
from copy import deepcopy
from time import sleep, time
from PyQt5.QtWidgets import QMainWindow, QApplication, QListWidgetItem, QWidget
from PyQt5 import Qt
from login_window import Ui_MainWindow as Window1
from main_window import Ui_MainWindow as Window2

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

    #Executed when darm mode button pressed
    def enable_dark_mode(self):

        self.centralwidget.setStyleSheet("background: '#262626'")
        self.menubar.setStyleSheet("QMenuBar {"
                                   "color: white;"
                                   "background: black"
                                   "}"

                                   "QMenuBar:selected {"
                                   "color: black"
                                   "}")
        self.menuOptions.setStyleSheet("QMenu {"
                                       "background: white;"
                                       "color: black"
                                       "}"

                                       "QMenu:selected {"
                                       "background: red;"
                                       "}")
        self.PasswordLabel.setStyleSheet("color: '#ccc'")
        self.UsernameLabel.setStyleSheet("color: '#ccc'")
        self.PasswordLine.setStyleSheet("color: '#ccc'; background: '#1a1a1a'")
        self.UsernameLine.setStyleSheet("color: '#ccc'; background: '#1a1a1a'")
        self.LoginButton.setStyleSheet("QPushButton {"
                                       "color: #CCC;"
                                       "background: #1A1A1A;"
                                       "border: 1px solid white;"
                                       "border-radius: 10px"
                                       "}"

                                       "QPushButton:hover {"
                                       "border-color: red"
                                       "}")
        self.RegisterButton.setStyleSheet("QPushButton {"
                                          "color: #CCC;"
                                          "background: #1A1A1A;"
                                          "border: 1px solid white;"
                                          "border-radius: 10px"
                                          "}"

                                          "QPushButton:hover {"
                                          "border-color: red"
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

        #On click of these buttons, the function named as a parameter is executed
        self.actionExit.triggered.connect(exit_program)
        self.listWidget.itemSelectionChanged.connect(self.item_changed)

    def item_changed(self):
        selected_user = self.listWidget.selectedItems()[0].text()
        tab_count = self.tabWidget.count()
        for x in range(tab_count):
            if self.tabWidget.tabText(x) == selected_user:
                self.tabWidget.setCurrentIndex(x)
                return
        
        object_name = "object " + str(self.tabWidget.count())
        tab = QWidget()
        tab.setObjectName(object_name)
        self.tabWidget.addTab(tab, selected_user)
        self.tabWidget.setCurrentIndex(tab_count)

class ControllerClass():
    def __init__(self):
        self.login()

    def login(self):
        self.WINDOW1 = LoginWindow()

    def mainWindow(self):
        username = self.WINDOW1.get_username()
        self.WINDOW1.close()

        #Running the broadcast function in a separate thread so the main program can continue
        #This thread is a "daemon", so when the main program thread is killed this thread will also be killed.
        #This makes sure no threads are left alive accidentally is the program is force closed.
        t1 = threading.Thread(target=broadcast_self, args=(username,), daemon=True)
        t2 = threading.Thread(target=detect_other_clients, daemon=True)
        t3 = threading.Thread(target=remove_offline_clients, daemon=True)

        self.WINDOW2 = MainWindow()

        t1.start()
        t2.start()
        t3.start()

#Executed when exit button pressed
def exit_program():
    sys.exit()

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

    #The variable MAGIC_PASS is used so we don't accidentally get confused with other applications that are broadcasting on port 40000
    #When detecting broadcasts, we can check if the MAGIC_PASS value is at the beginning, so we know that the message is meant for us
    MAGIC_PASS = "o8H1s7,"
    IP_ADDRESS = socket.gethostbyname(socket.gethostname())
    MESSAGE = MAGIC_PASS + USERNAME + IP_ADDRESS

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    #Broadcast the message every 2 seconds
    while True:
        sock.sendto(bytes(MESSAGE, encoding="utf-8"), ('<broadcast>', PORT))
        print("Broadcasting...")
        sleep(2)

#This function detects broadcasts on port 40000 made by other instances of this program.
def detect_other_clients():
    PORT = 40000
    MAGIC_PASS = "o8H1s7"
    IP_ADDRESS = socket.gethostbyname(socket.gethostname())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PORT))

    while 1:
        data, addr = sock.recvfrom(1024)

        #Making sure the broadcast is meant for us, and we aren't just detecting our own broadcast
        if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")) and addr[0] != IP_ADDRESS:
            username = data.decode("utf-8").split(",")[1]
            print("got service announcement from", username)
            update_online_clients([addr[0], username])

#Remove clients that haven't broadcasted in the last 3 seconds from our dictionary
def remove_offline_clients():
    #Global variable lets us access this variable outside of this function
    global clients_online
    clients_online = {}
    while True:
        #Creating a copy of the dictionary
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
            clients_online[key[0]] = [time(), client_data[1]]
            return

    #Adding client to dictionary
    clients_online[client_data[0]] = [time(), client_data[1]]
    update_online_clients_list(client_data, "add")
    CONTROLLER.WINDOW2.numberOfClientsLabel.setText(str(len(clients_online)))

#Updating the list users click on in the GUI
def update_online_clients_list(client_data, action):
    if action == "rm":
        item = CONTROLLER.WINDOW2.listWidget.findItems((client_data[1] + " " + str(client_data[0])), Qt.Qt.MatchExactly)
        CONTROLLER.WINDOW2.listWidget.takeItem(CONTROLLER.WINDOW2.listWidget.row(item[0]))
    else:
        item = QListWidgetItem(client_data[1] + " " + str(client_data[0]))
        CONTROLLER.WINDOW2.listWidget.addItem(item)

if __name__ == '__main__':
    APP = QApplication(sys.argv)
    CONTROLLER = ControllerClass()
    sys.exit(APP.exec_())
    