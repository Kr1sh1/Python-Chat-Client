# pylint: disable=W0601,W0201,C
import sys
import sqlite3
import hashlib
import os
import socket
import threading
from secrets import randbits
from copy import deepcopy
from time import sleep, time
from PyQt5.QtWidgets import QMainWindow, QApplication, QListWidgetItem, QWidget, QPlainTextEdit, QPushButton
from PyQt5 import Qt, QtCore, QtWidgets
from login_window import Ui_MainWindow as Window1
from main_window import Ui_MainWindow as Window2

#These constants are used for the diffie-hellman key exchange
#The prime number used is 617 digits long and was aquired from https://www.ietf.org/rfc/rfc3526.txt
PRIME = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559
GENERATOR = 2
SECRET = randbits(256)
SEND_TO_PARTY = pow(GENERATOR, SECRET, PRIME)

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

class ControllerClass():
    def __init__(self):
        self.login()

    def login(self):
        self.WINDOW1 = LoginWindow()

    def mainWindow(self):
        self.username = self.WINDOW1.get_username()
        self.WINDOW1.close()

        #Running the broadcast function in a separate thread so the main program can continue
        #This thread is a "daemon", so when the main program thread is killed this thread will also be killed.
        #This makes sure no threads are left alive accidentally is the program is force closed.
        t1 = threading.Thread(target=broadcast_self, args=(self.username,), daemon=True)
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
    USERNAME = username

    #The variable MAGIC_PASS is used so we don't accidentally get confused with other applications that are broadcasting on port 40000
    #When detecting broadcasts, we can check if the MAGIC_PASS value is at the beginning, so we know that the message is meant for us
    MAGIC_PASS = "o8H1s7,"
    MESSAGE = MAGIC_PASS + USERNAME

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
        print(f"Recieved some data, not sure if compatible: {data}{addr}")
        print(IP_ADDRESS)
        #Making sure the broadcast is meant for us, and we aren't just detecting our own broadcast
        if data.startswith(bytes(MAGIC_PASS, encoding="utf-8")) and addr[0] != IP_ADDRESS:
            username = data.decode("utf-8").split(",")[1]
            print(f"got service announcement from: {username}")
            update_online_clients([addr[0], username])

#Remove clients that haven't broadcasted in the last 3 seconds from our dictionary
def remove_offline_clients():
    #Global variable lets us access this variable outside of this function
    global clients_online
    clients_online = {}
    while True:
        #Creating a copy of the dictionary, deepcopies prevent race conditions from occuring due to multi-threading
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
    