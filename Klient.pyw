# pylint: disable=C
import sys
import sqlite3
import hashlib
import os
from PyQt5.QtWidgets import QMainWindow, QApplication
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
        self.actionExit.triggered.connect(self.exit_program)
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

        CONTROLLER.mainWindow()
        self.close()

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

    #Executed when exit button pressed
    def exit_program(self):
        sys.exit()

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

class ControllerClass():
    def __init__(self):
        self.login()

    def login(self):
        self.WINDOW1 = LoginWindow()

    def mainWindow(self):
        self.WINDOW2 = MainWindow()

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

if __name__ == '__main__':
    APP = QApplication(sys.argv)
    CONTROLLER = ControllerClass()
    sys.exit(APP.exec_())
    