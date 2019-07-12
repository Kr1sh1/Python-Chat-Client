#Importing all necessary modules
import sys
import sqlite3
import hashlib
import os
from PyQt5 import uic, QtCore
from PyQt5.QtWidgets import QMainWindow, QApplication

#Main class for the login window
class MyWindow(QMainWindow):
    def __init__(self):
        super(MyWindow, self).__init__()

        #Loading and showing the ui file I made using the "Qt Designer" software
        uic.loadUi('loginui.ui', self)
        #Uncheck next comment to enable borderless mode
        #self.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.show()

        #On click of these buttons, the function named as a parameter is executed
        self.LoginButton.clicked.connect(self.login)
        self.RegisterButton.clicked.connect(self.register)
        self.actionExit.triggered.connect(self.exit_program)
        self.actionDark_Mode.triggered.connect(self.enable_dark_mode)
        self.actionLight_Mode.triggered.connect(self.enable_light_mode)

    #Executed when login button pressed
    def login(self):
        #The current values inside of the username and password boxes in the GUI are saved to the variables username and password
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
        c = connection.cursor()

        try:
            #Executing SQL query on the database to retrieve the salted-hashed password and the salt used
            c.execute("""SELECT passwordHash, salt
                         FROM users
                         WHERE username=?""",(username,))

            #Error thrown when database doen't exist, this happens when the file was missing so a new one empty one was created above
        except sqlite3.OperationalError:
            #Updating message box in the GUI
            self.InformationLabel.setText("'User-details.db' file missing or empty. Make a new account or place the file in this directory.")
            self.InformationLabel.setStyleSheet('color: red')
            print("'User-details.db' file missing or empty. Make a new account or place the file in this directory.")
            return

        try:
            #Retrieving results from the query just executed
            passwordHash, salt = c.fetchone()
            #Type error thrown when there weren't any matches for the condition username=username

        except TypeError:
            #Updating message box in the GUI
            self.InformationLabel.setText("Incorrect Username")
            self.InformationLabel.setStyleSheet('color: red')
            print("Incorrect username")
            return

        #hashing the password with the retrieved salt using the method hashPassword in the SecretCrypt class
        hashedPassword, salt = hashPassword(password, salt)

        #Comparing newly hashed password to the existing hashed password in the database
        if passwordHash == hashedPassword:
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
        c = connection.cursor()

        #Checking if the username is already in use by someone else
        try:
            c.execute("""SELECT username
                         FROM users
                         WHERE username=?""",(username,))
            payload = c.fetchone()

            #If payload has a value then the username already exists in the database. In this case the user needs to pick a different username
            if payload != None:
                self.InformationLabel.setText("Username already exists, try a different one")
                self.InformationLabel.setStyleSheet('color: red')
                print("Username already exists, try a different one")

                return
        except sqlite3.DatabaseError:
            pass

        hashedPassword, salt = hashPassword(password)

        try:
            c.execute("""INSERT INTO users
                         VALUES (?,?,?)""",(username, hashedPassword, salt))
        except sqlite3.DatabaseError:
            c.execute("""CREATE TABLE users
                         (username text, passwordHash text, salt text)""")

            c.execute("""INSERT INTO users
                         VALUES (?,?,?)""",(username, hashedPassword, salt))

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

def hashPassword(password, salt = None):
        password_bytes = bytes(password, encoding="utf-8")
        if salt == None:
            salt = os.urandom(16)
        hashedPassword = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 200000)
        return hashedPassword, salt

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MyWindow()
    sys.exit(app.exec_())
    