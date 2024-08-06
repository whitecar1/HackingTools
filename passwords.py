from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

import settingsmanager
import password_checker
import sys

class PasswordsTools(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
        self.setWindowTitle("PasswordsTools")
        self.setGeometry(360, 170, 1200, 800)
        self.setStyleSheet("background-color: #000066")
        
        self.menu = settingsmanager.MenuBar()
        self.setMenuBar(self.menu)
        
    def initUI(self): 
        selectLabel = QLabel("Select a tool:")
        selectLabel.setFont(QFont("Arial", 30))
        selectLabel.setStyleSheet("color: #FFFF33")
        
        password_checker = QPushButton("Password Checker")
        password_checker.setFont(QFont("Arial", 15))
        password_checker.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        password_checker.clicked.connect(self.password_checker_tool)
        
        self.main_buttons = settingsmanager.MainButtons()
        
        mainLayout = QGridLayout()
        mainLayout.setSpacing(20)
        mainLayout.addWidget(selectLabel, 0, 1, 1, 2)
        mainLayout.addWidget(password_checker, 1, 1)
        mainLayout.addLayout(self.main_buttons.makeButtons(), 5, 0, 1, 3)
        
        centralWidget = QtWidgets.QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)

    def password_checker_tool(self):
        self.close()
        self.passwordchecker = password_checker.PasswordChecker()
        self.passwordchecker.show()