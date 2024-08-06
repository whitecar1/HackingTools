from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

import settingsmanager
import sys

class PasswordChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
        self.setWindowTitle("PasswordChecker")
        self.setGeometry(360, 170, 1200, 800)
        self.setStyleSheet("background-color: #000066;")
        
        self.menu = settingsmanager.MenuBar()
        self.setMenuBar(self.menu)
        
    def initUI(self):
        self.main_buttons = settingsmanager.MainButtons()
        
        mainLayout = QGridLayout()
        mainLayout.setSpacing(20)
        mainLayout.addLayout(self.main_buttons.makeButtons(), 0, 0, 1, 3)
        
        centralWidget = QtWidgets.QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)