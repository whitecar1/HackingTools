from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

import toolswindow
import startwindow
import settingswindow
import settingsmanager
import sys

class SettingsWindow(QMainWindow):
    def __init__(self):
        super(SettingsWindow, self).__init__()
        self.initUI()
        
        self.setWindowTitle("Settings")
        self.setGeometry(360, 170, 1200, 800)
        self.setStyleSheet("background-color: #000066")
        
        self.menu = settingsmanager.MenuBar()
        self.setMenuBar(self.menu)
        
    def initUI(self):
        colorLabel = QLabel("Change a background color", self)
        colorLabel.setFont(QFont("Arial", 25))
        colorLabel.setStyleSheet("color: #FFFF33")
        colorLabel.adjustSize()
        
        colorButton = QPushButton("change", self)
        colorButton.setFont(QFont("Arial", 10))
        colorButton.setStyleSheet("background-color: #CC00FF; color: #FFD700;")
                
        self.main_buttons = settingsmanager.MainButtons()
        
        mainLayout = QGridLayout()
        mainLayout.setSpacing(20)
        mainLayout.addWidget(colorLabel, 0, 0, 1, 2)
        mainLayout.addWidget(colorButton, 0, 2)
        mainLayout.addLayout(self.main_buttons.makeButtons(), 1, 0, 1, 4)
        
        centralWidget = QtWidgets.QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)
