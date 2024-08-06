from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

import toolswindow
import settingswindow
import sys

class StartWindow(QMainWindow):
    def __init__(self):
        super(StartWindow, self).__init__()
        self.initUI()
       
    def initUI(self):
            self.setWindowTitle("HackingTools")
            self.setGeometry(360, 170, 1200, 800)
            self.setMinimumSize(800, 600)
            self.setStyleSheet("background-color: #000066")
                    
            welcomeLabel = QLabel(self)
            welcomeLabel.setText("Welcome to HackingTools!!!")
            welcomeLabel.setFont(QFont("Arial", 30))
            welcomeLabel.setStyleSheet("color: #FFFF33;")
            
            startButton = QtWidgets.QPushButton(self)
            startButton.setText("start")
            startButton.setFont(QFont("Arial", 15))
            startButton.setMinimumSize(250, 100)
            startButton.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
            startButton.clicked.connect(self.start_button)
                    
            settingsButton = QtWidgets.QPushButton(self)
            settingsButton.setText("settings")
            settingsButton.setFont(QFont("Arial", 15))
            settingsButton.setMinimumSize(250, 100)
            settingsButton.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
            settingsButton.clicked.connect(self.settings_button)
            
            exitButton = QtWidgets.QPushButton(self)
            exitButton.setText("exit")
            exitButton.setFont(QFont("arial", 15))
            exitButton.setMinimumSize(250, 100)
            exitButton.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
            exitButton.clicked.connect(self.exit_button)
        
            mainLayout = QGridLayout()
            mainLayout.setSpacing(20)
            mainLayout.addWidget(welcomeLabel, 0, 0, 1, 3, QtCore.Qt.AlignCenter)
            mainLayout.addWidget(startButton, 1, 1)
            mainLayout.setSpacing(50)
            mainLayout.addWidget(settingsButton, 2, 1)
            mainLayout.addWidget(exitButton, 3, 1)
        
            centralWidget = QtWidgets.QWidget()
            centralWidget.setLayout(mainLayout)
            self.setCentralWidget(centralWidget)
        
    def start_button(self):
            self.startWindow = toolswindow.ToolsWindow()
            self.startWindow.show()
            self.close()
        
    def settings_button(self):
        self.settings = settingswindow.SettingsWindow()
        self.settings.show()
        self.close()
    
    def exit_button(self):
       sys.exit()
