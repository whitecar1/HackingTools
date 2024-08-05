from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

import startwindow
import settingswindow
import sys
import subprocess

class MenuBar(QMenuBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.createMenus()
        
    def createMenus(self):    
        self.setStyleSheet("background-color: white; color: red;")
        fileMenu = self.addMenu("&File")
        
        exitAction = QAction("&Exit", self)
        exitAction.setShortcut("Ctrl+Q")
        exitAction.setStatusTip("Exit application")
        exitAction.triggered.connect(self.quitApplication)
        fileMenu.addAction(exitAction)
        
        editMenu = self.addMenu("&Edit")
        
        open_settings = QAction("Open settings", self)
        open_settings.setShortcut("Ctrl+S")
        open_settings.triggered.connect(self.open_settings_menu)
        
        editMenu.addAction(open_settings)
        
        helpMenu = self.addMenu("&Help")  
        
        help_action = QAction("Support", self)
        help_action.setShortcut("f1")
        help_action.triggered.connect(self.helpAction)
        
        helpMenu.addAction(help_action)
        
        aboutMenu = self.addMenu("&About")
        
        about_dev = QAction("About developer", self)
        about_dev.setShortcut("Ctrl+A")
        about_dev.setStatusTip("About developer")
        about_dev.triggered.connect(self.open_my_site)
        aboutMenu.addAction(about_dev)
           
    
    def quitApplication(self):
        exitButton = QMessageBox.question(self, "Exit", "Do you want to leave the application?", QMessageBox.Yes, QMessageBox.No)
        if exitButton == QMessageBox.Yes:
            sys.exit()
            
    def open_my_site(self):
        pass
    
    def helpAction(self):
        pass
    
    def open_settings_menu(self):
        pass
            
class MainButtons(QPushButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.makeButtons()
        
    def makeButtons(self):    
        horisontalLayout = QHBoxLayout()
        
        terminalButton = QPushButton("Terminal", self)
        terminalButton.setFont(QFont("Arial", 15))
        terminalButton.setStyleSheet("background-color: #FFFF33; color: #0000FF;")
        terminalButton.clicked.connect(self.terminal)
        
        backButton = QPushButton("Back to start window", self)
        backButton.setFont(QFont("Arial", 15))
        backButton.setStyleSheet("background-color: #FFFF33; color: #0000FF;")
        backButton.clicked.connect(self.return_to_main_window)
        
        exitButton = QPushButton("Exit", self)
        exitButton.setFont(QFont("Arial", 15))
        exitButton.setStyleSheet("background-color: #FFFF33; color: #0000FF;")
        exitButton.clicked.connect(self.exit_button)
        
        horisontalLayout.addWidget(terminalButton)
        horisontalLayout.addWidget(backButton)
        horisontalLayout.addWidget(exitButton)
        
        return horisontalLayout
        
    def terminal(self):
        pass
                
    def return_to_main_window(self):
        self.close()
        self.mainWindow = startwindow.StartWindow()
        self.mainWindow.show()
        
    def exit_button(self):
        exit = QMessageBox.question(self, "Exit", 'Do you want to leave the application?', QMessageBox.Yes, QMessageBox.No) 
        if exit == QMessageBox.Yes:
            sys.exit()
