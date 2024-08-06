from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

import settingsmanager
import port_scanner
import sys

class ScanningTools(QMainWindow):
    def __init__(self):
        super(ScanningTools, self).__init__()
        self.initUI()
       
        self.setWindowTitle("ScanningTools")
        self.setGeometry(360, 170, 1200, 800)
        self.setStyleSheet("background-color: #000066")
        
        self.menu = settingsmanager.MenuBar()
        self.setMenuBar(self.menu)
       
    def initUI(self):
        selectLabel = QLabel("Select a scanner:")
        selectLabel.setFont(QFont("Arial", 30))
        selectLabel.setStyleSheet("color: #FFFF33")
        
        port_scanner = QPushButton("Port Scanner", self)
        port_scanner.setFont(QFont("Arial", 15))
        port_scanner.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        port_scanner.clicked.connect(self.portScanner)
        
        second_tool = QPushButton("Second tool")
        second_tool.setFont(QFont("Arial", 15))
        second_tool.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        second_tool.clicked.connect(self.second_tool)
        
        third_tool = QPushButton("Third tool")
        third_tool.setFont(QFont("Arial", 15))
        third_tool.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        third_tool.clicked.connect(self.third_tool)

        fourth_tool = QPushButton("Fourth tool")
        fourth_tool.setFont(QFont("Arial", 15))
        fourth_tool.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        fourth_tool.clicked.connect(self.fourth_tool)
        
        self.main_buttons = settingsmanager.MainButtons()
        
        mainLayout = QGridLayout()
        mainLayout.setSpacing(20)
        mainLayout.addWidget(selectLabel, 0, 1, 1, 2)
        mainLayout.addWidget(port_scanner, 1, 1)
        mainLayout.addWidget(second_tool, 2, 1)
        mainLayout.addWidget(third_tool, 3, 1)
        mainLayout.addWidget(fourth_tool, 4, 1)
        mainLayout.addLayout(self.main_buttons.makeButtons(), 5, 0, 1, 3)
        
        centralWidget = QtWidgets.QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)

    def portScanner(self):
        self.close()
        self.portscanner = port_scanner.PortScanner()
        self.portscanner.show()
        
    def second_tool(self):
        pass
    
    def third_tool(self):
        pass
    
    def fourth_tool(self):
        pass