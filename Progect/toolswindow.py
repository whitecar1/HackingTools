from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

import startwindow
import toolswindow
import settingswindow
import scanning
import bruteforce
import osint
import exploits
import hashs
import monitoring
import passwords
import vpn
import settingsmanager

import sys

class ToolsWindow(QMainWindow):
    def __init__(self):
        super(ToolsWindow, self).__init__()
        self.initUI()
        
        self.setWindowTitle("HackingTools")
        self.setGeometry(360, 170, 1200, 800)
        self.setStyleSheet("background-color: #000066;")
        
        self.menu = settingsmanager.MenuBar()
        self.setMenuBar(self.menu)
        
    def initUI(self):            
        chooseLabel = QLabel("Select the required tool:", self)
        chooseLabel.setFont(QFont("Arial", 30))
        chooseLabel.setStyleSheet("color: #FFFF33;")

        portScanner = QPushButton("Scanning", self)
        portScanner.setFont(QFont("Arial", 15))
        portScanner.setMinimumSize(300, 70)
        portScanner.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        portScanner.clicked.connect(self.scanning_tools)
        
        bruteforcer = QPushButton("BruteForce", self)
        bruteforcer.setFont(QFont("Arial", 15))
        bruteforcer.setMinimumSize(300, 70)
        bruteforcer.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        bruteforcer.clicked.connect(self.bruteforce_tools)

        thirdScanner = QPushButton("OSINT", self)
        thirdScanner.setFont(QFont("Arial", 15))
        thirdScanner.setMinimumSize(300, 70)
        thirdScanner.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        thirdScanner.clicked.connect(self.osint_tools)
        
        fourthScanner = QPushButton("Monitoring", self)
        fourthScanner.setFont(QFont("Arial", 15))
        fourthScanner.setMinimumSize(300, 70)
        fourthScanner.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        fourthScanner.clicked.connect(self.monitoring_tools)

        fifthScanner = QPushButton("VPN", self)
        fifthScanner.setFont(QFont("Arial", 15))
        fifthScanner.setMinimumSize(300, 70)
        fifthScanner.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        fifthScanner.clicked.connect(self.vpn_tools)
        
        sixthScanner = QPushButton("Exploits", self)
        sixthScanner.setFont(QFont("Arial", 15))
        sixthScanner.setMinimumSize(300, 70)
        sixthScanner.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        sixthScanner.clicked.connect(self.exploit_tools)
        
        seventhScanner = QPushButton("Password Checkers", self)
        seventhScanner.setFont(QFont("Arial", 15))
        seventhScanner.setMinimumSize(300, 70)
        seventhScanner.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        seventhScanner.clicked.connect(self.password_checkers)
        
        eightScanner = QPushButton("Hash Crackers", self)
        eightScanner.setFont(QFont("Arial", 15))
        eightScanner.setMinimumSize(300, 70)
        eightScanner.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        eightScanner.clicked.connect(self.hash_crackers)
        
        self.main_buttons = settingsmanager.MainButtons()
        
        mainLayout = QGridLayout()
        mainLayout.setSpacing(30)
        mainLayout.addWidget(chooseLabel, 0, 0, 1, 3, QtCore.Qt.AlignCenter)
        mainLayout.addWidget(portScanner, 1,0)
        mainLayout.addWidget(bruteforcer, 1, 2)
        mainLayout.addWidget(thirdScanner, 2, 0)
        mainLayout.addWidget(fourthScanner, 2, 2)
        mainLayout.addWidget(fifthScanner, 3, 0)
        mainLayout.addWidget(sixthScanner, 3, 2)
        mainLayout.addWidget(seventhScanner, 4, 0)
        mainLayout.addWidget(eightScanner, 4, 2)
        mainLayout.addLayout(self.main_buttons.makeButtons(), 5, 0, 1, 3)
        
        centralWidget = QtWidgets.QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)
    
    def scanning_tools(self):
        self.close()
        self.scanning_tool = scanning.ScanningTools()
        self.scanning_tool.show()
    
    def bruteforce_tools(self):
        self.close()
        self.bruteforce_tool = bruteforce.BruteForceTools()
        self.bruteforce_tool.show()
    
    def osint_tools(self):
        self.close()
        self.osint_tool = osint.OsintTools()
        self.osint_tool.show()
    
    def monitoring_tools(self):
        self.close()
        self.monitoring_tool = monitoring.MonitoringTools()
        self.monitoring_tool.show()
    
    def vpn_tools(self):
        self.close()
        self.vpn_tool = vpn.VpnTools()
        self.vpn_tool.show()
    
    def exploit_tools(self):
        self.close()
        self.exploits_tool = exploits.ExploitsTools()
        self.exploits_tool.show()
    
    def password_checkers(self):
        self.close()
        self.password_tool = passwords.PasswordsTools()
        self.password_tool.show()
    
    def hash_crackers(self):
        self.close()
        self.hashs_tool = hashs.HashsTools()
        self.hashs_tool.show()
