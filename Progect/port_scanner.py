from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

import settingsmanager
import sys

import socket
import colored

targetIP = "0.0.0.0"
targetPort = "0"
isStop = False

class PortScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
        self.setWindowTitle("PortScanner")
        self.setGeometry(360, 170, 1200, 800)
        self.setStyleSheet("background-color: #000066")
        
        self.menu = settingsmanager.MenuBar()
        self.setMenuBar(self.menu)
        
    def initUI(self):
        manualLabel = QLabel("Read our manual before using please")
        manualLabel.setStyleSheet("""
                                  font: bold italic;
                                  font-size: 30px;
                                  color: green; 
                                  """)
        
        targetLabel = QLabel("Select a target IP:")
        targetLabel.setFont(QFont("Arial", 15))
        targetLabel.setStyleSheet("color: #FFFF33")
        
        self.targetEdit = QLineEdit()
        self.targetEdit.setMaxLength(31)
        self.targetEdit.setStyleSheet("background-color: white; color: red;")
        
        portLabel = QLabel("Select a target port:")
        portLabel.setFont(QFont("Arial", 15))
        portLabel.setStyleSheet("color: #FFFF33")

        self.portEdit = QLineEdit()
        self.portEdit.setMaxLength(11)
        self.portEdit.setStyleSheet("background-color: white; color: red;")
        
        dataButton = QPushButton("Show target Ip and Port")
        dataButton.setFont(QFont("Arial", 15))
        dataButton.setStyleSheet("background-color: #CC0000; color: #708090; border-radius: 10px; padding: 10px 20px;")
        dataButton.clicked.connect(self.showTarget)

        saveButton = QPushButton("Save to file")
        saveButton.setFont(QFont("Arial", 15))
        saveButton.setStyleSheet("background-color: #CC0000; color: #FFD700;")
        saveButton.clicked.connect(self.save_to_file)
        
        scanningButton = QPushButton("Start scanning")
        scanningButton.setFont(QFont("Arial", 15))
        scanningButton.setStyleSheet("background-color: #FF00FF; color: #FFD700;")
        scanningButton.clicked.connect(self.startScanning)
        
        stopButton = QPushButton("Stop scanning")
        stopButton.setFont(QFont("Arial", 15))
        stopButton.setStyleSheet("background-color: #CC0000; color: #FFD700;")
        stopButton.clicked.connect(self.stopScanning)
    
        self.textEdit = QTextEdit()
        self.textEdit.setReadOnly(True)
        self.textEdit.setStyleSheet("background-color: white; color: red;")
    
        self.main_buttons = settingsmanager.MainButtons()
        
        mainLayout = QGridLayout()
        mainLayout.addWidget(manualLabel, 0, 1, 1, 2)
        mainLayout.addWidget(targetLabel, 1, 0)
        mainLayout.addWidget(self.targetEdit, 1, 1)
        mainLayout.addWidget(portLabel, 2, 0)
        mainLayout.addWidget(self.portEdit, 2, 1)
        mainLayout.addWidget(dataButton, 1, 2, 2, 1)
        mainLayout.addWidget(saveButton, 3, 0)
        mainLayout.addWidget(scanningButton, 3, 1)
        mainLayout.addWidget(stopButton, 3, 2)
        mainLayout.addWidget(self.textEdit, 4, 0, 1, 3)
        mainLayout.addLayout(self.main_buttons.makeButtons(), 5, 0, 1, 3)
        
        centralWidget = QtWidgets.QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)

    def TargetIpChanged(self):       
        targetIP = self.targetEdit.text()
        if targetIP == "":
            return "0.0.0.0"
        return targetIP
        
    def TargetPortChanged(self):
        targetPort = self.portEdit.text()
        if targetPort == "":
            return "1-1024"
        elif targetPort == "*":
            return "1-65535"
        else:
            return targetPort
        
    def showTarget(self):
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Target")
        msg_box.setText(f"Target IPs:\t{self.TargetIpChanged()}\n\nTarget ports:\t{self.TargetPortChanged()}")
        msg_box.setFont(QFont("Arial", 20))
        msg_box.setGeometry(700, 400, 700, 750)
        msg_box.setStyleSheet("background-color: #000066; color: #FFFF33")
        msg_box.exec_()
    
    def save_to_file(self):
        filename, _ = QFileDialog.getSaveFileName(None, "Save file", '.', "Text files (*.txt);;All files(*.*)")
        
        if filename:
            with open(filename, "w") as file:
                file.write(self.textEdit.toPlainText())
        
    def startScanning(self):
        self.textEdit.clear()
        self.textEdit.append(f"<p style='font-size:25px; color: red;'>Target IPs: {self.TargetIpChanged()}</p>")
        self.textEdit.append(f"<p style='font-size:25px; color: red;'>Target ports: {self.TargetPortChanged()}</p><p></p>")
        self.textEdit.append("<p style='font-size: 20px; color: blue;'>Start scanning</p><p></p>")
        self.PortScanner()
    
    def stopScanning(self):
        global isStop
        isStop = True
        print(isStop)
        
    def ScanPort(self, target:str, ports:str):
        self.textEdit.append('<p style="font-size:18px; color: green;">Port    Result</p>')
        if "-" in ports:
            ports = ports.split("-")
            for port in range(int(ports[0]), int(ports[1])+1):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((target, port))
                    self.textEdit.append(f"<p style='font-size:18px; color: green;'>{port}\t\topen</p>")
                    sock.close()
                except:
                    pass
        else:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((target, ports))
                self.textEdit.append(f"<p style='font-size:18px; color: green;>{port}open</p>")
                sock.close()
            except:
                pass
        
    def PortScanner(self):
        target_ips = self.TargetIpChanged()
        target_ports = self.TargetPortChanged()
        if "," in target_ips:
            for target in target_ips.split(","):
                try:
                    self.textEdit.append(f"<h3>Scanning: {target}</h3>")
                    self.ScanPort(target, target_ports)
                except:
                    pass
        elif "-" in target_ips:
            for target in target_ips.split('-'):
                try:
                    self.textEdit.append(f"<h3>Scanning: {target}</h3>")
                    self.ScanPort(target, target_ports)
                except:
                    pass
