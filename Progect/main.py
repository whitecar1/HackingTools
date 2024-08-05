from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

from startwindow import StartWindow

import sys

if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = StartWindow()
    mainWindow.show()
    sys.exit(app.exec_())
