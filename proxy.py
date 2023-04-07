# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'proxy.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
import vpn_pro

__ver__ = vpn_pro.__ver__


def click_on(button: QtWidgets.QPushButton, *args):
    try:
        print(*args)
        vpn_pro.ProxyChange(*args)
        button.setText("Disable Proxy")
    except AssertionError as error:
        print("Not correct params, proxy was not changed.")


def click_off(button: QtWidgets.QPushButton):
    vpn_pro.ProxyOff()
    button.setText("Change Proxy")


protocol = 'http'


class Ui_MainWindow(object):
    global isProxy

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setFixedSize(400, 380)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(130, 170, 151, 41))
        self.pushButton.setObjectName("pushButton")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(95, 76, 131, 22))
        self.lineEdit.setInputMask("")
        self.lineEdit.setText("")
        self.lineEdit.setObjectName("lineEdit")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(230, 70, 51, 31))
        self.label.setObjectName("label")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(235, 76, 41, 22))
        self.lineEdit_2.setInputMask("")
        self.lineEdit_2.setText("")
        self.lineEdit_2.setMaxLength(4)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_3.setGeometry(QtCore.QRect(70, 290, 131, 22))
        self.lineEdit_3.setInputMask("")
        self.lineEdit_3.setText("")
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.lineEdit_4 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_4.setGeometry(QtCore.QRect(220, 290, 131, 22))
        self.lineEdit_4.setInputMask("")
        self.lineEdit_4.setText("")
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.horizontalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(55, 116, 291, 41))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.radioButton_3 = QtWidgets.QRadioButton(self.horizontalLayoutWidget)
        self.radioButton_3.setObjectName("radioButton_3")
        self.horizontalLayout.addWidget(self.radioButton_3)
        self.radioButton_2 = QtWidgets.QRadioButton(self.horizontalLayoutWidget)
        self.radioButton_2.setObjectName("radioButton_2")
        self.horizontalLayout.addWidget(self.radioButton_2)
        self.radioButton = QtWidgets.QRadioButton(self.horizontalLayoutWidget)
        self.radioButton.setObjectName("radioButton")
        self.radioButton_3.setChecked(True)
        self.horizontalLayout.addWidget(self.radioButton)
        self.radioButton_4 = QtWidgets.QRadioButton(self.horizontalLayoutWidget)
        self.radioButton_4.setObjectName("radioButton_4")
        self.horizontalLayout.addWidget(self.radioButton_4)
        self.lineEdit_5 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_5.setGeometry(QtCore.QRect(150, 240, 121, 20))
        self.lineEdit_5.setInputMask("")
        self.lineEdit_5.setText("")
        self.lineEdit_5.setObjectName("lineEdit_5")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        def onClicked(text):
            global protocol
            protocol = text

        self.pushButton.clicked.connect(
            lambda: click_on(self.pushButton, protocol, self.lineEdit.text(), self.lineEdit_2.text(),
                             self.lineEdit_3.text(), self.lineEdit_4.text(),
                             self.lineEdit_5.text()) if not vpn_pro.ProxyCheck() else click_off(self.pushButton))

        self.radioButton.toggled.connect(lambda: onClicked('ftp'))
        self.radioButton_2.toggled.connect(lambda: onClicked('http'))
        self.radioButton_3.toggled.connect(lambda: onClicked('https'))
        self.radioButton_4.toggled.connect(lambda: onClicked('socks'))

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Proxy Changer v{ver}".format(ver=vpn_pro.__ver__)))
        self.pushButton.setText(_translate("MainWindow", "Change Proxy"))
        self.lineEdit.setPlaceholderText(_translate("MainWindow", "192.0.0.1"))
        self.label.setText(_translate("MainWindow", ":"))
        self.lineEdit_2.setPlaceholderText(_translate("MainWindow", "8888"))
        self.lineEdit_3.setPlaceholderText(_translate("MainWindow", "Login"))
        self.lineEdit_4.setPlaceholderText(_translate("MainWindow", "Password"))
        self.radioButton_3.setText(_translate("MainWindow", "Https"))
        self.radioButton_2.setText(_translate("MainWindow", "Http"))
        self.radioButton.setText(_translate("MainWindow", "Ftp"))
        self.radioButton_4.setText(_translate("MainWindow", "Socks 5"))
        self.lineEdit_5.setPlaceholderText(_translate("MainWindow", "Non proxies"))


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
