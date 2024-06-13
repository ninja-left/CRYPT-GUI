# Form implementation generated from reading ui file 'modules/design.ui'
#
# Created by: PyQt6 UI code generator 6.7.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PySide6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setWindowModality(QtCore.Qt.WindowModality.NonModal)
        MainWindow.setEnabled(True)
        MainWindow.resize(800, 600)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(800, 600))
        MainWindow.setMaximumSize(QtCore.QSize(800, 600))
        MainWindow.setMouseTracking(False)
        MainWindow.setAcceptDrops(False)
        icon = QtGui.QIcon()
        icon.addPixmap(":/assets/icon.png")
        MainWindow.setWindowIcon(icon)
        MainWindow.setToolButtonStyle(QtCore.Qt.ToolButtonStyle.ToolButtonIconOnly)
        MainWindow.setTabShape(QtWidgets.QTabWidget.TabShape.Rounded)
        MainWindow.setDockNestingEnabled(True)
        MainWindow.setUnifiedTitleAndToolBarOnMac(True)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)
        self.centralwidget.setMinimumSize(QtCore.QSize(800, 578))
        self.centralwidget.setMaximumSize(QtCore.QSize(800, 578))
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(parent=self.centralwidget)
        self.tabWidget.setEnabled(True)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 791, 581))
        self.tabWidget.setMinimumSize(QtCore.QSize(791, 581))
        self.tabWidget.setMaximumSize(QtCore.QSize(791, 581))
        self.tabWidget.setAutoFillBackground(True)
        self.tabWidget.setTabPosition(QtWidgets.QTabWidget.TabPosition.North)
        self.tabWidget.setTabShape(QtWidgets.QTabWidget.TabShape.Rounded)
        self.tabWidget.setElideMode(QtCore.Qt.TextElideMode.ElideNone)
        self.tabWidget.setDocumentMode(False)
        self.tabWidget.setObjectName("tabWidget")
        self.inputTab = QtWidgets.QWidget()
        self.inputTab.setMinimumSize(QtCore.QSize(787, 550))
        self.inputTab.setMaximumSize(QtCore.QSize(787, 550))
        self.inputTab.setObjectName("inputTab")
        self.verticalLayoutWidget = QtWidgets.QWidget(parent=self.inputTab)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(20, 90, 751, 441))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.inputText = QtWidgets.QPlainTextEdit(parent=self.verticalLayoutWidget)
        self.inputText.setMinimumSize(QtCore.QSize(749, 439))
        self.inputText.setMaximumSize(QtCore.QSize(749, 449))
        self.inputText.setBackgroundVisible(False)
        self.inputText.setObjectName("inputText")
        self.verticalLayout.addWidget(self.inputText)
        self.btnPaste = QtWidgets.QPushButton(parent=self.inputTab)
        self.btnPaste.setGeometry(QtCore.QRect(300, 50, 201, 25))
        self.btnPaste.setMinimumSize(QtCore.QSize(201, 25))
        self.btnPaste.setMaximumSize(QtCore.QSize(201, 25))
        icon = QtGui.QIcon.fromTheme("QIcon::ThemeIcon::EditPaste")
        self.btnPaste.setIcon(icon)
        self.btnPaste.setObjectName("btnPaste")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/assets/Login.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.tabWidget.addTab(self.inputTab, icon1, "")
        self.setupTab = QtWidgets.QWidget()
        self.setupTab.setMinimumSize(QtCore.QSize(787, 550))
        self.setupTab.setMaximumSize(QtCore.QSize(787, 550))
        self.setupTab.setObjectName("setupTab")
        self.btnEncode = QtWidgets.QPushButton(parent=self.setupTab)
        self.btnEncode.setEnabled(False)
        self.btnEncode.setGeometry(QtCore.QRect(650, 510, 121, 25))
        self.btnEncode.setMinimumSize(QtCore.QSize(121, 25))
        self.btnEncode.setMaximumSize(QtCore.QSize(121, 25))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/assets/Locked.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.btnEncode.setIcon(icon2)
        self.btnEncode.setObjectName("btnEncode")
        self.btnDecode = QtWidgets.QPushButton(parent=self.setupTab)
        self.btnDecode.setEnabled(False)
        self.btnDecode.setGeometry(QtCore.QRect(520, 510, 121, 25))
        self.btnDecode.setMinimumSize(QtCore.QSize(121, 25))
        self.btnDecode.setMaximumSize(QtCore.QSize(121, 25))
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/assets/Unlocked.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.btnDecode.setIcon(icon3)
        self.btnDecode.setObjectName("btnDecode")
        self.operationMode = QtWidgets.QComboBox(parent=self.setupTab)
        self.operationMode.setGeometry(QtCore.QRect(290, 50, 231, 25))
        self.operationMode.setMinimumSize(QtCore.QSize(231, 25))
        self.operationMode.setMaximumSize(QtCore.QSize(231, 25))
        self.operationMode.setObjectName("operationMode")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.operationMode.addItem("")
        self.label = QtWidgets.QLabel(parent=self.setupTab)
        self.label.setGeometry(QtCore.QRect(340, 10, 131, 31))
        self.label.setMinimumSize(QtCore.QSize(131, 17))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.label.setFont(font)
        self.label.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.NoTextInteraction)
        self.label.setObjectName("label")
        self.btnBruteForce = QtWidgets.QPushButton(parent=self.setupTab)
        self.btnBruteForce.setEnabled(False)
        self.btnBruteForce.setGeometry(QtCore.QRect(390, 510, 121, 25))
        self.btnBruteForce.setMinimumSize(QtCore.QSize(121, 25))
        self.btnBruteForce.setMaximumSize(QtCore.QSize(121, 25))
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(":/assets/Insecure_outline.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.btnBruteForce.setIcon(icon4)
        self.btnBruteForce.setAutoDefault(False)
        self.btnBruteForce.setFlat(False)
        self.btnBruteForce.setObjectName("btnBruteForce")
        self.formLayoutWidget = QtWidgets.QWidget(parent=self.setupTab)
        self.formLayoutWidget.setGeometry(QtCore.QRect(10, 100, 771, 391))
        self.formLayoutWidget.setObjectName("formLayoutWidget")
        self.formLayout = QtWidgets.QFormLayout(self.formLayoutWidget)
        self.formLayout.setContentsMargins(0, 0, 0, 0)
        self.formLayout.setObjectName("formLayout")
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(":/assets/Configure.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.tabWidget.addTab(self.setupTab, icon5, "")
        self.outputTab = QtWidgets.QWidget()
        self.outputTab.setMinimumSize(QtCore.QSize(787, 550))
        self.outputTab.setMaximumSize(QtCore.QSize(787, 550))
        self.outputTab.setObjectName("outputTab")
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(parent=self.outputTab)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(20, 90, 751, 441))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.outputText = QtWidgets.QPlainTextEdit(parent=self.verticalLayoutWidget_2)
        self.outputText.setMinimumSize(QtCore.QSize(749, 439))
        self.outputText.setMaximumSize(QtCore.QSize(749, 439))
        self.outputText.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.outputText.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.outputText.setUndoRedoEnabled(False)
        self.outputText.setPlainText("")
        self.outputText.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.NoTextInteraction)
        self.outputText.setBackgroundVisible(False)
        self.outputText.setObjectName("outputText")
        self.verticalLayout_2.addWidget(self.outputText)
        self.btnCopy = QtWidgets.QPushButton(parent=self.outputTab)
        self.btnCopy.setGeometry(QtCore.QRect(300, 50, 201, 25))
        self.btnCopy.setMinimumSize(QtCore.QSize(201, 25))
        self.btnCopy.setMaximumSize(QtCore.QSize(201, 25))
        icon = QtGui.QIcon.fromTheme("QIcon::ThemeIcon::EditCopy")
        self.btnCopy.setIcon(icon)
        self.btnCopy.setDefault(False)
        self.btnCopy.setFlat(False)
        self.btnCopy.setObjectName("btnCopy")
        icon6 = QtGui.QIcon()
        icon6.addPixmap(QtGui.QPixmap(":/assets/Logout.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.tabWidget.addTab(self.outputTab, icon6, "")
        self.aboutTab = QtWidgets.QWidget()
        self.aboutTab.setObjectName("aboutTab")
        self.verticalLayoutWidget_3 = QtWidgets.QWidget(parent=self.aboutTab)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(10, 10, 771, 521))
        self.verticalLayoutWidget_3.setObjectName("verticalLayoutWidget_3")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label_2 = QtWidgets.QLabel(parent=self.verticalLayoutWidget_3)
        font = QtGui.QFont()
        font.setPointSize(26)
        self.label_2.setFont(font)
        self.label_2.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter|QtCore.Qt.AlignmentFlag.AlignTop)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_3.addWidget(self.label_2)
        self.label_3 = QtWidgets.QLabel(parent=self.verticalLayoutWidget_3)
        self.label_3.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.verticalLayout_3.addWidget(self.label_3)
        self.textBrowser = QtWidgets.QTextBrowser(parent=self.verticalLayoutWidget_3)
        self.textBrowser.setOpenLinks(False)
        self.textBrowser.setObjectName("textBrowser")
        self.verticalLayout_3.addWidget(self.textBrowser)
        icon = QtGui.QIcon()
        icon.addPixmap(":/assets/icon.png")
        self.tabWidget.addTab(self.aboutTab, icon, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.actionCopy = QtGui.QAction(parent=MainWindow)
        icon = QtGui.QIcon.fromTheme("QIcon::ThemeIcon::EditCopy")
        self.actionCopy.setIcon(icon)
        self.actionCopy.setMenuRole(QtGui.QAction.MenuRole.NoRole)
        self.actionCopy.setObjectName("actionCopy")
        self.actionPaste = QtGui.QAction(parent=MainWindow)
        icon = QtGui.QIcon.fromTheme("QIcon::ThemeIcon::EditPaste")
        self.actionPaste.setIcon(icon)
        self.actionPaste.setMenuRole(QtGui.QAction.MenuRole.NoRole)
        self.actionPaste.setObjectName("actionPaste")
        self.actionEncode = QtGui.QAction(parent=MainWindow)
        self.actionEncode.setMenuRole(QtGui.QAction.MenuRole.NoRole)
        self.actionEncode.setObjectName("actionEncode")
        self.actionDecode = QtGui.QAction(parent=MainWindow)
        self.actionDecode.setMenuRole(QtGui.QAction.MenuRole.NoRole)
        self.actionDecode.setObjectName("actionDecode")
        self.actionBrute = QtGui.QAction(parent=MainWindow)
        self.actionBrute.setMenuRole(QtGui.QAction.MenuRole.NoRole)
        self.actionBrute.setObjectName("actionBrute")
        self.actionOperationChanged = QtGui.QAction(parent=MainWindow)
        self.actionOperationChanged.setObjectName("actionOperationChanged")

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(3)
        self.operationMode.setCurrentIndex(0)
        self.btnCopy.clicked.connect(self.actionCopy.trigger) # type: ignore
        self.btnPaste.clicked.connect(self.actionPaste.trigger) # type: ignore
        self.btnEncode.clicked.connect(self.actionEncode.trigger) # type: ignore
        self.btnDecode.clicked.connect(self.actionDecode.trigger) # type: ignore
        self.btnBruteForce.clicked.connect(self.actionBrute.trigger) # type: ignore
        self.operationMode.currentIndexChanged['int'].connect(self.actionOperationChanged.trigger) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        MainWindow.setTabOrder(self.tabWidget, self.btnPaste)
        MainWindow.setTabOrder(self.btnPaste, self.inputText)
        MainWindow.setTabOrder(self.inputText, self.operationMode)
        MainWindow.setTabOrder(self.operationMode, self.btnEncode)
        MainWindow.setTabOrder(self.btnEncode, self.btnDecode)
        MainWindow.setTabOrder(self.btnDecode, self.btnBruteForce)
        MainWindow.setTabOrder(self.btnBruteForce, self.btnCopy)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "CRYPT"))
        MainWindow.setToolTip(_translate("MainWindow", "A Collection of Tools"))
        self.inputTab.setAccessibleName(_translate("MainWindow", "&Input"))
        self.inputText.setPlaceholderText(_translate("MainWindow", "Input data to be encoded/decoded."))
        self.btnPaste.setText(_translate("MainWindow", "Paste from Clipboard"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.inputTab), _translate("MainWindow", "Input"))
        self.btnEncode.setText(_translate("MainWindow", "Encode/Encrypt"))
        self.btnDecode.setText(_translate("MainWindow", "Decode/Decrypt"))
        self.operationMode.setCurrentText(_translate("MainWindow", "None"))
        self.operationMode.setPlaceholderText(_translate("MainWindow", "No Operation Chosen"))
        self.operationMode.setItemText(0, _translate("MainWindow", "None"))
        self.operationMode.setItemText(1, _translate("MainWindow", "Base16"))
        self.operationMode.setItemText(2, _translate("MainWindow", "Base32"))
        self.operationMode.setItemText(3, _translate("MainWindow", "Base85"))
        self.operationMode.setItemText(4, _translate("MainWindow", "Base64"))
        self.operationMode.setItemText(5, _translate("MainWindow", "Caesar Cipher"))
        self.operationMode.setItemText(6, _translate("MainWindow", "Morse Code"))
        self.operationMode.setItemText(7, _translate("MainWindow", "Baconian Cipher"))
        self.operationMode.setItemText(8, _translate("MainWindow", "Vigenere Cipher"))
        self.operationMode.setItemText(9, _translate("MainWindow", "MD5"))
        self.operationMode.setItemText(10, _translate("MainWindow", "MD5 CRYPT"))
        self.operationMode.setItemText(11, _translate("MainWindow", "SHA256"))
        self.operationMode.setItemText(12, _translate("MainWindow", "SHA256 CRYPT"))
        self.operationMode.setItemText(13, _translate("MainWindow", "SHA512"))
        self.operationMode.setItemText(14, _translate("MainWindow", "SHA512 CRYPT"))
        self.operationMode.setItemText(15, _translate("MainWindow", "bCrypt"))
        self.operationMode.setItemText(16, _translate("MainWindow", "Argon2"))
        self.operationMode.setItemText(17, _translate("MainWindow", "NT Hash"))
        self.operationMode.setItemText(18, _translate("MainWindow", "PBKDF2 SHA256"))
        self.operationMode.setItemText(19, _translate("MainWindow", "PBKDF2 SHA512"))
        self.label.setText(_translate("MainWindow", "Operation"))
        self.btnBruteForce.setText(_translate("MainWindow", "Brute Force"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.setupTab), _translate("MainWindow", "Setup"))
        self.outputText.setPlaceholderText(_translate("MainWindow", "Decoded/Encoded data would be displayed here."))
        self.btnCopy.setText(_translate("MainWindow", "Copy to Clipboard"))
        self.btnCopy.setShortcut(_translate("MainWindow", "Ctrl+Shift+C"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.outputTab), _translate("MainWindow", "Output"))
        self.label_2.setText(_translate("MainWindow", "CRYPT GUI"))
        self.label_3.setText(_translate("MainWindow", "Licenses"))
        self.textBrowser.setDocumentTitle(_translate("MainWindow", "GNU General Public License v3.0"))
        self.textBrowser.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><title>GNU General Public License v3.0</title><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"hr { height: 1px; border-width: 0; }\n"
"li.unchecked::marker { content: \"\\2610\"; }\n"
"li.checked::marker { content: \"\\2612\"; }\n"
"</style></head><body style=\" font-family:\'Sans Serif\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">CRYPT GUI, A Collection of tools, is licensed under GPL v3.0 Copyright (c) 2024 Ninja Left</p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">CRYPT was built using Python 3.11, Qt Designer &amp; Pyside6.</p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Some functions used in this software are from <a href=\"https://github.com/TheAlgorithms/Python\"><span style=\" text-decoration: underline; color:#b85b6a;\">This Repository</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" color:#ffffff;\">and are licensed under MIT Copyright (c) 2016-2024 TheAlgorithms and contributors.</span></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'monospace\'; color:#ffffff;\">Icons:</span></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/configuration_9780271\"><span style=\" text-decoration: underline; color:#b85b6a;\">Configure icon by afif fudin - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/login_5729989\"><span style=\" text-decoration: underline; color:#b85b6a;\">Login icon by FR_Media - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/logout_5729988\"><span style=\" text-decoration: underline; color:#b85b6a;\">Logout icon by FR_Media - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/lock_2549910\"><span style=\" text-decoration: underline; color:#b85b6a;\">Locked icon by Aswell Studio - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/unlock_2549951\"><span style=\" text-decoration: underline; color:#b85b6a;\">Unlocked icon by Aswell Studio - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/unsecure_5690981\"><span style=\" text-decoration: underline; color:#b85b6a;\">Unsecure icon by juicy_fish - Flaticon</span></a></p></body></html>"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.aboutTab), _translate("MainWindow", "About"))
        self.actionCopy.setText(_translate("MainWindow", "Copy"))
        self.actionCopy.setShortcut(_translate("MainWindow", "Ctrl+Shift+C"))
        self.actionPaste.setText(_translate("MainWindow", "Paste"))
        self.actionPaste.setShortcut(_translate("MainWindow", "Ctrl+Shift+V"))
        self.actionEncode.setText(_translate("MainWindow", "Encode"))
        self.actionDecode.setText(_translate("MainWindow", "Decode"))
        self.actionBrute.setText(_translate("MainWindow", "Brute"))
        self.actionOperationChanged.setText(_translate("MainWindow", "OperationChanged"))
        self.actionOperationChanged.setToolTip(_translate("MainWindow", "OperationChanged"))
