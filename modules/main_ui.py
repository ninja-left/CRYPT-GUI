# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'design.ui'
##
## Created by: Qt User Interface Compiler version 6.7.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QAction, QBrush, QColor, QConicalGradient,
    QCursor, QFont, QFontDatabase, QGradient,
    QIcon, QImage, QKeySequence, QLinearGradient,
    QPainter, QPalette, QPixmap, QRadialGradient,
    QTransform)
from PySide6.QtWidgets import (QApplication, QComboBox, QFormLayout, QLabel,
    QMainWindow, QPlainTextEdit, QPushButton, QSizePolicy,
    QTabWidget, QTextBrowser, QVBoxLayout, QWidget)
import resources_rc

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.setWindowModality(Qt.WindowModality.NonModal)
        MainWindow.setEnabled(True)
        MainWindow.resize(800, 600)
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QSize(800, 600))
        MainWindow.setMaximumSize(QSize(800, 600))
        MainWindow.setMouseTracking(False)
        MainWindow.setAcceptDrops(False)
        icon = QIcon()
        icon.addFile(u":/assets/icon.png", QSize(), QIcon.Normal, QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        MainWindow.setTabShape(QTabWidget.TabShape.Rounded)
        MainWindow.setDockNestingEnabled(True)
        MainWindow.setUnifiedTitleAndToolBarOnMac(True)
        self.actionCopy = QAction(MainWindow)
        self.actionCopy.setObjectName(u"actionCopy")
        icon1 = QIcon()
        if QIcon.hasThemeIcon(QIcon.ThemeIcon.EditCopy):
            icon1 = QIcon.fromTheme(QIcon.ThemeIcon.EditCopy)
        else:
            icon1.addFile(u"../../../.designer/backup", QSize(), QIcon.Normal, QIcon.Off)

        self.actionCopy.setIcon(icon1)
        self.actionCopy.setMenuRole(QAction.MenuRole.NoRole)
        self.actionPaste = QAction(MainWindow)
        self.actionPaste.setObjectName(u"actionPaste")
        icon2 = QIcon()
        if QIcon.hasThemeIcon(QIcon.ThemeIcon.EditPaste):
            icon2 = QIcon.fromTheme(QIcon.ThemeIcon.EditPaste)
        else:
            icon2.addFile(u"../../../.designer/backup", QSize(), QIcon.Normal, QIcon.Off)

        self.actionPaste.setIcon(icon2)
        self.actionPaste.setMenuRole(QAction.MenuRole.NoRole)
        self.actionEncode = QAction(MainWindow)
        self.actionEncode.setObjectName(u"actionEncode")
        self.actionEncode.setMenuRole(QAction.MenuRole.NoRole)
        self.actionDecode = QAction(MainWindow)
        self.actionDecode.setObjectName(u"actionDecode")
        self.actionDecode.setMenuRole(QAction.MenuRole.NoRole)
        self.actionBrute = QAction(MainWindow)
        self.actionBrute.setObjectName(u"actionBrute")
        self.actionBrute.setMenuRole(QAction.MenuRole.NoRole)
        self.actionOperationChanged = QAction(MainWindow)
        self.actionOperationChanged.setObjectName(u"actionOperationChanged")
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)
        self.centralwidget.setMinimumSize(QSize(800, 578))
        self.centralwidget.setMaximumSize(QSize(800, 578))
        self.tabWidget = QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName(u"tabWidget")
        self.tabWidget.setEnabled(True)
        self.tabWidget.setGeometry(QRect(0, 0, 791, 581))
        self.tabWidget.setMinimumSize(QSize(791, 581))
        self.tabWidget.setMaximumSize(QSize(791, 581))
        self.tabWidget.setAutoFillBackground(True)
        self.tabWidget.setTabPosition(QTabWidget.TabPosition.North)
        self.tabWidget.setTabShape(QTabWidget.TabShape.Rounded)
        self.tabWidget.setDocumentMode(False)
        self.tabWidget.setTabsClosable(False)
        self.tabWidget.setMovable(True)
        self.tabWidget.setTabBarAutoHide(True)
        self.inputTab = QWidget()
        self.inputTab.setObjectName(u"inputTab")
        self.inputTab.setMinimumSize(QSize(787, 550))
        self.inputTab.setMaximumSize(QSize(787, 550))
        self.verticalLayoutWidget = QWidget(self.inputTab)
        self.verticalLayoutWidget.setObjectName(u"verticalLayoutWidget")
        self.verticalLayoutWidget.setGeometry(QRect(20, 90, 751, 441))
        self.verticalLayout = QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.inputText = QPlainTextEdit(self.verticalLayoutWidget)
        self.inputText.setObjectName(u"inputText")
        self.inputText.setMinimumSize(QSize(749, 439))
        self.inputText.setMaximumSize(QSize(749, 449))
        self.inputText.setBackgroundVisible(False)

        self.verticalLayout.addWidget(self.inputText)

        self.btnPaste = QPushButton(self.inputTab)
        self.btnPaste.setObjectName(u"btnPaste")
        self.btnPaste.setGeometry(QRect(300, 50, 201, 25))
        self.btnPaste.setMinimumSize(QSize(201, 25))
        self.btnPaste.setMaximumSize(QSize(201, 25))
        self.btnPaste.setIcon(icon2)
        icon3 = QIcon()
        icon3.addFile(u":/assets/Login.png", QSize(), QIcon.Normal, QIcon.Off)
        self.tabWidget.addTab(self.inputTab, icon3, "")
        self.setupTab = QWidget()
        self.setupTab.setObjectName(u"setupTab")
        self.setupTab.setMinimumSize(QSize(787, 550))
        self.setupTab.setMaximumSize(QSize(787, 550))
        self.btnEncode = QPushButton(self.setupTab)
        self.btnEncode.setObjectName(u"btnEncode")
        self.btnEncode.setEnabled(False)
        self.btnEncode.setGeometry(QRect(650, 510, 121, 25))
        self.btnEncode.setMinimumSize(QSize(121, 25))
        self.btnEncode.setMaximumSize(QSize(121, 25))
        icon4 = QIcon()
        icon4.addFile(u":/assets/Locked.png", QSize(), QIcon.Normal, QIcon.Off)
        self.btnEncode.setIcon(icon4)
        self.btnDecode = QPushButton(self.setupTab)
        self.btnDecode.setObjectName(u"btnDecode")
        self.btnDecode.setEnabled(False)
        self.btnDecode.setGeometry(QRect(520, 510, 121, 25))
        self.btnDecode.setMinimumSize(QSize(121, 25))
        self.btnDecode.setMaximumSize(QSize(121, 25))
        icon5 = QIcon()
        icon5.addFile(u":/assets/Unlocked.png", QSize(), QIcon.Normal, QIcon.Off)
        self.btnDecode.setIcon(icon5)
        self.operationMode = QComboBox(self.setupTab)
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
        self.operationMode.setObjectName(u"operationMode")
        self.operationMode.setGeometry(QRect(290, 50, 231, 25))
        self.operationMode.setMinimumSize(QSize(231, 25))
        self.operationMode.setMaximumSize(QSize(231, 25))
        self.label = QLabel(self.setupTab)
        self.label.setObjectName(u"label")
        self.label.setGeometry(QRect(340, 10, 131, 31))
        self.label.setMinimumSize(QSize(131, 17))
        font = QFont()
        font.setPointSize(16)
        self.label.setFont(font)
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self.btnBruteForce = QPushButton(self.setupTab)
        self.btnBruteForce.setObjectName(u"btnBruteForce")
        self.btnBruteForce.setEnabled(False)
        self.btnBruteForce.setGeometry(QRect(390, 510, 121, 25))
        self.btnBruteForce.setMinimumSize(QSize(121, 25))
        self.btnBruteForce.setMaximumSize(QSize(121, 25))
        icon6 = QIcon()
        icon6.addFile(u":/assets/Crack.png", QSize(), QIcon.Normal, QIcon.Off)
        self.btnBruteForce.setIcon(icon6)
        self.btnBruteForce.setAutoDefault(False)
        self.btnBruteForce.setFlat(False)
        self.formLayoutWidget = QWidget(self.setupTab)
        self.formLayoutWidget.setObjectName(u"formLayoutWidget")
        self.formLayoutWidget.setGeometry(QRect(20, 90, 771, 391))
        self.formLayout = QFormLayout(self.formLayoutWidget)
        self.formLayout.setObjectName(u"formLayout")
        self.formLayout.setContentsMargins(0, 0, 0, 0)
        icon7 = QIcon()
        icon7.addFile(u":/assets/Configure.png", QSize(), QIcon.Normal, QIcon.Off)
        self.tabWidget.addTab(self.setupTab, icon7, "")
        self.outputTab = QWidget()
        self.outputTab.setObjectName(u"outputTab")
        self.outputTab.setMinimumSize(QSize(787, 550))
        self.outputTab.setMaximumSize(QSize(787, 550))
        self.verticalLayoutWidget_2 = QWidget(self.outputTab)
        self.verticalLayoutWidget_2.setObjectName(u"verticalLayoutWidget_2")
        self.verticalLayoutWidget_2.setGeometry(QRect(20, 90, 751, 441))
        self.verticalLayout_2 = QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.outputText = QPlainTextEdit(self.verticalLayoutWidget_2)
        self.outputText.setObjectName(u"outputText")
        self.outputText.setMinimumSize(QSize(749, 439))
        self.outputText.setMaximumSize(QSize(749, 439))
        self.outputText.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.outputText.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.outputText.setUndoRedoEnabled(False)
        self.outputText.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self.outputText.setBackgroundVisible(False)

        self.verticalLayout_2.addWidget(self.outputText)

        self.btnCopy = QPushButton(self.outputTab)
        self.btnCopy.setObjectName(u"btnCopy")
        self.btnCopy.setGeometry(QRect(300, 50, 201, 25))
        self.btnCopy.setMinimumSize(QSize(201, 25))
        self.btnCopy.setMaximumSize(QSize(201, 25))
        self.btnCopy.setIcon(icon1)
        self.btnCopy.setFlat(False)
        icon8 = QIcon()
        icon8.addFile(u":/assets/Logout.png", QSize(), QIcon.Normal, QIcon.Off)
        self.tabWidget.addTab(self.outputTab, icon8, "")
        self.aboutTab = QWidget()
        self.aboutTab.setObjectName(u"aboutTab")
        self.verticalLayoutWidget_3 = QWidget(self.aboutTab)
        self.verticalLayoutWidget_3.setObjectName(u"verticalLayoutWidget_3")
        self.verticalLayoutWidget_3.setGeometry(QRect(10, 10, 771, 521))
        self.verticalLayout_3 = QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.label_2 = QLabel(self.verticalLayoutWidget_3)
        self.label_2.setObjectName(u"label_2")
        font1 = QFont()
        font1.setPointSize(26)
        self.label_2.setFont(font1)
        self.label_2.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignTop)

        self.verticalLayout_3.addWidget(self.label_2)

        self.label_3 = QLabel(self.verticalLayoutWidget_3)
        self.label_3.setObjectName(u"label_3")
        self.label_3.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.verticalLayout_3.addWidget(self.label_3)

        self.textBrowser = QTextBrowser(self.verticalLayoutWidget_3)
        self.textBrowser.setObjectName(u"textBrowser")
        self.textBrowser.setOpenLinks(False)

        self.verticalLayout_3.addWidget(self.textBrowser)

        self.tabWidget.addTab(self.aboutTab, icon, "")
        MainWindow.setCentralWidget(self.centralwidget)
        QWidget.setTabOrder(self.tabWidget, self.btnPaste)
        QWidget.setTabOrder(self.btnPaste, self.inputText)
        QWidget.setTabOrder(self.inputText, self.operationMode)
        QWidget.setTabOrder(self.operationMode, self.btnEncode)
        QWidget.setTabOrder(self.btnEncode, self.btnDecode)
        QWidget.setTabOrder(self.btnDecode, self.btnBruteForce)
        QWidget.setTabOrder(self.btnBruteForce, self.btnCopy)

        self.retranslateUi(MainWindow)
        self.btnCopy.clicked.connect(self.actionCopy.trigger)
        self.btnPaste.clicked.connect(self.actionPaste.trigger)
        self.btnEncode.clicked.connect(self.actionEncode.trigger)
        self.btnDecode.clicked.connect(self.actionDecode.trigger)
        self.btnBruteForce.clicked.connect(self.actionBrute.trigger)
        self.operationMode.currentIndexChanged.connect(self.actionOperationChanged.trigger)

        self.tabWidget.setCurrentIndex(0)
        self.operationMode.setCurrentIndex(0)
        self.btnCopy.setDefault(False)


        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"CRYPT GUI", None))
#if QT_CONFIG(tooltip)
        MainWindow.setToolTip(QCoreApplication.translate("MainWindow", u"A Collection of Tools", None))
#endif // QT_CONFIG(tooltip)
        self.actionCopy.setText(QCoreApplication.translate("MainWindow", u"Copy", None))
#if QT_CONFIG(shortcut)
        self.actionCopy.setShortcut(QCoreApplication.translate("MainWindow", u"Ctrl+Shift+C", None))
#endif // QT_CONFIG(shortcut)
        self.actionPaste.setText(QCoreApplication.translate("MainWindow", u"Paste", None))
#if QT_CONFIG(shortcut)
        self.actionPaste.setShortcut(QCoreApplication.translate("MainWindow", u"Ctrl+Shift+V", None))
#endif // QT_CONFIG(shortcut)
        self.actionEncode.setText(QCoreApplication.translate("MainWindow", u"Encode", None))
        self.actionDecode.setText(QCoreApplication.translate("MainWindow", u"Decode", None))
        self.actionBrute.setText(QCoreApplication.translate("MainWindow", u"Brute", None))
        self.actionOperationChanged.setText(QCoreApplication.translate("MainWindow", u"OperationChanged", None))
#if QT_CONFIG(tooltip)
        self.actionOperationChanged.setToolTip(QCoreApplication.translate("MainWindow", u"OperationChanged", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(accessibility)
        self.inputTab.setAccessibleName(QCoreApplication.translate("MainWindow", u"&Input", None))
#endif // QT_CONFIG(accessibility)
        self.inputText.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Input data to be encoded/decoded.", None))
        self.btnPaste.setText(QCoreApplication.translate("MainWindow", u"Paste from Clipboard", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.inputTab), QCoreApplication.translate("MainWindow", u"Input", None))
        self.btnEncode.setText(QCoreApplication.translate("MainWindow", u"Encode/Encrypt", None))
        self.btnDecode.setText(QCoreApplication.translate("MainWindow", u"Decode/Decrypt", None))
        self.operationMode.setItemText(0, QCoreApplication.translate("MainWindow", u"None", None))
        self.operationMode.setItemText(1, QCoreApplication.translate("MainWindow", u"Base16", None))
        self.operationMode.setItemText(2, QCoreApplication.translate("MainWindow", u"Base32", None))
        self.operationMode.setItemText(3, QCoreApplication.translate("MainWindow", u"Base85", None))
        self.operationMode.setItemText(4, QCoreApplication.translate("MainWindow", u"Base64", None))
        self.operationMode.setItemText(5, QCoreApplication.translate("MainWindow", u"Caesar Cipher", None))
        self.operationMode.setItemText(6, QCoreApplication.translate("MainWindow", u"Morse Code", None))
        self.operationMode.setItemText(7, QCoreApplication.translate("MainWindow", u"Baconian Cipher", None))
        self.operationMode.setItemText(8, QCoreApplication.translate("MainWindow", u"Vigenere Cipher", None))
        self.operationMode.setItemText(9, QCoreApplication.translate("MainWindow", u"MD5", None))
        self.operationMode.setItemText(10, QCoreApplication.translate("MainWindow", u"MD5 CRYPT", None))
        self.operationMode.setItemText(11, QCoreApplication.translate("MainWindow", u"SHA256", None))
        self.operationMode.setItemText(12, QCoreApplication.translate("MainWindow", u"SHA256 CRYPT", None))
        self.operationMode.setItemText(13, QCoreApplication.translate("MainWindow", u"SHA512", None))
        self.operationMode.setItemText(14, QCoreApplication.translate("MainWindow", u"SHA512 CRYPT", None))
        self.operationMode.setItemText(15, QCoreApplication.translate("MainWindow", u"bCrypt", None))
        self.operationMode.setItemText(16, QCoreApplication.translate("MainWindow", u"Argon2", None))
        self.operationMode.setItemText(17, QCoreApplication.translate("MainWindow", u"NT Hash", None))
        self.operationMode.setItemText(18, QCoreApplication.translate("MainWindow", u"PBKDF2 SHA256", None))
        self.operationMode.setItemText(19, QCoreApplication.translate("MainWindow", u"PBKDF2 SHA512", None))

        self.operationMode.setCurrentText(QCoreApplication.translate("MainWindow", u"None", None))
        self.operationMode.setPlaceholderText(QCoreApplication.translate("MainWindow", u"No Operation Chosen", None))
        self.label.setText(QCoreApplication.translate("MainWindow", u"Operation", None))
        self.btnBruteForce.setText(QCoreApplication.translate("MainWindow", u"Brute Force", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.setupTab), QCoreApplication.translate("MainWindow", u"Setup", None))
        self.outputText.setPlainText("")
        self.outputText.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Decoded/Encoded data would be displayed here.", None))
        self.btnCopy.setText(QCoreApplication.translate("MainWindow", u"Copy to Clipboard", None))
#if QT_CONFIG(shortcut)
        self.btnCopy.setShortcut(QCoreApplication.translate("MainWindow", u"Ctrl+Shift+C", None))
#endif // QT_CONFIG(shortcut)
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.outputTab), QCoreApplication.translate("MainWindow", u"Output", None))
        self.label_2.setText(QCoreApplication.translate("MainWindow", u"CRYPT GUI", None))
        self.label_3.setText(QCoreApplication.translate("MainWindow", u"Licenses", None))
        self.textBrowser.setDocumentTitle(QCoreApplication.translate("MainWindow", u"GNU General Public License v3.0", None))
        self.textBrowser.setHtml(QCoreApplication.translate("MainWindow", u"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><title>GNU General Public License v3.0</title><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"hr { height: 1px; border-width: 0; }\n"
"li.unchecked::marker { content: \"\\2610\"; }\n"
"li.checked::marker { content: \"\\2612\"; }\n"
"</style></head><body style=\" font-family:'Sans Serif'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">CRYPT GUI, A Collection of tools, is licensed under GPL v3.0 Copyright (c) 2024 Ninja Left</p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">CRYPT was built using Python 3.11, Qt Designer &amp; Pyside6.</p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; ma"
                        "rgin-right:0px; -qt-block-indent:0; text-indent:0px;\">Some functions used in this software are from <a href=\"https://github.com/TheAlgorithms/Python\"><span style=\" text-decoration: underline; color:#b85b6a;\">This Repository</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" color:#ffffff;\">and are licensed under MIT Copyright (c) 2016-2024 TheAlgorithms and contributors.</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:'monospace'; color:#ffffff;\">Icons:</span></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon"
                        "/configuration_9780271\"><span style=\" text-decoration: underline; color:#b85b6a;\">Configure icon by afif fudin - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/login_5729989\"><span style=\" text-decoration: underline; color:#b85b6a;\">Login icon by FR_Media - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/logout_5729988\"><span style=\" text-decoration: underline; color:#b85b6a;\">Logout icon by FR_Media - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/lock_2549910\"><span style=\" text-decoration: underline; color:#b85b6a;\">Locked icon by Aswell Studio - Flaticon</span></"
                        "a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/unlock_2549951\"><span style=\" text-decoration: underline; color:#b85b6a;\">Unlocked icon by Aswell Studio - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/unsecure_5690981\"><span style=\" text-decoration: underline; color:#b85b6a;\">Unsecure icon by juicy_fish - Flaticon</span></a></p>\n"
"<p style=\" margin-top:1px; margin-bottom:1px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><a href=\"https://www.flaticon.com/free-icon/search_1828057\"><span style=\" text-decoration: underline; color:#b85b6a;\">Search icon by Pixel Perfect - Flaticon</span></a></p></body></html>", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.aboutTab), QCoreApplication.translate("MainWindow", u"About", None))
    # retranslateUi

