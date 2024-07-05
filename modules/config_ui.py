# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'config.ui'
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
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSizePolicy,
    QSpacerItem, QVBoxLayout, QWidget)


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        if not Dialog.objectName():
            Dialog.setObjectName(u"Dialog")
        Dialog.resize(638, 780)
        icon = QIcon()
        icon.addFile(u":/assets/Configure.png", QSize(), QIcon.Normal, QIcon.Off)
        Dialog.setWindowIcon(icon)
        self.actionSaveSettings = QAction(Dialog)
        self.actionSaveSettings.setObjectName(u"actionSaveSettings")
        self.actionSaveSettings.setMenuRole(QAction.MenuRole.NoRole)
        self.actionLoudSettings = QAction(Dialog)
        self.actionLoudSettings.setObjectName(u"actionLoudSettings")
        self.actionLoudSettings.setMenuRole(QAction.MenuRole.NoRole)
        self.verticalLayoutWidget = QWidget(Dialog)
        self.verticalLayoutWidget.setObjectName(u"verticalLayoutWidget")
        self.verticalLayoutWidget.setGeometry(QRect(10, 10, 621, 761))
        self.verticalLayout = QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel(self.verticalLayoutWidget)
        self.label.setObjectName(u"label")

        self.verticalLayout.addWidget(self.label, 0, Qt.AlignmentFlag.AlignHCenter)

        self.horizontalLayout_6 = QHBoxLayout()
        self.horizontalLayout_6.setObjectName(u"horizontalLayout_6")
        self.label_6 = QLabel(self.verticalLayoutWidget)
        self.label_6.setObjectName(u"label_6")

        self.horizontalLayout_6.addWidget(self.label_6)

        self.inputAlph_Default = QLineEdit(self.verticalLayoutWidget)
        self.inputAlph_Default.setObjectName(u"inputAlph_Default")
        self.inputAlph_Default.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_6.addWidget(self.inputAlph_Default)


        self.verticalLayout.addLayout(self.horizontalLayout_6)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.label_3 = QLabel(self.verticalLayoutWidget)
        self.label_3.setObjectName(u"label_3")

        self.horizontalLayout_3.addWidget(self.label_3)

        self.inputAlph_B32 = QLineEdit(self.verticalLayoutWidget)
        self.inputAlph_B32.setObjectName(u"inputAlph_B32")
        self.inputAlph_B32.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_3.addWidget(self.inputAlph_B32)


        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.horizontalLayout_4 = QHBoxLayout()
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.label_4 = QLabel(self.verticalLayoutWidget)
        self.label_4.setObjectName(u"label_4")

        self.horizontalLayout_4.addWidget(self.label_4)

        self.inputAlph_B64 = QLineEdit(self.verticalLayoutWidget)
        self.inputAlph_B64.setObjectName(u"inputAlph_B64")
        self.inputAlph_B64.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_4.addWidget(self.inputAlph_B64)


        self.verticalLayout.addLayout(self.horizontalLayout_4)

        self.horizontalLayout_5 = QHBoxLayout()
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.label_5 = QLabel(self.verticalLayoutWidget)
        self.label_5.setObjectName(u"label_5")

        self.horizontalLayout_5.addWidget(self.label_5)

        self.inputAlph_B85 = QLineEdit(self.verticalLayoutWidget)
        self.inputAlph_B85.setObjectName(u"inputAlph_B85")
        self.inputAlph_B85.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_5.addWidget(self.inputAlph_B85)


        self.verticalLayout.addLayout(self.horizontalLayout_5)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.label_2 = QLabel(self.verticalLayoutWidget)
        self.label_2.setObjectName(u"label_2")

        self.horizontalLayout_2.addWidget(self.label_2)

        self.inputAlph_Vigenere = QLineEdit(self.verticalLayoutWidget)
        self.inputAlph_Vigenere.setObjectName(u"inputAlph_Vigenere")
        self.inputAlph_Vigenere.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_2.addWidget(self.inputAlph_Vigenere)


        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.label_7 = QLabel(self.verticalLayoutWidget)
        self.label_7.setObjectName(u"label_7")

        self.verticalLayout.addWidget(self.label_7, 0, Qt.AlignmentFlag.AlignHCenter)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.label_8 = QLabel(self.verticalLayoutWidget)
        self.label_8.setObjectName(u"label_8")

        self.horizontalLayout.addWidget(self.label_8)

        self.inputKey_Caesar = QLineEdit(self.verticalLayoutWidget)
        self.inputKey_Caesar.setObjectName(u"inputKey_Caesar")
        self.inputKey_Caesar.setMaximumSize(QSize(511, 25))

        self.horizontalLayout.addWidget(self.inputKey_Caesar)


        self.verticalLayout.addLayout(self.horizontalLayout)

        self.horizontalLayout_7 = QHBoxLayout()
        self.horizontalLayout_7.setObjectName(u"horizontalLayout_7")
        self.label_9 = QLabel(self.verticalLayoutWidget)
        self.label_9.setObjectName(u"label_9")

        self.horizontalLayout_7.addWidget(self.label_9)

        self.inputKey_Vigenere = QLineEdit(self.verticalLayoutWidget)
        self.inputKey_Vigenere.setObjectName(u"inputKey_Vigenere")
        self.inputKey_Vigenere.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_7.addWidget(self.inputKey_Vigenere)


        self.verticalLayout.addLayout(self.horizontalLayout_7)

        self.label_10 = QLabel(self.verticalLayoutWidget)
        self.label_10.setObjectName(u"label_10")

        self.verticalLayout.addWidget(self.label_10, 0, Qt.AlignmentFlag.AlignHCenter)

        self.horizontalLayout_8 = QHBoxLayout()
        self.horizontalLayout_8.setObjectName(u"horizontalLayout_8")
        self.label_11 = QLabel(self.verticalLayoutWidget)
        self.label_11.setObjectName(u"label_11")

        self.horizontalLayout_8.addWidget(self.label_11)

        self.inputRound_bCrypt = QLineEdit(self.verticalLayoutWidget)
        self.inputRound_bCrypt.setObjectName(u"inputRound_bCrypt")
        self.inputRound_bCrypt.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_8.addWidget(self.inputRound_bCrypt)


        self.verticalLayout.addLayout(self.horizontalLayout_8)

        self.horizontalLayout_9 = QHBoxLayout()
        self.horizontalLayout_9.setObjectName(u"horizontalLayout_9")
        self.label_12 = QLabel(self.verticalLayoutWidget)
        self.label_12.setObjectName(u"label_12")

        self.horizontalLayout_9.addWidget(self.label_12)

        self.inputRound_Argon2 = QLineEdit(self.verticalLayoutWidget)
        self.inputRound_Argon2.setObjectName(u"inputRound_Argon2")
        self.inputRound_Argon2.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_9.addWidget(self.inputRound_Argon2)


        self.verticalLayout.addLayout(self.horizontalLayout_9)

        self.horizontalLayout_10 = QHBoxLayout()
        self.horizontalLayout_10.setObjectName(u"horizontalLayout_10")
        self.label_13 = QLabel(self.verticalLayoutWidget)
        self.label_13.setObjectName(u"label_13")

        self.horizontalLayout_10.addWidget(self.label_13)

        self.inputRound_PBKDF2 = QLineEdit(self.verticalLayoutWidget)
        self.inputRound_PBKDF2.setObjectName(u"inputRound_PBKDF2")
        self.inputRound_PBKDF2.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_10.addWidget(self.inputRound_PBKDF2)


        self.verticalLayout.addLayout(self.horizontalLayout_10)

        self.label_14 = QLabel(self.verticalLayoutWidget)
        self.label_14.setObjectName(u"label_14")

        self.verticalLayout.addWidget(self.label_14, 0, Qt.AlignmentFlag.AlignHCenter)

        self.horizontalLayout_11 = QHBoxLayout()
        self.horizontalLayout_11.setObjectName(u"horizontalLayout_11")
        self.label_15 = QLabel(self.verticalLayoutWidget)
        self.label_15.setObjectName(u"label_15")

        self.horizontalLayout_11.addWidget(self.label_15)

        self.inputBf_MaxLength = QLineEdit(self.verticalLayoutWidget)
        self.inputBf_MaxLength.setObjectName(u"inputBf_MaxLength")
        self.inputBf_MaxLength.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_11.addWidget(self.inputBf_MaxLength)


        self.verticalLayout.addLayout(self.horizontalLayout_11)

        self.horizontalLayout_12 = QHBoxLayout()
        self.horizontalLayout_12.setObjectName(u"horizontalLayout_12")
        self.label_16 = QLabel(self.verticalLayoutWidget)
        self.label_16.setObjectName(u"label_16")

        self.horizontalLayout_12.addWidget(self.label_16)

        self.inputBf_Ramp = QCheckBox(self.verticalLayoutWidget)
        self.inputBf_Ramp.setObjectName(u"inputBf_Ramp")

        self.horizontalLayout_12.addWidget(self.inputBf_Ramp)


        self.verticalLayout.addLayout(self.horizontalLayout_12)

        self.horizontalLayout_13 = QHBoxLayout()
        self.horizontalLayout_13.setObjectName(u"horizontalLayout_13")
        self.label_17 = QLabel(self.verticalLayoutWidget)
        self.label_17.setObjectName(u"label_17")

        self.horizontalLayout_13.addWidget(self.label_17)

        self.inputBf_StartLength = QLineEdit(self.verticalLayoutWidget)
        self.inputBf_StartLength.setObjectName(u"inputBf_StartLength")
        self.inputBf_StartLength.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_13.addWidget(self.inputBf_StartLength)


        self.verticalLayout.addLayout(self.horizontalLayout_13)

        self.horizontalLayout_14 = QHBoxLayout()
        self.horizontalLayout_14.setObjectName(u"horizontalLayout_14")
        self.label_18 = QLabel(self.verticalLayoutWidget)
        self.label_18.setObjectName(u"label_18")

        self.horizontalLayout_14.addWidget(self.label_18)

        self.inputBf_IncludeL = QCheckBox(self.verticalLayoutWidget)
        self.inputBf_IncludeL.setObjectName(u"inputBf_IncludeL")

        self.horizontalLayout_14.addWidget(self.inputBf_IncludeL)

        self.inputBf_IncludeD = QCheckBox(self.verticalLayoutWidget)
        self.inputBf_IncludeD.setObjectName(u"inputBf_IncludeD")

        self.horizontalLayout_14.addWidget(self.inputBf_IncludeD)

        self.inputBf_IncludeS = QCheckBox(self.verticalLayoutWidget)
        self.inputBf_IncludeS.setObjectName(u"inputBf_IncludeS")

        self.horizontalLayout_14.addWidget(self.inputBf_IncludeS)

        self.inputBf_IncludeW = QCheckBox(self.verticalLayoutWidget)
        self.inputBf_IncludeW.setObjectName(u"inputBf_IncludeW")

        self.horizontalLayout_14.addWidget(self.inputBf_IncludeW)


        self.verticalLayout.addLayout(self.horizontalLayout_14)

        self.label_19 = QLabel(self.verticalLayoutWidget)
        self.label_19.setObjectName(u"label_19")

        self.verticalLayout.addWidget(self.label_19, 0, Qt.AlignmentFlag.AlignHCenter)

        self.horizontalLayout_15 = QHBoxLayout()
        self.horizontalLayout_15.setObjectName(u"horizontalLayout_15")
        self.label_20 = QLabel(self.verticalLayoutWidget)
        self.label_20.setObjectName(u"label_20")

        self.horizontalLayout_15.addWidget(self.label_20)

        self.inputOther_FontSize = QLineEdit(self.verticalLayoutWidget)
        self.inputOther_FontSize.setObjectName(u"inputOther_FontSize")
        self.inputOther_FontSize.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_15.addWidget(self.inputOther_FontSize)


        self.verticalLayout.addLayout(self.horizontalLayout_15)

        self.horizontalLayout_16 = QHBoxLayout()
        self.horizontalLayout_16.setObjectName(u"horizontalLayout_16")
        self.label_21 = QLabel(self.verticalLayoutWidget)
        self.label_21.setObjectName(u"label_21")

        self.horizontalLayout_16.addWidget(self.label_21)

        self.inputOther_PasteTimeout = QLineEdit(self.verticalLayoutWidget)
        self.inputOther_PasteTimeout.setObjectName(u"inputOther_PasteTimeout")
        self.inputOther_PasteTimeout.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_16.addWidget(self.inputOther_PasteTimeout)


        self.verticalLayout.addLayout(self.horizontalLayout_16)

        self.horizontalLayout_17 = QHBoxLayout()
        self.horizontalLayout_17.setObjectName(u"horizontalLayout_17")
        self.label_22 = QLabel(self.verticalLayoutWidget)
        self.label_22.setObjectName(u"label_22")

        self.horizontalLayout_17.addWidget(self.label_22)

        self.inputOther_SaltPattern = QLineEdit(self.verticalLayoutWidget)
        self.inputOther_SaltPattern.setObjectName(u"inputOther_SaltPattern")
        self.inputOther_SaltPattern.setMaximumSize(QSize(511, 25))

        self.horizontalLayout_17.addWidget(self.inputOther_SaltPattern)


        self.verticalLayout.addLayout(self.horizontalLayout_17)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.verticalLayout.addItem(self.verticalSpacer)

        self.horizontalLayout_18 = QHBoxLayout()
        self.horizontalLayout_18.setObjectName(u"horizontalLayout_18")
        self.btnSave = QPushButton(self.verticalLayoutWidget)
        self.btnSave.setObjectName(u"btnSave")
        self.btnSave.setMaximumSize(QSize(80, 25))
        icon1 = QIcon()
        icon1.addFile(u":/assets/Save.png", QSize(), QIcon.Normal, QIcon.Off)
        self.btnSave.setIcon(icon1)

        self.horizontalLayout_18.addWidget(self.btnSave)

        self.btnLoad = QPushButton(self.verticalLayoutWidget)
        self.btnLoad.setObjectName(u"btnLoad")
        self.btnLoad.setMaximumSize(QSize(80, 25))
        icon2 = QIcon()
        icon2.addFile(u":/assets/Load.png", QSize(), QIcon.Normal, QIcon.Off)
        self.btnLoad.setIcon(icon2)

        self.horizontalLayout_18.addWidget(self.btnLoad)


        self.verticalLayout.addLayout(self.horizontalLayout_18)


        self.retranslateUi(Dialog)
        self.btnSave.clicked.connect(self.actionSaveSettings.trigger)
        self.btnLoad.clicked.connect(self.actionLoudSettings.trigger)

        QMetaObject.connectSlotsByName(Dialog)
    # setupUi

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QCoreApplication.translate("Dialog", u"Settings", None))
        self.actionSaveSettings.setText(QCoreApplication.translate("Dialog", u"SaveSettings", None))
#if QT_CONFIG(shortcut)
        self.actionSaveSettings.setShortcut(QCoreApplication.translate("Dialog", u"Ctrl+S", None))
#endif // QT_CONFIG(shortcut)
        self.actionLoudSettings.setText(QCoreApplication.translate("Dialog", u"LoudSettings", None))
#if QT_CONFIG(shortcut)
        self.actionLoudSettings.setShortcut(QCoreApplication.translate("Dialog", u"Ctrl+L", None))
#endif // QT_CONFIG(shortcut)
        self.label.setText(QCoreApplication.translate("Dialog", u"Default Alphabets", None))
        self.label_6.setText(QCoreApplication.translate("Dialog", u"Default:", None))
        self.label_3.setText(QCoreApplication.translate("Dialog", u"Base 32:", None))
        self.label_4.setText(QCoreApplication.translate("Dialog", u"Base 64:", None))
        self.label_5.setText(QCoreApplication.translate("Dialog", u"Base 85:", None))
        self.label_2.setText(QCoreApplication.translate("Dialog", u"Vigenere:", None))
        self.label_7.setText(QCoreApplication.translate("Dialog", u"Default Keys", None))
        self.label_8.setText(QCoreApplication.translate("Dialog", u"Caesar Cipher:", None))
        self.label_9.setText(QCoreApplication.translate("Dialog", u"Vigenere Cipher:", None))
        self.label_10.setText(QCoreApplication.translate("Dialog", u"Default Hash Rounds", None))
        self.label_11.setText(QCoreApplication.translate("Dialog", u"bCrypt:", None))
        self.label_12.setText(QCoreApplication.translate("Dialog", u"Argon2:", None))
        self.label_13.setText(QCoreApplication.translate("Dialog", u"PBKDF2:", None))
        self.label_14.setText(QCoreApplication.translate("Dialog", u"Brute Force options", None))
        self.label_15.setText(QCoreApplication.translate("Dialog", u"Max Length:", None))
        self.label_16.setText(QCoreApplication.translate("Dialog", u"Ramp?", None))
        self.inputBf_Ramp.setText(QCoreApplication.translate("Dialog", u"yes", None))
        self.label_17.setText(QCoreApplication.translate("Dialog", u"Start Length:", None))
        self.label_18.setText(QCoreApplication.translate("Dialog", u"Inlcude:", None))
        self.inputBf_IncludeL.setText(QCoreApplication.translate("Dialog", u"Letters", None))
        self.inputBf_IncludeD.setText(QCoreApplication.translate("Dialog", u"Numbers", None))
        self.inputBf_IncludeS.setText(QCoreApplication.translate("Dialog", u"Symbols", None))
        self.inputBf_IncludeW.setText(QCoreApplication.translate("Dialog", u"Spaces", None))
        self.label_19.setText(QCoreApplication.translate("Dialog", u"Other settings", None))
        self.label_20.setText(QCoreApplication.translate("Dialog", u"Font Size:", None))
        self.label_21.setText(QCoreApplication.translate("Dialog", u"Paste timeout:", None))
        self.label_22.setText(QCoreApplication.translate("Dialog", u"Salt Pattern:", None))
        self.btnSave.setText(QCoreApplication.translate("Dialog", u"&Save", None))
#if QT_CONFIG(shortcut)
        self.btnSave.setShortcut(QCoreApplication.translate("Dialog", u"Ctrl+S", None))
#endif // QT_CONFIG(shortcut)
        self.btnLoad.setText(QCoreApplication.translate("Dialog", u"&Load", None))
#if QT_CONFIG(shortcut)
        self.btnLoad.setShortcut(QCoreApplication.translate("Dialog", u"Ctrl+L", None))
#endif // QT_CONFIG(shortcut)
    # retranslateUi

