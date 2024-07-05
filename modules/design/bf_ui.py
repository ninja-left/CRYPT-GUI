# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'bf.ui'
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
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QGridLayout,
    QHBoxLayout, QLabel, QLayout, QLineEdit,
    QProgressBar, QPushButton, QSizePolicy, QSpacerItem,
    QWidget)


class Ui_BruteForceDialog(object):
    def setupUi(self, BruteForceDialog):
        if not BruteForceDialog.objectName():
            BruteForceDialog.setObjectName(u"BruteForceDialog")
        BruteForceDialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        BruteForceDialog.resize(525, 440)
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(BruteForceDialog.sizePolicy().hasHeightForWidth())
        BruteForceDialog.setSizePolicy(sizePolicy)
        BruteForceDialog.setMinimumSize(QSize(525, 440))
        BruteForceDialog.setMaximumSize(QSize(525, 440))
        BruteForceDialog.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        BruteForceDialog.setAcceptDrops(False)
        icon = QIcon()
        icon.addFile(u":/images/Crack.png", QSize(), QIcon.Normal, QIcon.Off)
        BruteForceDialog.setWindowIcon(icon)
        BruteForceDialog.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        BruteForceDialog.setAutoFillBackground(False)
        BruteForceDialog.setModal(False)
        self.actionChooseFile = QAction(BruteForceDialog)
        self.actionChooseFile.setObjectName(u"actionChooseFile")
        self.actionChooseFile.setMenuRole(QAction.MenuRole.NoRole)
        self.actionConfigBrute = QAction(BruteForceDialog)
        self.actionConfigBrute.setObjectName(u"actionConfigBrute")
        self.actionConfigBrute.setMenuRole(QAction.MenuRole.NoRole)
        self.actionConfigWordList = QAction(BruteForceDialog)
        self.actionConfigWordList.setObjectName(u"actionConfigWordList")
        self.actionConfigWordList.setMenuRole(QAction.MenuRole.NoRole)
        self.actionConfigRamp = QAction(BruteForceDialog)
        self.actionConfigRamp.setObjectName(u"actionConfigRamp")
        self.actionConfigRamp.setMenuRole(QAction.MenuRole.NoRole)
        self.actionCrack = QAction(BruteForceDialog)
        self.actionCrack.setObjectName(u"actionCrack")
        self.actionCrack.setMenuRole(QAction.MenuRole.NoRole)
        self.gridLayoutWidget = QWidget(BruteForceDialog)
        self.gridLayoutWidget.setObjectName(u"gridLayoutWidget")
        self.gridLayoutWidget.setGeometry(QRect(0, 0, 521, 431))
        self.gridLayout = QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setObjectName(u"gridLayout")
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.btnCrack = QPushButton(self.gridLayoutWidget)
        self.btnCrack.setObjectName(u"btnCrack")
        self.btnCrack.setMinimumSize(QSize(170, 25))
        self.btnCrack.setMaximumSize(QSize(170, 25))
        self.btnCrack.setIcon(icon)

        self.gridLayout.addWidget(self.btnCrack, 3, 0, 1, 1, Qt.AlignmentFlag.AlignHCenter)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.inputBrute = QCheckBox(self.gridLayoutWidget)
        self.inputBrute.setObjectName(u"inputBrute")
        self.inputBrute.setTristate(False)

        self.horizontalLayout.addWidget(self.inputBrute, 0, Qt.AlignmentFlag.AlignHCenter)

        self.inputWordList = QCheckBox(self.gridLayoutWidget)
        self.inputWordList.setObjectName(u"inputWordList")

        self.horizontalLayout.addWidget(self.inputWordList, 0, Qt.AlignmentFlag.AlignHCenter)


        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)

        self.verticalSpacer_2 = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.gridLayout.addItem(self.verticalSpacer_2, 4, 0, 1, 1)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.gridLayout.addItem(self.verticalSpacer, 2, 0, 1, 1)

        self.progressBar = QProgressBar(self.gridLayoutWidget)
        self.progressBar.setObjectName(u"progressBar")
        self.progressBar.setEnabled(True)
        self.progressBar.setMinimumSize(QSize(411, 25))
        self.progressBar.setMaximumSize(QSize(411, 25))
        self.progressBar.setValue(24)
        self.progressBar.setOrientation(Qt.Orientation.Horizontal)
        self.progressBar.setTextDirection(QProgressBar.Direction.TopToBottom)

        self.gridLayout.addWidget(self.progressBar, 6, 0, 1, 1, Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignBottom)

        self.optionGrid = QGridLayout()
        self.optionGrid.setObjectName(u"optionGrid")
        self.optionGrid.setSizeConstraint(QLayout.SizeConstraint.SetDefaultConstraint)
        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.inputFilePath = QLineEdit(self.gridLayoutWidget)
        self.inputFilePath.setObjectName(u"inputFilePath")
        self.inputFilePath.setMaximumSize(QSize(439, 25))
        self.inputFilePath.setReadOnly(False)

        self.horizontalLayout_2.addWidget(self.inputFilePath)

        self.inputChooseFile = QPushButton(self.gridLayoutWidget)
        self.inputChooseFile.setObjectName(u"inputChooseFile")
        self.inputChooseFile.setMaximumSize(QSize(80, 25))
        icon1 = QIcon()
        icon1.addFile(u":/images/Input.png", QSize(), QIcon.Normal, QIcon.Off)
        self.inputChooseFile.setIcon(icon1)

        self.horizontalLayout_2.addWidget(self.inputChooseFile)


        self.optionGrid.addLayout(self.horizontalLayout_2, 0, 1, 1, 1)

        self.label_2 = QLabel(self.gridLayoutWidget)
        self.label_2.setObjectName(u"label_2")

        self.optionGrid.addWidget(self.label_2, 1, 0, 1, 1, Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignVCenter)

        self.label_4 = QLabel(self.gridLayoutWidget)
        self.label_4.setObjectName(u"label_4")

        self.optionGrid.addWidget(self.label_4, 3, 0, 1, 1, Qt.AlignmentFlag.AlignHCenter)

        self.label = QLabel(self.gridLayoutWidget)
        self.label.setObjectName(u"label")

        self.optionGrid.addWidget(self.label, 0, 0, 1, 1, Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignVCenter)

        self.inputStartLength = QLineEdit(self.gridLayoutWidget)
        self.inputStartLength.setObjectName(u"inputStartLength")

        self.optionGrid.addWidget(self.inputStartLength, 3, 1, 1, 1)

        self.inputRamp = QCheckBox(self.gridLayoutWidget)
        self.inputRamp.setObjectName(u"inputRamp")
        self.inputRamp.setChecked(True)

        self.optionGrid.addWidget(self.inputRamp, 2, 1, 1, 1)

        self.label_3 = QLabel(self.gridLayoutWidget)
        self.label_3.setObjectName(u"label_3")

        self.optionGrid.addWidget(self.label_3, 2, 0, 1, 1, Qt.AlignmentFlag.AlignHCenter)

        self.inputMaxLength = QLineEdit(self.gridLayoutWidget)
        self.inputMaxLength.setObjectName(u"inputMaxLength")
        self.inputMaxLength.setMaximumSize(QSize(444, 25))
        self.inputMaxLength.setInputMethodHints(Qt.InputMethodHint.ImhDigitsOnly)

        self.optionGrid.addWidget(self.inputMaxLength, 1, 1, 1, 1)

        self.label_5 = QLabel(self.gridLayoutWidget)
        self.label_5.setObjectName(u"label_5")

        self.optionGrid.addWidget(self.label_5, 4, 0, 1, 1, Qt.AlignmentFlag.AlignHCenter)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.inputLetters = QCheckBox(self.gridLayoutWidget)
        self.inputLetters.setObjectName(u"inputLetters")
        self.inputLetters.setChecked(True)

        self.horizontalLayout_3.addWidget(self.inputLetters)

        self.inputNumbers = QCheckBox(self.gridLayoutWidget)
        self.inputNumbers.setObjectName(u"inputNumbers")
        self.inputNumbers.setChecked(True)

        self.horizontalLayout_3.addWidget(self.inputNumbers)

        self.inputSymbols = QCheckBox(self.gridLayoutWidget)
        self.inputSymbols.setObjectName(u"inputSymbols")
        self.inputSymbols.setChecked(True)

        self.horizontalLayout_3.addWidget(self.inputSymbols)

        self.inputSpaces = QCheckBox(self.gridLayoutWidget)
        self.inputSpaces.setObjectName(u"inputSpaces")

        self.horizontalLayout_3.addWidget(self.inputSpaces)


        self.optionGrid.addLayout(self.horizontalLayout_3, 4, 1, 1, 1)


        self.gridLayout.addLayout(self.optionGrid, 1, 0, 1, 1)


        self.retranslateUi(BruteForceDialog)
        self.inputBrute.stateChanged.connect(self.actionConfigBrute.trigger)
        self.inputWordList.stateChanged.connect(self.actionConfigWordList.trigger)
        self.btnCrack.clicked.connect(self.actionCrack.trigger)
        self.inputRamp.stateChanged.connect(self.actionConfigRamp.trigger)
        self.inputChooseFile.clicked.connect(self.actionChooseFile.trigger)

        QMetaObject.connectSlotsByName(BruteForceDialog)
    # setupUi

    def retranslateUi(self, BruteForceDialog):
        BruteForceDialog.setWindowTitle(QCoreApplication.translate("BruteForceDialog", u"Brute-Force", None))
#if QT_CONFIG(accessibility)
        BruteForceDialog.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Brute-Force menu", None))
#endif // QT_CONFIG(accessibility)
        self.actionChooseFile.setText(QCoreApplication.translate("BruteForceDialog", u"ChooseFile", None))
        self.actionConfigBrute.setText(QCoreApplication.translate("BruteForceDialog", u"configBrute", None))
        self.actionConfigWordList.setText(QCoreApplication.translate("BruteForceDialog", u"ConfigWordList", None))
        self.actionConfigRamp.setText(QCoreApplication.translate("BruteForceDialog", u"ConfigRamp", None))
        self.actionCrack.setText(QCoreApplication.translate("BruteForceDialog", u"Crack", None))
        self.btnCrack.setText(QCoreApplication.translate("BruteForceDialog", u"&Start Cracking", None))
#if QT_CONFIG(tooltip)
        self.inputBrute.setToolTip(QCoreApplication.translate("BruteForceDialog", u"Crack the hash by brute-forcing", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputBrute.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Brute Forcing", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputBrute.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Brute Force", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputBrute.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Crack the hash by brute-forcing", None))
#endif // QT_CONFIG(accessibility)
        self.inputBrute.setText(QCoreApplication.translate("BruteForceDialog", u"Brute Force", None))
#if QT_CONFIG(tooltip)
        self.inputWordList.setToolTip(QCoreApplication.translate("BruteForceDialog", u"Crack the hash using a wordlist", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputWordList.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Word List cracking", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputWordList.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Word list", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputWordList.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Crack the hash using a wordlist", None))
#endif // QT_CONFIG(accessibility)
        self.inputWordList.setText(QCoreApplication.translate("BruteForceDialog", u"Word List", None))
#if QT_CONFIG(tooltip)
        self.inputFilePath.setToolTip(QCoreApplication.translate("BruteForceDialog", u"Can be relative or absolute", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputFilePath.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Input file path", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputFilePath.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Input file path", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputFilePath.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Can be relative or absolute", None))
#endif // QT_CONFIG(accessibility)
        self.inputFilePath.setPlaceholderText(QCoreApplication.translate("BruteForceDialog", u"File Path", None))
        self.inputChooseFile.setText(QCoreApplication.translate("BruteForceDialog", u"Browse", None))
        self.label_2.setText(QCoreApplication.translate("BruteForceDialog", u"Max Length", None))
        self.label_4.setText(QCoreApplication.translate("BruteForceDialog", u"Start Length", None))
        self.label.setText(QCoreApplication.translate("BruteForceDialog", u"Filename", None))
#if QT_CONFIG(whatsthis)
        self.inputStartLength.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Start Length", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputStartLength.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Start Length", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputStartLength.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Start from this length until Max Length", None))
#endif // QT_CONFIG(accessibility)
        self.inputStartLength.setPlaceholderText(QCoreApplication.translate("BruteForceDialog", u"Start from this length until Max Length", None))
#if QT_CONFIG(tooltip)
        self.inputRamp.setToolTip(QCoreApplication.translate("BruteForceDialog", u"If unchecked, iterate over current max length value.", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputRamp.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Ramp", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputRamp.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Ramp", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputRamp.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Ramp up from a start length till length; If unchecked, iterate over current max length value.", None))
#endif // QT_CONFIG(accessibility)
        self.inputRamp.setText(QCoreApplication.translate("BruteForceDialog", u"Ramp up from a start length until max length.", None))
        self.label_3.setText(QCoreApplication.translate("BruteForceDialog", u"Ramp?", None))
#if QT_CONFIG(tooltip)
        self.inputMaxLength.setToolTip(QCoreApplication.translate("BruteForceDialog", u"A number", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputMaxLength.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Maximum Length", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputMaxLength.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Maximum Length", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputMaxLength.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Maximum length of plain text.", None))
#endif // QT_CONFIG(accessibility)
        self.inputMaxLength.setPlaceholderText(QCoreApplication.translate("BruteForceDialog", u"Maximum length of plain text", None))
        self.label_5.setText(QCoreApplication.translate("BruteForceDialog", u"Include", None))
#if QT_CONFIG(tooltip)
        self.inputLetters.setToolTip(QCoreApplication.translate("BruteForceDialog", u"English uppercase & lowercase", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputLetters.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"English letters", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputLetters.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"English letters", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputLetters.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Use English uppercase & lowercase", None))
#endif // QT_CONFIG(accessibility)
        self.inputLetters.setText(QCoreApplication.translate("BruteForceDialog", u"Letters", None))
#if QT_CONFIG(tooltip)
        self.inputNumbers.setToolTip(QCoreApplication.translate("BruteForceDialog", u"0-9", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputNumbers.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Numbers", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputNumbers.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Numbers", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputNumbers.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Use numbers 0-9", None))
#endif // QT_CONFIG(accessibility)
        self.inputNumbers.setText(QCoreApplication.translate("BruteForceDialog", u"Numbers", None))
#if QT_CONFIG(tooltip)
        self.inputSymbols.setToolTip(QCoreApplication.translate("BruteForceDialog", u"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputSymbols.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Symbols", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputSymbols.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Symbols", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputSymbols.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Use symbols", None))
#endif // QT_CONFIG(accessibility)
        self.inputSymbols.setText(QCoreApplication.translate("BruteForceDialog", u"Symbols", None))
#if QT_CONFIG(tooltip)
        self.inputSpaces.setToolTip(QCoreApplication.translate("BruteForceDialog", u"Use space, tab, newline & similar characters", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(whatsthis)
        self.inputSpaces.setWhatsThis(QCoreApplication.translate("BruteForceDialog", u"Whitespace", None))
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        self.inputSpaces.setAccessibleName(QCoreApplication.translate("BruteForceDialog", u"Whitespace", None))
#endif // QT_CONFIG(accessibility)
#if QT_CONFIG(accessibility)
        self.inputSpaces.setAccessibleDescription(QCoreApplication.translate("BruteForceDialog", u"Use space, tab, newline & similar characters", None))
#endif // QT_CONFIG(accessibility)
        self.inputSpaces.setText(QCoreApplication.translate("BruteForceDialog", u"Whitespace", None))
    # retranslateUi

