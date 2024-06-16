#!/usr/bin/env python3

from PySide6.QtWidgets import QApplication, QDialog, QMainWindow, QMessageBox
from PySide6 import QtGui
import pyperclip3
import sys

from modules import main_ui, resources

class Window(QMainWindow, main_ui.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.connectSignalSlots()
        self.OpMode = ""
        self.defaultTextEncode = "Encode/Encrypt"
        self.defaultTextDecode = "Decode/Decrypt"
        self.defaultIconDecode = QtGui.QIcon()
        self.defaultIconDecode.addPixmap(":/assets/Unlocked.png")

    def connectSignalSlots(self):
        self.actionCopy.triggered.connect(self.doCopy)
        self.actionPaste.triggered.connect(self.doPaste)
        self.actionEncode.triggered.connect(self.doEncode)
        self.actionDecode.triggered.connect(self.doDecode)
        self.actionBrute.triggered.connect(self.doBrute)
        self.actionOperationChanged.triggered.connect(self.doChangeOp)

    def doCopy(self):
        text = str(self.outputText.toPlainText())
        if not text.strip():
            msg = QMessageBox(QMessageBox.Warning, "Copying failed!", "Is there any data in the output area?", QMessageBox.Cancel)
            msg.setInformativeText("Copying would fail if there's no data in the output box.")
            msg.setDetailedText("If you entered the input data, head to the \"Setup\" tab to decide what to do with it.")
            msg.exec()
        else:
            pyperclip3.copy(text)
            QMessageBox.information(self, "Copied!", "The output data has been copied.", QMessageBox.Ok)

    def doPaste(self):
        try:
            text = str(pyperclip3.paste().decode('utf-8'))
            self.inputText.setPlainText(text)
            QMessageBox.information(self, "Pasted!", "Pasted data into the input area.")
        except:
            msg = QMessageBox(QMessageBox.Warning, "Paste failed!", "Are you sure you copied text?", QMessageBox.Cancel)
            msg.setInformativeText("Only text can be pasted.")
            msg.setDetailedText("Make sure that the data you're trying to paste is Text not Image or something else.")
            msg.exec()
            raise

    def doChangeOp(self):
        chosenMode = self.operationMode.currentText()
        match chosenMode:
            case "None":
                # Set buttons to default
                self.btnEncode.setText(self.defaultTextEncode)
                self.btnEncode.setEnabled(False)
                self.btnDecode.setText(self.defaultTextDecode)
                self.btnDecode.setIcon(self.defaultIconDecode)
                self.btnDecode.setEnabled(False)
                self.btnBruteForce.setEnabled(False)
            case "Base16" | "Base32" | "Base85" | "Base64":
                self.btnEncode.setText("Encode")
                self.btnEncode.setEnabled(True)
                self.btnDecode.setIcon(self.defaultIconDecode)
                self.btnDecode.setText("Decode")
                self.btnDecode.setEnabled(True)
                self.btnBruteForce.setEnabled(False)
            case "Caesar Cipher" | "Morse Code" | "Baconian Cipher" | "Vigenere Cipher":
                self.btnEncode.setText("Encrypt")
                self.btnEncode.setEnabled(True)
                self.btnDecode.setIcon(self.defaultIconDecode)
                self.btnDecode.setText("Decrypt")
                self.btnDecode.setEnabled(True)
                self.btnBruteForce.setEnabled(True)
            case _:
                # Enable all buttons
                self.btnEncode.setText("Hash")
                self.btnEncode.setEnabled(True)
                self.btnDecode.setText("Verify")
                decode_icon = QtGui.QIcon()
                decode_icon.addPixmap(":/assets/Verify.png")
                self.btnDecode.setIcon(decode_icon)
                self.btnDecode.setEnabled(True)
                self.btnBruteForce.setEnabled(True)
        # TODO: self.OpMode = chosenMode

    def doDecode(self):
        # Code
        pass

    def doEncode(self):
        # Code
        pass

    def doBrute(self):
        # Code
        pass

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec())
