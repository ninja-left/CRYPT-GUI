#!/usr/bin/env python3

from PySide6.QtWidgets import QApplication, QDialog, QMainWindow, QMessageBox
from PySide6 import QtGui
import pyperclip
import sys
from multiprocessing import Pool, TimeoutError as mpTimeoutError
from string import ascii_letters, ascii_uppercase

from modules import main_ui, resources_rc

class Window(QMainWindow, main_ui.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.connectSignalSlots()
        self.pasteTimeout = 1  # seconds
        self.Operation = ""
        self.defaultTextEncode = "Encode/Encrypt"
        self.defaultTextDecode = "Decode/Decrypt"
        self.defaultIconDecode = QtGui.QIcon()
        self.defaultIconDecode.addPixmap(":/assets/Unlocked.png")
        self.pool = Pool()

        # TODO: User should be able to change default alphabets
        # TODO: Read default alphabets from a config file
        self.default_alphabet = ascii_letters
        self.vigenere_alphabet = ascii_uppercase
        self.b64_alphabet = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        )

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
            pyperclip.copy(text)
            QMessageBox.information(self, "Copied!", "The output data has been copied.", QMessageBox.Ok)

    def doPaste(self):
        try:
            pool_result = self.pool.apply_async(pyperclip.paste)
            pool_result.wait(1)
            text = pool_result.get(timeout=self.pasteTimeout)
            self.inputText.toPlainText()
            self.inputText.setPlainText(self.inputText.toPlainText() + text)
            QMessageBox.information(self, "Pasted!", "Pasted data into the input area.")
        except mpTimeoutError:
            msg = QMessageBox(QMessageBox.Warning, "Paste failed!", "Have you copied anything?", QMessageBox.Cancel)
            msg.setInformativeText("Pasting took too long to finish.")
            msg.setDetailedText("This could happen if there's no data in Clipboard. Make sure to copy something first.")
            msg.exec()
            raise
        except:
            msg = QMessageBox(QMessageBox.Warning, "Paste failed!", "Are you sure you copied text?", QMessageBox.Cancel)
            msg.setInformativeText("Only text can be pasted.")
            msg.setDetailedText("Make sure that the data you're trying to paste is Text not Image or something else.")
            msg.exec()
            raise

    def doChangeOp(self):
        chosenMode = self.operationMode.currentText()
        self.Operation = chosenMode
        match self.Operation:
            case "None":
                # Set everything to default
                self.btnEncode.setText(self.defaultTextEncode)
                self.btnEncode.setEnabled(False)
                self.btnDecode.setText(self.defaultTextDecode)
                self.btnDecode.setIcon(self.defaultIconDecode)
                self.btnDecode.setEnabled(False)
                self.btnBruteForce.setEnabled(False)
                self.inputAlphabet.setEnabled(False)
                self.inputKey.setEnabled(False)
                self.inputSalt.setEnabled(False)
                self.inputSaltPattern.setEnabled(False)
            case "Base16" | "Base32" | "Base85" | "Base64":
                self.btnEncode.setText("Encode")
                self.btnEncode.setEnabled(True)
                self.btnDecode.setIcon(self.defaultIconDecode)
                self.btnDecode.setText("Decode")
                self.btnDecode.setEnabled(True)
                self.btnBruteForce.setEnabled(False)
                self.inputAlphabet.setEnabled(True)
                self.inputKey.setEnabled(False)
                self.inputSalt.setEnabled(False)
                self.inputSaltPattern.setEnabled(False)
            case "Caesar Cipher" | "Morse Code" | "Baconian Cipher" | "Vigenere Cipher":
                self.btnEncode.setText("Encrypt")
                self.btnEncode.setEnabled(True)
                self.btnDecode.setIcon(self.defaultIconDecode)
                self.btnDecode.setText("Decrypt")
                self.btnDecode.setEnabled(True)
                self.btnBruteForce.setEnabled(True)
                self.inputAlphabet.setEnabled(True)
                self.inputKey.setEnabled(True)
                self.inputSalt.setEnabled(False)
                self.inputSaltPattern.setEnabled(False)
            case _:
                # Hashes
                self.btnEncode.setText("Hash")
                self.btnEncode.setEnabled(True)
                self.btnDecode.setText("Verify")
                decode_icon = QtGui.QIcon()
                decode_icon.addPixmap(":/assets/Verify.png")
                self.btnDecode.setIcon(decode_icon)
                self.btnDecode.setEnabled(True)
                self.btnBruteForce.setEnabled(True)
                self.inputAlphabet.setEnabled(False)
                self.inputKey.setEnabled(False)
                self.inputSalt.setEnabled(True)
                self.inputSaltPattern.setEnabled(True)

    def doDecode(self):
        print("Decode pressed")

    def doEncode(self):
        print("Encode pressed")

    def doBrute(self):
        print("brute pressed")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec())
