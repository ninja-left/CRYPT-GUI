#!/usr/bin/env python3

from PySide6.QtWidgets import QApplication, QDialog, QMainWindow, QMessageBox
from PySide6 import QtGui
import pyperclip
import sys
from multiprocessing import Pool, TimeoutError as mpTimeoutError
from string import ascii_letters, ascii_uppercase

from modules import main_ui, resources_rc, cracker, ciphers


class BadInputError(Exception):
    def __init__(self, message: str = "Input is not valid"):
        self.message = message
        super().__init__(self.message)


class BadKeyError(Exception):
    def __init__(self, message: str = "Key is not valid"):
        self.message = message
        super().__init__(self.message)


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
        self.default_rounds_bcrypt = "14"
        self.default_rounds_argon2 = "4"
        self.default_rounds_pbkdf2 = "30000"

        # TODO: User should be able to change default alphabets
        # TODO: Read default alphabets from a config file
        self.default_alphabet = ascii_letters
        self.vigenere_alphabet = ascii_uppercase
        self.b32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        self.b64_alphabet = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        )
        self.b85_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+-;<=>?@^_`{|}~"

    def connectSignalSlots(self):
        self.actionCopy.triggered.connect(self.doCopy)
        self.actionPaste.triggered.connect(self.doPaste)
        self.actionEncode.triggered.connect(self.doEncode)
        self.actionDecode.triggered.connect(self.doDecode)
        self.actionBrute.triggered.connect(self.doBrute)
        self.actionOperationChanged.triggered.connect(self.doChangeOp)
        self.actionConfig.triggered.connect(self.doConfig)
        self.actionZoomOut.triggered.connect(self.doZoomOut)
        self.actionZoomIn.triggered.connect(self.doZoomIn)

    def showMessageBox(
        self,
        title: str = "Aborted!",
        text: str = "Could not finish task.",
        info: str = "",
        detail: str = "",
        level: int = 2,
        button: int = 1,
    ):
        """
        * title: Message title
        * info: Informative text
        * detail: Detailed text
        * level: Should be 1-3 (Information: 1, Warning: 2, Critical: 3)
        * button: Should be 1 or 2 (Cancel: 1, Ok: 2)
        """
        if button == 1:
            msgButton = QMessageBox.Cancel
        else:
            msgButton = QMessageBox.Ok
        match level:
            case 1:
                msgLevel = QMessageBox.Information
            case 2:
                msgLevel = QMessageBox.Warning
            case 3:
                msgLevel = QMessageBox.Critical

        msg = QMessageBox(msgLevel, title, text, msgButton)
        msg.setInformativeText(info)
        msg.setDetailedText(detail)
        msg.exec()

    def checkTextEmpty(self, textToCheck: str, area: str, detailed: str):
        try:
            if not textToCheck.strip():
                raise Exception(f"There's no data in {area} area.")
            return True
        except Exception as e:
            self.showMessageBox(info=str(e), detail=detailed)
            return False

    def doCopy(self):
        text = self.outputText.toPlainText()
        if not self.checkTextEmpty(
            text, "output", 'Go to the "Setup" tab to do operations on the input.'
        ):
            return 0
        pyperclip.copy(text)
        self.showMessageBox(
            title="Finished!",
            text="The output data has been copied.",
            level=1,
            button=2,
        )

    def doPaste(self):
        try:
            pool_result = self.pool.apply_async(pyperclip.paste)
            pool_result.wait(1)
            text = pool_result.get(timeout=self.pasteTimeout)
            self.inputText.setPlainText(self.inputText.toPlainText() + text)
            self.showMessageBox(
                title="Finished!",
                text="Pasted data into the input area.",
                level=1,
                button=2,
            )
        except mpTimeoutError:
            self.showMessageBox(
                info="Pasting took too long to finish.",
                detail="This could happen if there's no data in Clipboard. Make sure to copy something first.",
            )
            raise
        except:
            self.showMessageBox(
                info="Copied data is not text.",
                detail="Make sure that the data you're trying to paste is Text not Image or something else.",
            )
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
                self.inputPlainText.setEnabled(False)
                self.inputRounds.setEnabled(False)
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
                self.inputPlainText.setEnabled(False)
                match self.Operation:
                    case "Base16":
                        self.inputAlphabet.setText("")
                        self.inputAlphabet.setEnabled(False)
                    case "Base32":
                        self.inputAlphabet.setText(self.b32_alphabet)
                    case "Base64":
                        self.inputAlphabet.setText(self.b64_alphabet)
                    case "Base85":
                        self.inputAlphabet.setText(self.b85_alphabet)
            case "Caesar Cipher" | "Morse Code" | "Baconian Cipher" | "Vigenere Cipher":
                self.btnEncode.setText("Encrypt")
                self.btnEncode.setEnabled(True)
                self.btnDecode.setIcon(self.defaultIconDecode)
                self.btnDecode.setText("Decrypt")
                self.btnDecode.setEnabled(True)
                self.btnBruteForce.setEnabled(False)
                self.inputAlphabet.setText(self.default_alphabet)
                self.inputAlphabet.setEnabled(True)
                self.inputKey.setEnabled(True)
                self.inputSalt.setEnabled(False)
                self.inputSaltPattern.setEnabled(False)
                self.inputPlainText.setText("")
                self.inputPlainText.setEnabled(False)
                match self.Operation:
                    case "Morse Code" | "Baconian Cipher":
                        self.inputAlphabet.setEnabled(False)
                        self.inputKey.setEnabled(False)
                    case "Vigenere Cipher":
                        self.inputAlphabet.setText(self.vigenere_alphabet)
                    case "Caesar Cipher":
                        self.btnBruteForce.setEnabled(True)
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
                self.inputRounds.setEnabled(False)
                self.inputSaltPattern.setEnabled(True)
                self.inputPlainText.setEnabled(True)
                if self.Operation in [
                    "bCrypt",
                    "Argon2",
                    "PBKDF2 SHA256",
                    "PBKDF2 SHA512",
                ]:
                    self.inputSalt.setEnabled(False)
                    self.inputSaltPattern.setEnabled(False)
                    self.inputRounds.setEnabled(True)
                    match self.Operation:
                        case "bCrypt":
                            self.inputRounds.setText(self.default_rounds_bcrypt)
                        case "Argon2":
                            self.inputRounds.setText(self.default_rounds_argon2)
                        case "PBKDF2 SHA256" | "PBKDF2 SHA512":
                            self.inputRounds.setText(self.default_rounds_pbkdf2)

    def doDecode(self):
        input_data = self.inputText.toPlainText()
        if not self.checkTextEmpty(
            input_data, "input", "Type some data in input area or use paste button."
        ):
            return 0
        alphabet = self.inputAlphabet.displayText()
        current_key = self.inputKey.displayText()
        salt = self.inputSalt.displayText()
        salt_pattern = self.inputSaltPattern.displayText()
        plain = self.inputPlainText.displayText()
        display_act = "Decoded"
        decoded = ""
        hashed_plain = ""
        try:
            match self.Operation:
                case "Base16":
                    decoded = ciphers.base16_decode(input_data)
                case "Base32":
                    decoded = ciphers.base32_decode(input_data)
                case "Base64":
                    decoded = ciphers.base64_decode(input_data, alphabet)
                case "Base85":
                    decoded = ciphers.base85_decode(input_data)
                case "Caesar Cipher":
                    if current_key:
                        current_key = -int(current_key)
                    else:
                        raise BadKeyError("No key specified.")
                    decoded = ciphers.caesar_cipher(input_data, current_key, alphabet)
                    display_act = "Decrypted"
                case "Morse Code":
                    decoded = ciphers.mc_decrypt(input_data)
                    if decoded.lower() == input_data:
                        raise BadInputError("Input is not Morse Code.")
                case "Baconian Cipher":
                    decoded = ciphers.bacon_decode(input_data)
                case "Vigenere Cipher":
                    decoded = ciphers.vig_cipher(input_data, current_key, alphabet, "d")
                    display_act = "Decrypted"
                case _:
                    # Hashes
                    display_act = "Verified"
                    if not plain.strip():
                        raise BadInputError("No plain text specified.")
                    if salt:
                        if salt_pattern:
                            good_plain = salt_pattern.replace("SALT", salt).replace(
                                "INPUT", plain
                            )
                        else:
                            good_plain = f"{salt}+{plain}"
                    else:
                        good_plain = plain
                    match self.Operation:
                        case "MD5":
                            hashed_plain = ciphers.md5(good_plain)
                        case "MD5 CRYPT":
                            hashed_plain = ciphers.md5_crypt(good_plain)
                        case "SHA256":
                            hashed_plain = ciphers.sha256(good_plain)
                        case "SHA256 CRYPT":
                            hashed_plain = ciphers.sha256_crypt(good_plain)
                        case "SHA512":
                            hashed_plain = ciphers.sha512(good_plain)
                        case "SHA512 CRYPT":
                            hashed_plain = ciphers.sha512_crypt(good_plain)
                        case "bCrypt":
                            hashed_plain = ciphers.bcrypt_verify(plain, input_data)
                        case "Argon2":
                            hashed_plain = ciphers.argon2_verify(plain, input_data)
                        case "NT Hash":
                            hashed_plain = ciphers.nthash(good_plain)
                        case "PBKDF2 SHA256":
                            hashed_plain = ciphers.pbkdf2_256_verify(plain)
                        case "PBKDF2 SHA512":
                            hashed_plain = ciphers.pbkdf2_512_verify(plain)
                        case _:
                            hashed_plain = ""

                    if self.Operation in [
                        "bCrypt",
                        "Argon2",
                        "PBKDF2 SHA256",
                        "PBKDF2 SHA512",
                    ]:
                        if hashed_plain:
                            decoded = f"The Hash matches the plain text."
                        else:
                            decoded = f"The Hash does not match the plain text."
                    else:
                        if hashed_plain == input_data:
                            decoded = f"The Hash matches the plain text:\n{input_data} = {hashed_plain}"
                        else:
                            decoded = f"The Hash does not match the plain text:\n{input_data} != {hashed_plain}"
            self.outputText.setPlainText(decoded)
            self.showMessageBox(
                title="Finished!", text=f"{display_act} the input.", level=1, button=2
            )
        except BadKeyError as e:
            self.showMessageBox(info="Provide a key.", detail=str(e))
            raise
        except BadInputError as e:
            self.showMessageBox(info=str(e))
            raise
        except Exception as e:
            self.showMessageBox(
                info=f"Something's probably wrong with the input.",
                detail=str(e),
            )
            raise

    def doEncode(self):
        input_data = self.inputText.toPlainText()
        if not self.checkTextEmpty(
            input_data, "input", "Type some data in input area or use paste button."
        ):
            return 0
        alphabet = self.inputAlphabet.displayText()
        current_key = self.inputKey.displayText()
        salt = self.inputSalt.displayText()
        salt_pattern = self.inputSaltPattern.displayText()
        display_act = "Encoded"
        rounds = self.inputRounds.displayText()
        encoded = ""
        try:
            match self.Operation:
                case "Base16":
                    encoded = ciphers.base16_encode(input_data)
                case "Base32":
                    encoded = ciphers.base32_encode(input_data)
                case "Base64":
                    encoded = ciphers.base64_encode(input_data, alphabet)
                case "Base85":
                    encoded = ciphers.base85_encode(input_data)
                case "Caesar Cipher":
                    if current_key:
                        current_key = int(current_key)
                    else:
                        raise BadKeyError("No key specified.")
                    encoded = ciphers.caesar_cipher(input_data, current_key, alphabet)
                    display_act = "Encrypted"
                case "Morse Code":
                    encoded = ciphers.mc_encrypt(input_data)
                case "Baconian Cipher":
                    encoded = ciphers.bacon_encode(input_data)
                case "Vigenere Cipher":
                    encoded = ciphers.vig_cipher(input_data, current_key, alphabet, "e")
                    display_act = "Encrypted"
                case _:
                    # Hashes
                    display_act = "Hashed"
                    if salt:
                        if salt_pattern:
                            good_data = salt_pattern.replace("SALT", salt).replace(
                                "INPUT", input_data
                            )
                        else:
                            good_data = f"{salt}+{input_data}"
                    else:
                        good_data = input_data
                    match self.Operation:
                        case "MD5":
                            encoded = ciphers.md5(good_data)
                        case "MD5 CRYPT":
                            encoded = ciphers.md5_crypt(good_data)
                        case "SHA256":
                            encoded = ciphers.sha256(good_data)
                        case "SHA256 CRYPT":
                            encoded = ciphers.sha256_crypt(good_data)
                        case "SHA512":
                            encoded = ciphers.sha512(good_data)
                        case "SHA512 CRYPT":
                            encoded = ciphers.sha512_crypt(good_data)
                        case "bCrypt":
                            encoded = ciphers.bcrypt_hash(input_data, rounds)
                        case "Argon2":
                            encoded = ciphers.argon2_hash(input_data, rounds)
                        case "NT Hash":
                            encoded = ciphers.nthash(good_data)
                        case "PBKDF2 SHA256":
                            encoded = ciphers.pbkdf2_256_hash(input_data, rounds)
                        case "PBKDF2 SHA512":
                            encoded = ciphers.pbkdf2_512_hash(input_data, rounds)

            self.outputText.setPlainText(encoded)
            self.showMessageBox(
                title="Finished!", text=f"{display_act} the input.", level=1, button=2
            )
        except BadKeyError as e:
            self.showMessageBox(info="Provide a key.", detail=str(e))
            raise
        except Exception as e:
            self.showMessageBox(detail=str(e))
            raise

    def doBrute(self):
        print("brute pressed")

    def doConfig(self):
        print("config pressed")

    def doZoomIn(self):
        outputFont = self.outputText.font()
        inputFont = self.inputText.font()
        outputFont.setPointSize(outputFont.pointSize() + 1)
        inputFont.setPointSize(inputFont.pointSize() + 1)
        self.outputText.setFont(outputFont)
        self.inputText.setFont(inputFont)

    def doZoomOut(self):
        outputFont = self.outputText.font()
        inputFont = self.inputText.font()
        outputFont.setPointSize(outputFont.pointSize() - 1)
        inputFont.setPointSize(inputFont.pointSize() - 1)
        self.outputText.setFont(outputFont)
        self.inputText.setFont(inputFont)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec())
