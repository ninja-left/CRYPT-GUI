#!/usr/bin/env python3

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QMainWindow,
    QMessageBox,
    QDialog,
    QFileDialog,
    QComboBox,
)
from PySide6 import QtGui
import pyperclip
import sys
import pathlib
from multiprocessing import Pool, TimeoutError as mpTimeoutError
from pluginlib import PluginImportError
import logging
from time import localtime
from sys import stdout

from modules import functions, ciphers, brute
from modules.design import main_ui, config_ui, bf_ui, resources_rc


brute_force_results = ""


class BadInputError(Exception):
    def __init__(self, message: str = "Input is not valid"):
        self.message = message
        super().__init__(self.message)


class BadKeyError(Exception):
    def __init__(self, message: str = "Key is not valid"):
        self.message = message
        super().__init__(self.message)


class ConfigDialog(QDialog, config_ui.Ui_Dialog):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.connectSignalSlots()
        self.LoadSettings()

    def connectSignalSlots(self):
        self.actionSaveSettings.triggered.connect(self.SaveSettings)
        self.actionLoadSettings.triggered.connect(self.LoadSettings)

    def SaveSettings(self):
        try:
            settings = functions.load_settings()
        except Exception as e:
            MainWindow.showMessageBox(
                self, info="Could not load settings.", detail=str(e)
            )
            return 1
        settings["alphabets"]["base32"] = self.inputAlph_B32.text()
        settings["alphabets"]["base64"] = self.inputAlph_B64.text()
        settings["alphabets"]["base85"] = self.inputAlph_B85.text()
        settings["alphabets"]["default"] = self.inputAlph_Default.text()
        settings["alphabets"]["vigenere"] = self.inputAlph_Vigenere.text()
        settings["default keys"]["vigenere"] = self.inputKey_Vigenere.text()
        settings["default keys"]["caesar cipher"] = self.inputKey_Caesar.text()
        settings["rounds"]["bcrypt"] = self.inputRound_bCrypt.text()
        settings["rounds"]["argon2"] = self.inputRound_Argon2.text()
        settings["rounds"]["pbkdf2"] = self.inputRound_PBKDF2.text()
        settings["brute"]["max length"] = self.inputBf_MaxLength.text()
        settings["brute"]["ramp"] = self.inputBf_Ramp.isChecked()
        settings["brute"]["start length"] = self.inputBf_StartLength.text()
        settings["brute"]["include"]["L"] = self.inputBf_IncludeL.isChecked()
        settings["brute"]["include"]["D"] = self.inputBf_IncludeD.isChecked()
        settings["brute"]["include"]["S"] = self.inputBf_IncludeS.isChecked()
        settings["brute"]["include"]["W"] = self.inputBf_IncludeW.isChecked()
        settings["other"]["font size"] = int(self.inputOther_FontSize.text())
        settings["other"]["paste timeout"] = int(self.inputOther_PasteTimeout.text())
        settings["other"]["default pattern"] = self.inputOther_SaltPattern.text()
        try:
            functions.save_settings(settings)
            MainWindow.showMessageBox(
                self, "Finished!", "Saved Settings.", level=1, button=2
            )
        except Exception as e:
            MainWindow.showMessageBox(
                self, info="Could not save settings.", detail=str(e)
            )

    def LoadSettings(self):
        try:
            settings = functions.load_settings()
        except Exception as e:
            MainWindow.showMessageBox(
                self, info="Could not load settings.", detail=str(e)
            )
            return 1
        self.inputAlph_B32.setText(settings["alphabets"]["base32"])
        self.inputAlph_B64.setText(settings["alphabets"]["base64"])
        self.inputAlph_B85.setText(settings["alphabets"]["base85"])
        self.inputAlph_Default.setText(settings["alphabets"]["default"])
        self.inputAlph_Vigenere.setText(settings["alphabets"]["vigenere"])
        self.inputKey_Vigenere.setText(settings["default keys"]["vigenere"])
        self.inputKey_Caesar.setText(settings["default keys"]["caesar cipher"])
        self.inputRound_bCrypt.setText(settings["rounds"]["bcrypt"])
        self.inputRound_Argon2.setText(settings["rounds"]["argon2"])
        self.inputRound_PBKDF2.setText(settings["rounds"]["pbkdf2"])
        self.inputBf_MaxLength.setText(settings["brute"]["max length"])
        self.inputBf_Ramp.setChecked(settings["brute"]["ramp"])
        self.inputBf_StartLength.setText(settings["brute"]["start length"])
        self.inputBf_IncludeL.setChecked(settings["brute"]["include"]["L"])
        self.inputBf_IncludeD.setChecked(settings["brute"]["include"]["D"])
        self.inputBf_IncludeS.setChecked(settings["brute"]["include"]["S"])
        self.inputBf_IncludeW.setChecked(settings["brute"]["include"]["W"])
        self.inputOther_FontSize.setText(str(settings["other"]["font size"]))
        self.inputOther_PasteTimeout.setText(str(settings["other"]["paste timeout"]))
        self.inputOther_SaltPattern.setText(settings["other"]["default pattern"])


class BruteForceDialog(QDialog, bf_ui.Ui_BruteForceDialog):
    def __init__(self, input_data="", salt="", salt_pattern="", hash_type=""):
        super().__init__()
        self.setupUi(self)
        self.connectSignalSlots()
        self.turnUI(False)
        self.input_data = input_data
        self.salt = salt
        self.salt_pattern = salt_pattern
        self.hash_type = hash_type
        self.mode = ""

        # User settings
        settings = functions.load_settings()
        include = settings["brute"]["include"]

        self.inputMaxLength.setText(settings["brute"]["max length"])
        if settings["brute"]["ramp"]:
            self.inputRamp.setChecked(True)
        self.inputStartLength.setText(settings["brute"]["start length"])
        if include["L"]:
            self.inputLetters.setChecked(True)
        else:
            self.inputLetters.setChecked(False)
        if include["D"]:
            self.inputNumbers.setChecked(True)
        else:
            self.inputNumbers.setChecked(False)
        if include["S"]:
            self.inputSymbols.setChecked(True)
        else:
            self.inputSymbols.setChecked(False)
        if include["W"]:
            self.inputSpaces.setChecked(True)
        else:
            self.inputSpaces.setChecked(False)

    def turnUI(self, To=True):
        self.label.setVisible(To)
        self.label_2.setVisible(To)
        self.label_3.setVisible(To)
        self.label_4.setVisible(To)
        self.label_5.setVisible(To)
        self.btnCrack.setVisible(To)
        self.inputChooseFile.setVisible(To)
        self.inputFilePath.setVisible(To)
        self.progressBar.setVisible(False)
        self.inputLetters.setVisible(To)
        self.inputNumbers.setVisible(To)
        self.inputSpaces.setVisible(To)
        self.inputSymbols.setVisible(To)
        self.inputMaxLength.setVisible(To)
        self.inputRamp.setVisible(To)
        self.inputStartLength.setVisible(To)

    def setUI(self, mode: str):
        if mode != "brute":
            self.label.setVisible(True)
            self.inputChooseFile.setVisible(True)
            self.inputFilePath.setVisible(True)
        else:
            self.label.setVisible(False)
            self.inputChooseFile.setVisible(False)
            self.inputFilePath.setVisible(False)
        if mode == "brute":
            self.label_2.setVisible(True)
            self.label_3.setVisible(True)
            self.label_4.setVisible(True)
            self.label_5.setVisible(True)
            self.inputLetters.setVisible(True)
            self.inputNumbers.setVisible(True)
            self.inputSpaces.setVisible(True)
            self.inputSymbols.setVisible(True)
            self.inputMaxLength.setVisible(True)
            self.inputRamp.setVisible(True)
            self.inputStartLength.setVisible(True)
        else:
            self.label_2.setVisible(False)
            self.label_3.setVisible(False)
            self.label_4.setVisible(False)
            self.label_5.setVisible(False)
            self.inputLetters.setVisible(False)
            self.inputNumbers.setVisible(False)
            self.inputSpaces.setVisible(False)
            self.inputSymbols.setVisible(False)
            self.inputMaxLength.setVisible(False)
            self.inputRamp.setVisible(False)
            self.inputStartLength.setVisible(False)
        self.btnCrack.setVisible(True)
        self.progressBar.setVisible(False)

    def connectSignalSlots(self):
        self.actionChooseFile.triggered.connect(self.ChooseFile)
        self.actionConfigBrute.triggered.connect(self.ConfigBrute)
        self.actionConfigWordList.triggered.connect(self.ConfigWL)
        self.actionConfigRamp.triggered.connect(self.ConfigRamp)
        self.actionCrack.triggered.connect(self.startCrack)

    def ConfigBrute(self):
        if self.inputBrute.isChecked():
            self.inputWordList.setChecked(False)
            self.turnUI()
            self.mode = "brute"
            self.setUI(self.mode)
        else:
            self.turnUI(False)
            self.mode = ""

    def ConfigWL(self):
        if self.inputWordList.isChecked():
            self.inputBrute.setChecked(False)
            self.turnUI()
            self.mode = "word"
            self.setUI(self.mode)
        else:
            self.turnUI(False)
            self.mode = ""

    def ConfigRamp(self):
        if self.inputRamp.isChecked():
            self.label_4.setVisible(True)
            self.inputStartLength.setVisible(True)
        else:
            self.label_4.setVisible(False)
            self.inputStartLength.setText("")
            self.inputStartLength.setVisible(False)

    def startCrack(self):
        global brute_force_results
        input_data = self.input_data
        file_path = self.inputFilePath.text()
        salt = self.salt
        salt_pattern = self.salt_pattern
        if salt:
            if salt_pattern and "SALT" in salt_pattern and "INPUT" in salt_pattern:
                good_data = salt_pattern.replace("SALT", salt).replace(
                    "INPUT", input_data
                )
            else:
                good_data = f"{salt}+{input_data}"
        else:
            good_data = input_data
        hash_type = self.hash_type
        length = self.inputMaxLength.text()
        ramp = self.inputRamp.isChecked()
        start_len = self.inputStartLength.text()
        use_Letters = self.inputLetters.isChecked()
        use_Numbers = self.inputNumbers.isChecked()
        use_Symbols = self.inputSymbols.isChecked()
        use_Space = self.inputSpaces.isChecked()
        self.progressBar.setValue(0)
        self.progressBar.setVisible(True)

        if self.mode == "word":
            # Checks
            if not file_path.strip():
                MainWindow.showMessageBox(
                    self,
                    info="File path is empty.",
                    detail="Enter file path or use Browse button.",
                )
                return 1
            if not pathlib.Path(file_path).absolute().exists():
                MainWindow.showMessageBox(
                    self,
                    info="File doesn't exist. Use the browse button to select one.",
                    detail=f"Path: {pathlib.Path(file_path).absolute()}",
                )
                return 1

            # Main
            total_lines = functions.get_file_lines(file_path)
            i = 0
            with open(file_path, "rb") as file_obj:
                for password in file_obj:
                    i += 1
                    self.progressBar.setValue(i / total_lines * 100)
                    password = password.strip(b"\n")
                    if functions.check_password(password, input_data, hash_type):
                        results = str(password)
                        break
                else:
                    results = ""

            # Results
            if results:
                MainWindow.showMessageBox(
                    self,
                    title="Finished!",
                    text="Found plain text!",
                    info=results,
                    level=1,
                    button=2,
                )
                brute_force_results = results
                self.close()
            else:
                brute_force_results = ""
                MainWindow.showMessageBox(
                    self,
                    "Failed!",
                    "Plain text not found.",
                    "Try another Word list or use brute-force.",
                )

        else:
            # Checks
            if start_len:
                try:
                    start_len = int(start_len)
                except:
                    start_len = 1
            else:
                start_len = 1
            if length:
                try:
                    length = int(length)
                except:
                    MainWindow.showMessageBox(self, info="Length is invalid.")
                    return 1

            # Main
            total_keys = functions.generate_possible_keys(
                length,
                ramp,
                use_Letters,
                use_Symbols,
                use_Numbers,
                use_Space,
                start_len,
            )
            print(f"Total possible keys: {total_keys:,}")
            i = 0
            for password in brute.brute(
                start_len,
                length,
                ramp,
                use_Letters,
                use_Numbers,
                use_Symbols,
                use_Space,
            ):
                i += 1
                self.progressBar.setValue((i + 1) * 100 / total_keys)
                if functions.check_password(password, input_data, hash_type, "b"):
                    decrypted_data = password
                    print("", decrypted_data)
                    break
                else:
                    decrypted_data = ""

            # Results
            if decrypted_data:
                MainWindow.showMessageBox(
                    self,
                    title="Finished!",
                    text="Found plain text!",
                    info=decrypted_data,
                    level=1,
                    button=2,
                )
                brute_force_results = decrypted_data
                self.close()
                return
            else:
                brute_force_results = ""
                MainWindow.showMessageBox(
                    self,
                    "Failed!",
                    "Plain text not found.",
                    "Tweak the options or try using Salts.",
                )

    def ChooseFile(self):
        d = QFileDialog(self)
        d.setFileMode(QFileDialog.ExistingFile)
        d.setAcceptMode(QFileDialog.AcceptOpen)
        d.setNameFilter("Text Files (*.txt *.list *.asc)")
        if d.exec():
            filename = d.selectedFiles()[0]
            self.inputFilePath.setText(filename)


class MainWindow(QMainWindow, main_ui.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.connectSignalSlots()
        self.Operation = ""
        self.defaultTextEncode = "Encode/Encrypt"
        self.defaultTextDecode = "Decode/Decrypt"
        self.defaultIconDecode = QtGui.QIcon()
        self.defaultIconDecode.addPixmap(":/images/Unlocked.png")
        self.pool = Pool()
        self.allHashes = (
            "MD5",
            "MD5 CRYPT",
            "SHA256",
            "SHA256 CRYPT",
            "SHA512",
            "SHA512 CRYPT",
            "bCrypt",
            "Argon2",
            "NT Hash",
            "PBKDF2 SHA256",
            "PBKDF2 SHA512",
        )

        # User settings
        settings = functions.load_settings()
        self.paste_timeout = settings["other"]["paste timeout"]
        self.default_font_size = settings["other"]["font size"]
        self.rounds_bcrypt = settings["rounds"]["bcrypt"]
        self.rounds_argon2 = settings["rounds"]["argon2"]
        self.rounds_pbkdf2 = settings["rounds"]["pbkdf2"]
        self.default_alphabet = settings["alphabets"]["default"]
        self.b32_alphabet = settings["alphabets"]["base32"]
        self.b64_alphabet = settings["alphabets"]["base64"]
        self.b85_alphabet = settings["alphabets"]["base85"]
        self.vigenere_alphabet = settings["alphabets"]["vigenere"]
        self.caesar_key = settings["default keys"]["caesar cipher"]
        self.vigenere_key = settings["default keys"]["vigenere"]
        self.default_pattern = settings["other"]["default pattern"]
        try:
            self.log_level = settings["log level"]
        except KeyError:
            settings["log level"] = "WARNING"
            functions.save_settings(settings)
            self.log_level = "WARNING"

        outputFont = self.outputText.font()
        inputFont = self.inputText.font()
        outputFont.setPointSize(self.default_font_size)
        inputFont.setPointSize(self.default_font_size)
        self.outputText.setFont(outputFont)
        self.inputText.setFont(inputFont)

        # Plugins
        self.LoadPlugins()

        # Error Logging
        TIME = localtime()
        self.Logger = logging.getLogger(__name__)
        self.Logger.setLevel(self.log_level)
        FORMATTER = logging.Formatter(
            "[{asctime}] - {name}:{levelname} - {message}", "%Y-%m-%d %H:%M:%S", "{"
        )
        HANDLE_FILE = logging.FileHandler("events.log", "a", "utf-8", False)
        # HANDLE_FILE = logging.handlers.TimedRotatingFileHandler(
        #     f"Logs/events.log", "D", 1, 5, "utf-8", False, False
        # )
        HANDLE_FILE.setFormatter(FORMATTER)
        HANDLE_CONS = logging.StreamHandler(stdout)
        HANDLE_CONS.setFormatter(FORMATTER)
        self.Logger.addHandler(HANDLE_CONS)
        self.Logger.addHandler(HANDLE_FILE)
        # TODO: Log errors on exceptions

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
            text = pool_result.get(timeout=self.paste_timeout)
            self.inputText.setPlainText(self.inputText.toPlainText() + text)
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
                        self.inputKey.setText(self.vigenere_key)
                    case "Caesar Cipher":
                        self.btnBruteForce.setEnabled(True)
                        self.inputKey.setText(self.caesar_key)
            case _:
                if self.Operation in self.allHashes:
                    self.btnEncode.setText("Hash")
                    self.btnEncode.setEnabled(True)
                    self.btnDecode.setText("Verify")
                    decode_icon = QtGui.QIcon()
                    decode_icon.addPixmap(":/images/Verify.png")
                    self.btnDecode.setIcon(decode_icon)
                    self.btnDecode.setEnabled(True)
                    self.btnBruteForce.setEnabled(True)
                    self.inputAlphabet.setEnabled(False)
                    self.inputKey.setEnabled(False)
                    self.inputSalt.setEnabled(True)
                    self.inputRounds.setEnabled(False)
                    self.inputSaltPattern.setEnabled(True)
                    self.inputSaltPattern.setText(self.default_pattern)
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
                                self.inputRounds.setText(self.rounds_bcrypt)
                            case "Argon2":
                                self.inputRounds.setText(self.rounds_argon2)
                            case "PBKDF2 SHA256" | "PBKDF2 SHA512":
                                self.inputRounds.setText(self.rounds_pbkdf2)
                else:  # Plugins
                    # Loading plugin info
                    t = self.Plugins[self.operationMode.currentData()]()
                    info = t.get_info()
                    print(info)
                    # Everything enabled and texts set to default
                    self.btnEncode.setText(self.defaultTextEncode)
                    self.btnEncode.setEnabled(True)
                    self.btnDecode.setText(self.defaultTextDecode)
                    self.btnDecode.setIcon(self.defaultIconDecode)
                    self.btnDecode.setEnabled(True)
                    self.btnBruteForce.setEnabled(True)
                    self.inputAlphabet.setEnabled(True)
                    self.inputKey.setEnabled(True)
                    self.inputSalt.setEnabled(True)
                    self.inputSaltPattern.setEnabled(True)
                    self.inputPlainText.setEnabled(True)
                    self.inputRounds.setEnabled(True)

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
                    if self.Operation in self.allHashes:
                        display_act = "Verified"
                        if not plain.strip():
                            raise BadInputError("No plain text specified.")
                        if salt:
                            if (
                                salt_pattern
                                and "SALT" in salt_pattern
                                and "INPUT" in salt_pattern
                            ):
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
                    else:  # Plugins
                        decoded = "Plugins"
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
                    if self.Operation in self.allHashes:
                        display_act = "Hashed"
                        if salt:
                            if (
                                salt_pattern
                                and "SALT" in salt_pattern
                                and "INPUT" in salt_pattern
                            ):
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
                    else:  # Plugins
                        encoded = "Plugins"

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
        global brute_force_results
        input_data = self.inputText.toPlainText()
        if not self.checkTextEmpty(
            input_data, "input", "Type some data in input area or use paste button."
        ):
            return 0
        alphabet = self.inputAlphabet.displayText()
        salt = self.inputSalt.displayText()
        salt_pattern = self.inputSaltPattern.displayText()
        match self.Operation:
            case "MD5" | "SHA256" | "SHA512":
                hash_type = self.Operation
            case _:
                hash_type = "other"

        if self.Operation == "Caesar Cipher":
            brute_force_data = dict()
            for key in range(1, len(alphabet) + 1):
                key = -key
                keyMatch = ciphers.caesar_cipher(input_string, key, alphabet)
                brute_force_data[f"Key {abs(key)}"] = keyMatch
            results = brute_force_data
            for i in results.items():
                p = self.outputText.toPlainText()
                self.outputText.setPlainText(f"{p}{i[0]}: {i[1]}\n")
            self.showMessageBox(
                title="Finished",
                text="Decrypted the input.",
                level=1,
                button=2,
            )
        else:
            d = BruteForceDialog(input_data, salt, salt_pattern, hash_type)
            d.exec()
            if brute_force_results:
                self.outputText.setPlainText(brute_force_results)

    def doConfig(self):
        d = ConfigDialog()
        d.exec()

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

    def LoadPlugins(self) -> None:
        # Load and check plugins
        try:
            self.Plugins = functions.get_loader().plugins.Cipher
        except PluginImportError as e:
            if e.friendly:
                sys.exit(e.friendly)
            else:
                raise
        self.Plugins = functions.check_plugins(self.Plugins)

        for i in self.Plugins:
            info = self.Plugins[i]().get_info()
            # info['name'] will be set as item data and can be used to call the plugin
            self.operationMode.addItem(info["config"]["display name"], info["name"])


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
