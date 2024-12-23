#!/usr/bin/env python3

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QMainWindow,
    QMessageBox,
    QFileDialog,
)
from PySide6.QtGui import QIcon
import clipman
from sys import argv, exit
from pathlib import Path
from pluginlib import PluginImportError
from logging import (
    disable,
    CRITICAL,
    NOTSET,
    shutdown,
)
from modules import functions, brute
from modules.design import main_ui, config_ui, bf_ui, resources_rc
from modules.logger_config import get_logger


brute_force_results = ""

Logger = get_logger()

class BadInputError(Exception):
    def __init__(self, message: str = "Input is not valid"):
        self.message = message
        super().__init__(self.message)


class BadKeyError(Exception):
    def __init__(self, message: str = "Key is not valid"):
        self.message = message
        super().__init__(self.message)


# TODO: Update config dialog to match config.yaml and add a new tab for selected plugin's info.yaml configuration
# NOTE 1: new tab should be inactive if no plugin is selected
# NOTE 2: new tab should not include lines for editing license, source, url, version, has decoder, has encoder,
# & has brute variables
class ConfigDialog(QDialog, config_ui.Ui_Dialog):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.connectSignalSlots()
        self.LoadSettings()
        Logger.info("Opened config dialog")

    def connectSignalSlots(self):
        self.actionSaveSettings.triggered.connect(self.SaveSettings)
        self.actionLoadSettings.triggered.connect(self.LoadSettings)

    def SaveSettings(self):
        try:
            settings = functions.load_settings()
            Logger.info("Loaded settings.")
            Logger.debug("settings: %s", settings)
        except Exception as e:
            MainWindow.showMessageBox(
                self, info="Could not load settings.", detail=str(e)
            )
            Logger.error("Could not load settings: %s", str(e), exc_info=1)
            return 1
        settings["alphabets"]["base32"] = self.inputAlph_B32.text()
        settings["alphabets"]["base64"] = self.inputAlph_B64.text()
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
        settings["other"]["log level"] = self.inputOther_LogLevel.currentText()
        if settings['other']['log level'] == "OFF":
            disable(CRITICAL)
        else:
            disable(NOTSET)
            Logger.setLevel(settings['other']['log level'])
        try:
            functions.save_settings(settings)
            MainWindow.showMessageBox(
                self, "Finished!", "Saved Settings.", level=1, button=2
            )
            Logger.info("Saved settings from dialog.")
            Logger.debug("new settings: %s", settings)
        except Exception as e:
            MainWindow.showMessageBox(
                self, info="Could not save settings.", detail=str(e)
            )
            Logger.error("Could not save settings: %s", str(e), exc_info=1)

    def LoadSettings(self):
        try:
            settings = functions.load_settings()
            Logger.info("Loaded settings.")
            Logger.debug("settings: %s", settings)
        except Exception as e:
            MainWindow.showMessageBox(
                self, info="Could not load settings.", detail=str(e)
            )
            Logger.error("Could not load settings: %s", str(e), exc_info=1)
            return 1
        self.inputAlph_B32.setText(settings["alphabets"]["base32"])
        self.inputAlph_B64.setText(settings["alphabets"]["base64"])
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
        self.inputOther_LogLevel.setCurrentText(settings["other"]["log level"])
        Logger.info("Successfully loaded settings to dialog.")


class BruteForceDialog(QDialog, bf_ui.Ui_BruteForceDialog):
    def __init__(self, input_data="", salt="", salt_pattern="", hash_type=""):
        super().__init__()
        self.setupUi(self)
        self.connectSignalSlots()
        Logger.info("Opened brute-force dialog.")

        self.turnUI(False)

        self.input_data = input_data
        self.salt = salt
        self.salt_pattern = salt_pattern
        self.hash_type = hash_type
        self.mode = ""
        Logger.debug(
            "input_data(%s), salt(%s), salt_pattern(%s), hash_type(%s)",
            input_data,
            salt,
            salt_pattern,
            hash_type,
        )

        # User settings
        settings = functions.load_settings()
        Logger.info("Loaded settings")
        Logger.debug("settings[brute]: %s", settings["brute"])
        include = settings["brute"]["include"]

        self.inputMaxLength.setText(settings["brute"]["max length"])
        self.inputRamp.setChecked(True if settings["brute"]["ramp"] else False)
        self.inputStartLength.setText(settings["brute"]["start length"])
        self.inputLetters.setChecked(True if include["L"] else False)
        self.inputNumbers.setChecked(True if include["D"] else False)
        self.inputSymbols.setChecked(True if include["S"] else False)
        self.inputSpaces.setChecked(True if include["W"] else False)
        Logger.info("Successfully Loaded brute options")

    def turnUI(self, To=True):
        Logger.debug("Making everything %s", "hidden" if To == False else "Visible")
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
        Logger.info("Settings labels & inputs based on mode")
        self.label.setVisible(True if mode != "brute" else False)
        self.inputChooseFile.setVisible(True if mode != "brute" else False)
        self.inputFilePath.setVisible(True if mode != "brute" else False)
        Logger.debug(
            "Set `Filename` label, Filepath input & browse button to %s",
            True if mode != "brute" else False,
        )
        self.label_2.setVisible(True if mode == "brute" else False)
        self.label_3.setVisible(True if mode == "brute" else False)
        self.label_4.setVisible(True if mode == "brute" else False)
        self.label_5.setVisible(True if mode == "brute" else False)
        self.inputLetters.setVisible(True if mode == "brute" else False)
        self.inputNumbers.setVisible(True if mode == "brute" else False)
        self.inputSpaces.setVisible(True if mode == "brute" else False)
        self.inputSymbols.setVisible(True if mode == "brute" else False)
        self.inputMaxLength.setVisible(True if mode == "brute" else False)
        self.inputRamp.setVisible(True if mode == "brute" else False)
        self.inputStartLength.setVisible(True if mode == "brute" else False)
        Logger.debug(
            "Set other labels, inputs & checkboxes to %s",
            True if mode == "brute" else False,
        )
        self.btnCrack.setVisible(True)
        self.progressBar.setVisible(False)
        Logger.debug(
            "Set `start cracking` button & progressbar to default (True, False)"
        )
        Logger.info("+++ Done +++")

    def connectSignalSlots(self):
        self.actionChooseFile.triggered.connect(self.ChooseFile)
        self.actionConfigBrute.triggered.connect(self.ConfigBrute)
        self.actionConfigWordList.triggered.connect(self.ConfigWL)
        self.actionConfigRamp.triggered.connect(self.ConfigRamp)
        self.actionCrack.triggered.connect(self.startCrack)

    def ConfigBrute(self):
        if self.inputBrute.isChecked():
            Logger.info("Mode is brute-force")
            self.inputWordList.setChecked(False)
            self.turnUI()
            self.mode = "brute"
            self.setUI(self.mode)
        else:
            self.turnUI(False)
            self.mode = ""

    def ConfigWL(self):
        if self.inputWordList.isChecked():
            Logger.info("Mode is word-list")
            self.inputBrute.setChecked(False)
            self.turnUI()
            self.mode = "word"
            self.setUI(self.mode)
        else:
            self.turnUI(False)
            self.mode = ""

    def ConfigRamp(self):
        Logger.info("Setting Ramp option")
        Logger.debug("Ramp checked: %s", True if self.inputRamp.isChecked() else False)
        self.label_4.setVisible(True if self.inputRamp.isChecked() else False)
        self.inputStartLength.setVisible(True if self.inputRamp.isChecked() else False)
        if not self.inputRamp.isChecked():
            self.inputStartLength.setText("")
            Logger.debug("Emptied `start length` input")

    def startCrack(self):
        global brute_force_results
        Logger.info("Started cracking process")
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
        Logger.debug(
            "Variables: good_data(%s), file_path(%s), salt(%s), salt_pattern(%s), hash_type(%s), length(%s), ramp(%s), start_len(%s), use_Letters(%s), use_Numbers(%s), use_Symbols(%s), use_Space(%s)",
            good_data,
            file_path,
            salt,
            salt_pattern,
            hash_type,
            length,
            ramp,
            start_len,
            use_Letters,
            use_Numbers,
            use_Symbols,
            use_Space,
        )

        if self.mode == "word":
            # Checks
            if not file_path.strip():
                MainWindow.showMessageBox(
                    self,
                    info="File path is empty.",
                    detail="Enter file path or use Browse button.",
                )
                Logger.error("File path is empty.")
                return 1
            if not Path(file_path).absolute().exists():
                MainWindow.showMessageBox(
                    self,
                    info="File doesn't exist. Use the browse button to select one.",
                    detail=f"Path: {Path(file_path).absolute()}",
                )
                Logger.error(
                    "`%s` doesn't exist. Use the browse button to select one.",
                    Path(file_path).absolute(),
                )
                return 1

            # Main
            total_lines = functions.get_file_lines(file_path)
            Logger.debug("Total lines: %s", total_lines)
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
                Logger.info("Results Found!")
                Logger.debug("Results: %s", results)
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
                Logger.warning("No Results Found!")

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
                    Logger.error("Length is invalid", exc_info=1)
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
            Logger.info(f"Total possible keys: {total_keys:,}")
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
                Logger.info("Results Found!")
                Logger.debug("Results: ", decrypted_data)
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
                Logger.warning("No Results Found!")

    def ChooseFile(self):
        d = QFileDialog(self)
        d.setFileMode(QFileDialog.ExistingFile)
        d.setAcceptMode(QFileDialog.AcceptOpen)
        d.setNameFilters(("Text Files (*.txt *.list *.asc)", "Any File (*)"))
        if d.exec():
            filename = d.selectedFiles()[0]
            self.inputFilePath.setText(filename)


class MainWindow(QMainWindow, main_ui.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.connectSignalSlots()
        self.Operation = ""
        self.default_texts = {
            "encode": "Encode/Encrypt",
            "decode": "Decode/Decrypt",
            "brute": "Brute Force",
            "alphabet tip": "",
            "alphabet label": "Alphabet",
            "key tip": "Key to be used for Encryption/Decryption",
            "key label": "Key",
            "arguments tip": "Extra values to be used by plugin",
            "rounds tip": "Usually a number used by hashing algorithm for improved security",
        }
        self.icons = {"decode": QIcon(), "verify": QIcon()}
        self.icons["decode"].addPixmap(":/images/Unlocked.png")
        self.icons["verify"].addPixmap(":/images/Verify.png")
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
        # Set content of About Tab textbox
        self.boxAboutContent.setMarkdown(functions.getMarkdownAbout())

        # User settings
        settings = functions.load_settings()
        self.default_font_size = settings["other"]["font size"]
        self.default_rounds = settings["rounds"]
        self.default_alphabets = settings["alphabets"]
        self.default_keys = settings["default keys"]
        self.default_pattern = settings["other"]["default pattern"]
        try:
            self.log_level = settings["other"]["log level"]
        except KeyError:
            Logger.error("`log level` value not set in config.yaml", exc_info=1)
            settings["other"]["log level"] = "WARNING"
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
        if self.log_level == "OFF":
            disable(CRITICAL)
        else:
            disable(NOTSET)
            Logger.setLevel(self.log_level)

        Logger.debug("Loaded settings: %s", settings)

        # Initializes clipman; (Required)
        clipman.init()

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
            if not "--test" in argv:  # Do not show message box when testing
                self.showMessageBox(info=str(e), detail=detailed)
            Logger.error("Failed to check if text is empty: %s", str(e), exc_info=1)
            return False

    def doCopy(self):
        text = self.outputText.toPlainText()
        if not self.checkTextEmpty(
            text, "output", 'Go to the "Setup" tab to do operations on the input.'
        ):
            return 0
        clipman.copy(text)
        if not "--test" in argv:  # Do not show message box when testing
            self.showMessageBox(
                title="Finished!",
                text="The output data has been copied.",
                level=1,
                button=2,
            )

    def doPaste(self):
        try:
            # The async lines were added due to pyperclip <<Attribute Error: Can't pickle local object 'init_wl_clipboard.<locals>.paste_wl'>> error and are not needed for clipman
            text = clipman.paste()
            Logger.debug("Clipboard data: %s", str(text))
            if text == "":
                raise ValueError("Clipboard is empty.")
            self.inputText.setPlainText(self.inputText.toPlainText() + text)
        except ValueError as e:
            if not "--test" in argv:  # Do not show message box when testing
                self.showMessageBox(info=str(e), detail="Copy something first!")
            Logger.error(str(e), exc_info=1)
        except Exception as e:
            if not "--test" in argv:  # Do not show message box when testing
                self.showMessageBox(
                    info="Copied data is not text.",
                    detail="Make sure that the data you're trying to paste is Text not Image or something else.",
                )
            Logger.error(str(e), exc_info=1)

    def doChangeOp(self):
        chosenMode = self.operationMode.currentText()
        self.Operation = chosenMode
        if self.Operation == "None":
            # Set everything to default
            self.btnEncode.setText(self.default_texts["encode"])
            self.btnEncode.setEnabled(False)
            self.btnDecode.setText(self.default_texts["decode"])
            self.btnDecode.setIcon(self.icons["decode"])
            self.btnDecode.setEnabled(False)
            self.btnBruteForce.setText(self.default_texts["brute"])
            self.btnBruteForce.setEnabled(False)
            self.inputAlphabet.setEnabled(False)
            self.inputAlphabet.setText("")
            self.inputAlphabet.setPlaceholderText(self.default_texts["alphabet tip"])
            self.labelAlphabet.setText(self.default_texts["alphabet label"])
            self.inputKey.setEnabled(False)
            self.inputKey.setText("")
            self.inputKey.setPlaceholderText(self.default_texts["key tip"])
            self.labelKey.setText(self.default_texts["key label"])
            self.inputSalt.setEnabled(False)
            self.inputSalt.setText("")
            self.inputSaltPattern.setEnabled(False)
            self.inputSaltPattern.setText("")
            self.inputPlainText.setEnabled(False)
            self.inputPlainText.setText("")
            self.inputRounds.setEnabled(False)
            self.inputRounds.setText("")
            self.inputRounds.setPlaceholderText(self.default_texts["rounds tip"])
            return None
        # Loading plugin info
        t = self.Plugins[self.operationMode.currentData()]()
        info = t.get_info()
        Logger.info("Chose `%s` plugin", info["config"]["display name"])
        Logger.debug(f"Plugin info: {info}")
        # Configure labels & buttons as specified by the plugin
        # TODO: Document and add variables (for encode, decode, brute, alphabet, & key) to change default labels
        self.btnEncode.setEnabled(x := info["config"]["has encoder"])
        if x and functions.hasKey(info["config"], "encode label"):
            self.btnEncode.setText(info["config"]["encode label"])
        else:
            self.btnEncode.setText(self.default_texts["encode"])
        self.btnDecode.setEnabled(x := info["config"]["has decoder"])
        if x and functions.hasKey(info["config"], "decode label"):
            self.btnDecode.setText(info["config"]["decode label"])
        else:
            self.btnDecode.setText(self.default_texts["decode"])
        # TODO: add variable to change icon to info.yaml
        if x and functions.hasKey(info["config"], "decode icon"):
            try:
                Logger.debug(
                    "Setting decode icon to `%s`",
                    x := str(info["config"]["decode icon"]),
                )
                self.btnDecode.setIcon(self.icons[x])
            except KeyError:
                # Set to default if icon is not found
                Logger.warning("Icon `%s` is not found; Setting to `decode`", x)
                self.btnDecode.setIcon(self.icons["decode"])
        else:
            self.btnDecode.setIcon(self.icons["decode"])
        self.btnBruteForce.setEnabled(x := info["config"]["has brute"])
        if x and functions.hasKey(info["config"], "brute label"):
            self.btnBruteForce.setText(str(info["config"]["brute label"]))
        else:
            self.btnBruteForce.setText(self.default_texts["brute"])
        self.inputAlphabet.setEnabled(x := info["config"]["can change alphabet"])
        # Set alphabet input placeholder text if specified by plugin
        if x and functions.hasKey(info["config"], "alphabet tip"):
            self.inputAlphabet.setPlaceholderText(str(info["config"]["alphabet tip"]))
        else:
            self.inputAlphabet.setPlaceholderText(self.default_texts["alphabet tip"])
        # Set alphabet label text if specified by plugin
        if x and functions.hasKey(info["config"], "alphabet label"):
            self.labelAlphabet.setText(str(info["config"]["alphabet label"]))
        else:
            self.labelAlphabet.setText(self.default_texts["alphabet label"])
        # Set alphabet input box value if plugin uses alphabets
        if x:
            if (alph := info["config"]["alphabet"]) == "$default$":
                Logger.debug("Tried to set plugin's default alphabet...")
                # Try to set the default
                if functions.hasKey(self.default_alphabets["plugins"], info["name"]):
                    # Check if a default alphabet exists for the plugin (specified in config.yaml)
                    self.inputAlphabet.setText(
                        self.default_alphabets["plugins"][info["name"]]
                    )
                    Logger.debug("and did it.")
                else:
                    Logger.debug("and failed. Tried to use `alt alphabet`...")
                    # If not, try to set the `alt alphabet` if it is set (in plugin's info.yaml)
                    if (
                        functions.hasKey(info["config"], "alt alphabet")
                        and info["config"]["alt alphabet"] != ""
                    ):
                        alph = info["config"]["alt alphabet"]
                        Logger.debug("and did it.")
                    else:
                        Logger.debug("and failed. Switched to user's default alphabet")
                        # If it's not set, use user's default (which is specified in config.yaml)
                        alph = self.default_alphabets["default"]
                    self.inputAlphabet.setText(alph)
                    Logger.debug("Set alphabet to %s", alph)
                    # Save the alphabet as plugin's default
                    d = functions.load_settings()
                    d["alphabets"]["plugins"][info["name"]] = alph
                    Logger.debug(d)
                    functions.save_settings(d)
                    del d
            else:  # set the alphabet specified in plugin's info.yaml
                self.inputAlphabet.setText(alph)
            del alph
        else:
            self.inputAlphabet.setText("")
        self.inputKey.setEnabled(x := info["config"]["uses keys"])
        # Set key label text if specified by plugin
        if x and functions.hasKey(info["config"], "key label"):
            self.labelKey.setText(str(info["config"]["key label"]))
        else:
            self.labelKey.setText(self.default_texts["key label"])
        # Set key input placeholder text if specified by plugin
        if x and functions.hasKey(info["config"], "key tip"):
            self.inputKey.setPlaceholderText(str(info["config"]["key tip"]))
        else:
            self.inputKey.setPlaceholderText(self.default_texts["key tip"])
        # Set key input value if plugin uses keys
        if x:
            if (k := info["config"]["default key"]) == "$default$":
                Logger.debug("Tried to set plugin's default key...")
                # Try to set the default
                if functions.hasKey(self.default_keys["plugins"], info["name"]):
                    # Check if a default key exists for the plugin (specified in config.yaml)
                    self.inputKey.setText(
                        str(self.default_keys["plugins"][info["name"]])
                    )
                    Logger.debug("and did it.")
                else:
                    Logger.debug("and failed. Tried to use `alt key`...")
                    # If not, try to set the `alt key` if it is set (in plugin's info.yaml) and not empty
                    if (
                        functions.hasKey(info["config"], "alt key")
                        and info["config"]["alt key"] != ""
                    ):
                        k = info["config"]["alt key"]
                        Logger.debug("and did it.")
                    else:
                        Logger.debug("and failed. Switched to user's default key")
                        # If it's not set, use user's default (which is specified in config.yaml)
                        k = self.default_keys["default"]
                    self.inputKey.setText(str(k))
                    Logger.debug("Set key to %s", k)
                    # Save the key as plugin's default
                    d = functions.load_settings()
                    d["default keys"]["plugins"][info["name"]] = k
                    Logger.debug(d)
                    functions.save_settings(d)
                    del d
            else:  # set the key specified in plugin's info.yaml
                self.inputKey.setText(str(k))
            del k
        else:
            self.inputKey.setText("")
        self.inputSalt.setEnabled(info["config"]["uses salt"])
        self.inputSaltPattern.setEnabled(info["config"]["uses salt"])
        if info["config"]["uses salt"]:
            if functions.hasKey(info["config"], "default pattern"):
                self.inputSaltPattern.setText(info["config"]["default pattern"])
            else:
                self.inputSaltPattern.setText(self.default_pattern)
        self.inputPlainText.setEnabled(info["config"]["uses plaintext"])
        self.inputRounds.setEnabled(x := info["config"]["uses rounds"])
        # Set rounds input placeholder if set py plugin
        if x and functions.hasKey(info["config"], "rounds tip"):
            self.inputRounds.setPlaceholderText(str(info["config"]["rounds tip"]))
        else:
            self.inputRounds.setPlaceholderText(self.default_texts["rounds tip"])
        # Set rounds if plugin uses them
        if x:
            if (R := info["config"]["default rounds"]) == "$default$":
                Logger.debug("Tried to set plugin's default rounds...")
                # Try to set the default
                if functions.hasKey(self.default_rounds, info["name"]):
                    # Check if a default rounds exists for the plugin (specified in config.yaml)
                    self.inputRounds.setText(str(self.default_rounds[info["name"]]))
                    Logger.debug("and did it.")
                else:
                    Logger.debug("and failed. Tried to use `alt rounds`...")
                    # If not, try to set the `alt rounds` if it is set (in plugin's info.yaml) and not empty
                    if (
                        functions.hasKey(info["config"], "alt rounds")
                        and info["config"]["alt rounds"] != ""
                    ):
                        R = info["config"]["alt rounds"]
                        Logger.debug("and did it.")
                    else:
                        Logger.debug("and failed. Aborting.")
                        Logger.warning("`%s` has no `alt rounds`", info["name"])
                        R = ""
                    self.inputRounds.setText(str(R))
                    Logger.debug("Set rounds to %s", R)
                    if R:
                        # Save the rounds as plugin's default if not empty
                        d = functions.load_settings()
                        d["rounds"][info["name"]] = R
                        Logger.debug(d)
                        functions.save_settings(d)
                        del d
            else:  # set the rounds specified in plugin's info.yaml
                self.inputRounds.setText(str(R))
            del R
        del info, t, x

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
        Logger.info("Decoding...")
        Logger.debug(
            "with: input_data(%s), alphabet(%s), current_key(%s), salt(%s), salt_pattern(%s), plain(%s)",
            input_data,
            alphabet,
            current_key,
            salt,
            salt_pattern,
            plain,
        )
        try:
            if salt:
                Logger.debug("Adding salt")
                if salt_pattern and "SALT" in salt_pattern and "INPUT" in salt_pattern:
                    good_plain = salt_pattern.replace("SALT", salt).replace(
                        "INPUT", plain
                    )
                else:
                    good_plain = f"{salt}+{plain}"
            else:
                good_plain = plain
            Logger.debug("good_plain(%s)", good_plain)
            t = self.Plugins[self.operationMode.currentData()]()
            info = t.get_info()
            Logger.debug(info)
            if info["config"]["uses plaintext"] and not plain.strip():
                raise BadInputError("No plain text specified.")
            decoded = t.decode(
                input_data,
                key=current_key,
                alphabet=alphabet,
                plaintext=good_plain,
            )
            display_act = f"{info['config']['display name']}: decoded"
            self.outputText.setPlainText(decoded)
            self.showMessageBox(
                title="Finished!", text=f"{display_act} the input.", level=1, button=2
            )
            Logger.info("%s the input.", display_act)
            Logger.debug(f"{display_act}: {input_data}\n->\n{decoded}")
        except BadKeyError as e:
            self.showMessageBox(info="Provide a key.", detail=str(e))
            Logger.error(str(e), exc_info=1)
        except BadInputError as e:
            self.showMessageBox(info=str(e))
            Logger.error(str(e), exc_info=1)
        except Exception as e:
            self.showMessageBox(
                info=f"Something's probably wrong with the input.",
                detail=str(e),
            )
            Logger.error("Could not decode input: %s", str(e), exc_info=1)
        finally:
            del info, decoded

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
        Logger.info("Decoding...")
        Logger.debug(
            "with: input_data(%s), alphabet(%s), current_key(%s), salt(%s), salt_pattern(%s), rounds(%s)",
            input_data,
            alphabet,
            current_key,
            salt,
            salt_pattern,
            rounds,
        )
        try:
            if salt:
                Logger.debug("Adding salt...")
                if salt_pattern and "SALT" in salt_pattern and "INPUT" in salt_pattern:
                    good_data = salt_pattern.replace("SALT", salt).replace(
                        "INPUT", input_data
                    )
                else:
                    good_data = f"{salt}+{input_data}"
            else:
                good_data = input_data
            Logger.debug("good_data(%s)", good_data)
            t = self.Plugins[self.operationMode.currentData()]()
            info = t.get_info()
            Logger.info("Using `%s` plugin", info["config"]["display name"])
            Logger.debug("Plugin info: %s", info)
            encoded = t.encode(
                good_data, key=current_key, alphabet=alphabet, rounds=rounds
            )
            display_act = f"{info['config']['display name']}: encoded"

            self.outputText.setPlainText(encoded)
            self.showMessageBox(
                title="Finished!", text=f"{display_act} the input.", level=1, button=2
            )
            Logger.info("Successfully %s", display_act)
            Logger.debug(f"{display_act} <<{input_data}>>: <<{encoded}>>")
        except BadKeyError as e:
            self.showMessageBox(info="Provide a key.", detail=str(e))
            Logger.error(str(e), exc_info=1)
        except Exception as e:
            self.showMessageBox(detail=str(e))
            Logger.error(str(e), exc_info=1)
        finally:
            del info, encoded

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
        rounds = self.inputRounds.displayText()
        Logger.info("Brute-forcing...")
        match self.Operation:
            case "MD5" | "SHA256" | "SHA512":
                hash_type = self.Operation
            case _:
                hash_type = "other"
        Logger.debug(
            "with: input_data(%s), alphabet(%s), salt(%s), salt_pattern(%s), rounds(%s), hash_type(%s)",
            input_data,
            alphabet,
            salt,
            salt_pattern,
            rounds,
            hash_type,
        )

        if self.Operation in self.allHashes:
            d = BruteForceDialog(input_data, salt, salt_pattern, hash_type)
            d.exec()
            if brute_force_results:
                self.outputText.setPlainText(brute_force_results)
                Logger.info("Successfully brute-forced.")
                Logger.debug(f"Brute-forced: {input_data} -> {brute_force_results}")
        else:  # Plugins
            t = self.Plugins[self.operationMode.currentData()]()
            info = t.get_info()
            Logger.debug(info)
            if info["config"]["uses salt"] and salt:
                if salt_pattern and "SALT" in salt_pattern and "INPUT" in salt_pattern:
                    input_data = salt_pattern.replace("SALT", salt).replace(
                        "INPUT", input_data
                    )
                else:
                    input_data = f"{salt}+{input_data}"
            results = t.brute_force(input_data, alphabet=alphabet, rounds=rounds)
            if results:
                self.showMessageBox("Finished", "Decoded the input.", level=1, button=2)
                if type(results) == dict:
                    for i in results.items():
                        p = self.outputText.toPlainText()
                        self.outputText.setPlainText(f"{p}{i[0]}: {i[1]}\n")
                else:
                    self.outputText.setPlainText(results)
                Logger.info("Successfully brute-forced.")
                Logger.debug(
                    f"{info['config']['display name']} Brute-forced: {input_data} -> {results}"
                )
            del info, results

    def doConfig(self) -> int:
        """Executes ConfigDialog class"""
        try:
            d = ConfigDialog()
            d.exec()
        except Exception as e:
            Logger.error(e, exc_info=1)

    def doZoomIn(self) -> None:
        """Get the current font of the TextBoxes, Increment it by 1, Set the new font"""
        Logger.info("Zooming-In")
        outputFont = self.outputText.font()
        inputFont = self.inputText.font()
        Logger.debug(
            "Current Font sizes: output(%s), input(%s)",
            outputFont.pointSize(),
            inputFont.pointSize(),
        )
        outputFont.setPointSize(outputFont.pointSize() + 1)
        inputFont.setPointSize(inputFont.pointSize() + 1)
        Logger.debug(
            "New Font sizes: output(%s), input(%s)",
            outputFont.pointSize(),
            inputFont.pointSize(),
        )
        self.outputText.setFont(outputFont)
        self.inputText.setFont(inputFont)
        Logger.info("Done")

    def doZoomOut(self) -> None:
        """Get the current font of the TextBoxes, Decrement it by 1, Set the new font"""
        Logger.info("Zooming-Out")
        outputFont = self.outputText.font()
        inputFont = self.inputText.font()
        Logger.debug(
            "Current Font sizes: output(%s), input(%s)",
            outputFont.pointSize(),
            inputFont.pointSize(),
        )
        outputFont.setPointSize(outputFont.pointSize() - 1)
        inputFont.setPointSize(inputFont.pointSize() - 1)
        Logger.debug(
            "New Font sizes: output(%s), input(%s)",
            outputFont.pointSize(),
            inputFont.pointSize(),
        )
        self.outputText.setFont(outputFont)
        self.inputText.setFont(inputFont)
        Logger.info("Done")

    def LoadPlugins(self) -> None:
        """Loads and checks plugins"""
        # Load settings for recording loaded plugins
        settings = functions.load_settings()
        if type(Loaded := settings["other"]["loaded plugins"]) == list:
            flag_NO_LOADED = False
            Loaded = Loaded.copy()
        else:
            flag_NO_LOADED = True
            Loaded = list()
        try:
            self.Plugins = functions.get_loader().plugins.Cipher
            Logger.info("Plugin loader is ready")
            Logger.debug("self.Plugins: %s", self.Plugins)
        except PluginImportError as e:
            if e.friendly:
                Logger.critical(str(e.friendly), exc_info=1)
            else:
                Logger.critical(str(e), exc_info=1)
            exit(1)
        self.Plugins = functions.check_plugins(self.Plugins)
        Logger.info("Checked plugins")
        Logger.debug("New self.Plugins: %s", self.Plugins)
        _A = self.boxAboutContent.toMarkdown()
        _A += "## Plugins"
        # NOTE: Added the 3 variables below to avoid error when deleting variables at the end
        _URL = ""
        _LICENSE = ""
        info = dict()

        for i in self.Plugins:
            info = self.Plugins[i]().get_info()
            Logger.info("Loading `%s`", info["config"]["display name"])
            # info['name'] will be set as item data and can be used to call the plugin
            self.operationMode.addItem(info["config"]["display name"], info["name"])
            # add plugin source URL (if set) and license to About tab
            try:
                _URL = f"\n\nSource: {info['source url']}"
            except KeyError:
                _URL = ""
            _LICENSE = f"\n\n{info['license']}"
            info.pop("license")
            # NOTE 1: Remove license variables from plugin's info because they
            # are long and pollute the log file and are only needed for being
            # saved to About Tab content (Which is already done above)
            # NOTE 2: Remove the license here so it doesn't have to be removed
            # later thus avoiding a KeyError when loading plugins in
            # doChangeOp() & 3 other functions more than once
            _A += f"\n### {info['config']['display name']}{_URL}{_LICENSE}"
            self.boxAboutContent.setMarkdown(_A)
            if not info["name"] in Loaded:
                Logger.info("Saving `%s` as Loaded", info["name"])
                Loaded.append(info["name"])
            Logger.info("Done")
        if (
            not flag_NO_LOADED
            and Loaded.copy() != settings["other"]["loaded plugins"].copy()
        ) or flag_NO_LOADED:
            settings["other"]["loaded plugins"] = Loaded
            functions.save_settings(settings)
            Logger.info("Saved loaded plugins to config file")
            Logger.debug("Loaded plugins: %s", Loaded)
        Logger.info("Loaded all plugins")
        del _A, _URL, _LICENSE, info


if __name__ == "__main__":
    if "--test" in argv:
        exit(functions.run_tests())
    Logger.info("---- Crypt Launched ----")
    app = QApplication(argv)
    win = MainWindow()
    win.show()
    x = app.exec()
    Logger.info("---- Crypt Shutdown ----")
    shutdown()
    exit(x)
