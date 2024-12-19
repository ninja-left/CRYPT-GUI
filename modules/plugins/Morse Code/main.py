from modules.parent import Cipher
from ruamel.yaml import YAML

y = YAML(typ="safe")
with open("modules/plugins/Morse Code/info.yaml") as f:
    info = y.load(f)
del y


class MorseCode(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def __init__(self):
        self.MORSE_CODE_DICT = {
            "A": ".-",
            "B": "-...",
            "C": "-.-.",
            "D": "-..",
            "E": ".",
            "F": "..-.",
            "G": "--.",
            "H": "....",
            "I": "..",
            "J": ".---",
            "K": "-.-",
            "L": ".-..",
            "M": "--",
            "N": "-.",
            "O": "---",
            "P": ".--.",
            "Q": "--.-",
            "R": ".-.",
            "S": "...",
            "T": "-",
            "U": "..-",
            "V": "...-",
            "W": ".--",
            "X": "-..-",
            "Y": "-.--",
            "Z": "--..",
            "1": ".----",
            "2": "..---",
            "3": "...--",
            "4": "....-",
            "5": ".....",
            "6": "-....",
            "7": "--...",
            "8": "---..",
            "9": "----.",
            "0": "-----",
            "&": ".-...",
            "@": ".--.-.",
            ":": "---...",
            ",": "--..--",
            ".": ".-.-.-",
            "'": ".----.",
            '"': ".-..-.",
            "_": "..--.-",
            "$": "...-..-",
            "?": "..--..",
            "/": "-..-.",
            "=": "-...-",
            "+": ".-.-.",
            "-": "-....-",
            "(": "-.--.",
            ")": "-.--.-",
            "!": "-.-.--",
            " ": "/",
            "\n": "[NL]",
        }  # Exclamation mark is not in ITU-R recommendation
        self.MORSE_REVERSE_DICT = {
            value: key for key, value in self.MORSE_CODE_DICT.items()
        }

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        encoded = ""
        for char in plain.upper():
            if char in self.MORSE_CODE_DICT.keys():
                encoded += self.MORSE_CODE_DICT[char] + " "
            else:
                encoded += char + " "
        return encoded

    def decode(self, encoded: str, **kwargs) -> str:
        decoded = ""
        for char in encoded.split():
            if char in self.MORSE_REVERSE_DICT.keys():
                decoded += self.MORSE_REVERSE_DICT[char]
            else:
                decoded += char

        return decoded.capitalize()
