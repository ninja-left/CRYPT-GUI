from modules.parent import Cipher
from ruamel.yaml import YAML

y = YAML(typ="safe")
with open("modules/plugins/BaconianCipher/info.yaml") as f:
    info = y.load(f)
del y


class BaconianCipher(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def __init__(self):
        self.encode_dict = {
            "a": "AAAAA",
            "b": "AAAAB",
            "c": "AAABA",
            "d": "AAABB",
            "e": "AABAA",
            "f": "AABAB",
            "g": "AABBA",
            "h": "AABBB",
            "i": "ABAAA",
            "j": "BBBAA",
            "k": "ABAAB",
            "l": "ABABA",
            "m": "ABABB",
            "n": "ABBAA",
            "o": "ABBAB",
            "p": "ABBBA",
            "q": "ABBBB",
            "r": "BAAAA",
            "s": "BAAAB",
            "t": "BAABA",
            "u": "BAABB",
            "v": "BBBAB",
            "w": "BABAA",
            "x": "BABAB",
            "y": "BABBA",
            "z": "BABBB",
            " ": " ",
        }
        self.decode_dict = {value: key for key, value in self.encode_dict.items()}

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        encoded = ""
        for letter in plain.lower():
            if letter.isalpha() or letter == " ":
                encoded += self.encode_dict[letter]
            else:
                encoded += letter
        return encoded

    def decode(self, encoded: str, **kwargs) -> str:
        decoded = ""
        pattern = r"[\d\._\-&!@?]+"
        for word in encoded.split():
            while len(word) != 0:
                if word[:5].isalpha():
                    decoded += self.decode_dict[word[:5]]
                    word = word[5:]
                else:
                    s = search(pattern, word)
                    if s:
                        decoded += word[s.start() : s.end()]
                        word = word.replace(word[s.start() : s.end()], "")
                    else:
                        raise BadCharacter(f"Bad characters in {word}; Bad:{s.group()}")
            decoded += " "
        return decoded.strip().capitalize()
