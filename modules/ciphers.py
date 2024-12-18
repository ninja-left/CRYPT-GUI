# -*- coding: UTF-8 -*-

"""
    Crypt, a set of tools
    Copyright (C) 2024  Ninja Left

    CRYPT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    any later version.

    CRYPT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with CRYPT.  If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
from re import search
import passlib.hash

# Morse Code
MORSE_CODE_DICT = {
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
MORSE_REVERSE_DICT = {value: key for key, value in MORSE_CODE_DICT.items()}


def mc_encrypt(message: str) -> str:
    encoded = ""
    for char in message.upper():
        if char in MORSE_CODE_DICT.keys():
            encoded += MORSE_CODE_DICT[char] + " "
        else:
            encoded += char + " "
    return encoded


def mc_decrypt(message: str) -> str:
    decoded = ""
    for char in message.split():
        if char in MORSE_REVERSE_DICT.keys():
            decoded += MORSE_REVERSE_DICT[char]
        else:
            decoded += char

    return decoded.capitalize()


# Baconian Cipher
encode_dict = {
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
decode_dict = {value: key for key, value in encode_dict.items()}


def bacon_encode(word: str) -> str:
    encoded = ""
    for letter in word.lower():
        if letter.isalpha() or letter == " ":
            encoded += encode_dict[letter]
        else:
            encoded += letter
    return encoded


def bacon_decode(coded: str) -> str:
    decoded = ""
    pattern = r"[\d\._\-&!@?]+"
    for word in coded.split():
        while len(word) != 0:
            if word[:5].isalpha():
                decoded += decode_dict[word[:5]]
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


# Vigenère Cipher
def vig_cipher(text: str, key: str, alphabet: str, mode: str = "e" or "d") -> str:
    results = ""
    keyIndex = 0

    for char in text:
        i = alphabet.find(char.upper())
        if i != -1:
            if mode == "e":
                i += alphabet.find(key[keyIndex])
            else:
                i -= alphabet.find(key[keyIndex])
            i %= len(alphabet)

            if char.isupper():
                results += alphabet[i]
            else:
                results += alphabet[i].lower()
            keyIndex += 1
            if keyIndex == len(key):
                keyIndex = 0
        else:
            results += char

    return results


# Hashes
def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def md5_b(text: bytes) -> str:
    return hashlib.md5(text).hexdigest()


def md5_crypt(text: str) -> str:
    return passlib.hash.md5_crypt.hash(text)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def sha256_b(text: bytes) -> str:
    return hashlib.sha256(text).hexdigest()


def sha256_crypt(text: str) -> str:
    return passlib.hash.sha256_crypt.hash(text)


def sha512(text: str) -> str:
    return hashlib.sha512(text.encode()).hexdigest()


def sha512_b(text: bytes) -> str:
    return hashlib.sha512(text).hexdigest()


def sha512_crypt(text: str) -> str:
    return passlib.hash.sha512_crypt.hash(text)


def bcrypt_hash(text: str, rounds: int) -> str:
    return passlib.hash.bcrypt.using(rounds=rounds).hash(text)


def bcrypt_verify(text: str, hashed: str) -> bool:
    return passlib.hash.bcrypt.verify(text, hashed)


def argon2_hash(text: str, rounds: int) -> str:
    return passlib.hash.argon2.using(rounds=rounds).hash(text)


def argon2_verify(text: str, hashed: str) -> bool:
    return passlib.hash.argon2.verify(text, hashed)


def nthash(text: str) -> str:
    return passlib.hash.nthash.hash(text)


def pbkdf2_256_hash(text: str, rounds: int) -> str:
    return passlib.hash.pbkdf2_sha256.using(rounds=rounds).hash(text)


def pbkdf2_512_hash(text: str, rounds: int) -> str:
    return passlib.hash.pbkdf2_sha512.using(rounds=rounds).hash(text)


def pbkdf2_256_verify(text: str, hashed: str) -> bool:
    return passlib.hash.pbkdf2_sha256.verify(text, hashed)


def pbkdf2_512_verify(text: str, hashed: str) -> bool:
    return passlib.hash.pbkdf2_sha512.verify(text, hashed)
