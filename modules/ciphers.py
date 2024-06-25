# -*- coding: UTF-8 -*-

"""
    CRYPT Ciphers, Encryption/Decryption Tool
    Copyright (C) 2024  Ninja Left

    CRYPT Ciphers is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    CRYPT Ciphers is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CRYPT Ciphers.  If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import hashlib
from re import search
import passlib.hash


# TODO: change the baseX functions so they may use alternative functions.
def base16_encode(txt: str) -> str:
    return base64.b16encode(txt.encode("utf-8")).decode("utf-8")


def base16_decode(b16encoded: str) -> str:
    return base64.b16decode(b16encoded.encode("utf-8")).decode("utf-8")


def base32_encode(string: str) -> str:
    return base64.b32encode(string.encode("utf-8")).decode("utf-8")


def base32_decode(encoded_bytes: str) -> str:
    return base64.b32decode(encoded_bytes.encode("utf-8")).decode("utf-8")


def base85_encode(string: str) -> str:
    return base64.b85encode(string.encode("utf-8")).decode("utf-8")


def base85_decode(a85encoded: str) -> str:
    return base64.b85decode(a85encoded.encode("utf-8")).decode("utf-8")


def base64_encode(text: str, B64_CHARSET: str) -> str:
    """Encodes data according to RFC4648.
    The data is first transformed to binary and appended with binary digits so that its
    length becomes a multiple of 6, then each 6 binary digits will match a character in
    the B64_CHARSET string. The number of appended binary digits would later determine
    how many "=" signs should be added, the padding.
    For every 2 binary digits added, a "=" sign is added in the output.
    We can add any binary digits to make it a multiple of 6, for instance, consider the
    following example:
    "AA" -> 0010100100101001 -> 001010 010010 1001
    As can be seen above, 2 more binary digits should be added, so there's 4
    possibilities here: 00, 01, 10 or 11.
    That being said, Base64 encoding can be used in Steganography to hide data in these
    appended digits.
    """
    data = text.encode()
    binary_stream = "".join(bin(byte)[2:].zfill(8) for byte in data)

    padding_needed = len(binary_stream) % 6 != 0

    if padding_needed:
        # The padding that will be added later
        padding = b"=" * ((6 - len(binary_stream) % 6) // 2)

        # Append binary_stream with arbitrary binary digits (0's by default) to make its
        # length a multiple of 6.
        binary_stream += "0" * (6 - len(binary_stream) % 6)
    else:
        padding = b""

    # Encode every 6 binary digits to their corresponding Base64 character
    return (
        "".join(
            B64_CHARSET[int(binary_stream[index : index + 6], 2)]
            for index in range(0, len(binary_stream), 6)
        ).encode()
        + padding
    ).decode()


def base64_decode(encoded_data: str, B64_CHARSET: str) -> str:
    """Decodes data according to RFC4648.
    This does the reverse operation of base64_encode.
    We first transform the encoded data back to a binary stream, take off the
    previously appended binary digits according to the padding, at this point we
    would have a binary stream whose length is multiple of 8, the last step is
    to convert every 8 bits to a byte.
    """

    # In case encoded_data is a bytes-like object, make sure it contains only
    # ASCII characters so we convert it to a string object
    if isinstance(encoded_data, bytes):
        try:
            encoded_data = encoded_data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("base64 encoded data should only contain ASCII characters")

    padding = encoded_data.count("=")

    if padding:  # Check if the encoded string contains non base64 characters
        assert all(
            char in B64_CHARSET for char in encoded_data[:-padding]
        ), "Invalid base64 character(s) found."
    else:
        assert all(
            char in B64_CHARSET for char in encoded_data
        ), "Invalid base64 character(s) found."

    # check padding
    assert len(encoded_data) % 4 == 0 and padding < 3, "Incorrect padding"
    if padding:  # Remove padding if there is one
        encoded_data = encoded_data[:-padding]
        binary_stream = "".join(
            bin(B64_CHARSET.index(char))[2:].zfill(6) for char in encoded_data
        )[: -padding * 2]
    else:
        binary_stream = "".join(
            bin(B64_CHARSET.index(char))[2:].zfill(6) for char in encoded_data
        )
    data = [
        int(binary_stream[index : index + 8], 2)
        for index in range(0, len(binary_stream), 8)
    ]
    return bytes(data).decode()


def caesar_cipher(input_string: str, key: int, alphabet: str) -> str:
    """
    Parameters:
    -----------
    *   input_string: the plain-text that needs to be encoded
    *   key: the number of letters to shift the message by

    Optional:
    *   alphabet (str): the alphabet used to encode the cipher, if not
        specified, the standard english alphabet with upper and lowercase
        letters is used
    """
    result = ""

    for character in input_string:
        if character not in alphabet:
            result += character
        else:
            # Get the index of the new key and make sure it isn't too large
            new_key = (alphabet.index(character) + key) % len(alphabet)

            # Append the encoded character to the alphabet
            result += alphabet[new_key]

    return result


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
# TODO: add a way to include salt with the text
def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def md5_crypt(text: str) -> str:
    return passlib.hash.md5_crypt.hash(text)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def sha256_crypt(text: str) -> str:
    return passlib.hash.sha256_crypt.hash(text)


def sha512(text: str) -> str:
    return hashlib.sha512(text.encode()).hexdigest()


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
