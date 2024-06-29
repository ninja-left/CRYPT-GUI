# -*- coding: UTF-8 -*-
"""
    CRYPT Brute-Forcer, Password hash brute-force functions
    Copyright (C) 2024  Ninja Left

    CRYPT Brute-Forcer is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    CRYPT Brute-Forcer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CRYPT Brute-Forcer.  If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
from passlib.context import CryptContext
import mmap
from PySide6.QtWidgets import QProgressBar
from modules.ciphers import md5, sha256, sha512
from modules.brute import brute
from modules.ciphers import caesar_cipher


HASH_CONTEXT = CryptContext(
    [
        "md5_crypt",
        "sha256_crypt",
        "sha512_crypt",
        "bcrypt",
        "argon2",
        "nthash",
        "pbkdf2_sha256",
        "pbkdf2_sha512",
    ]
)


def get_file_lines(file: str) -> int:
    with open(file, "r+") as f:
        buf = mmap.mmap(f.fileno(), 0)
        L = 0
        readline = buf.readline
        while readline():
            L += 1
        return L


def BruteForce(
    hash_input: str,
    length: int,
    ramp: bool,
    start_length: int = 1,
    have_letters: bool = True,
    have_symbols: bool = True,
    have_numbers: bool = True,
    hash_type: str = "other",
):
    """
    ----
    Parameters
    ----------
    * hash: Hash to crack.
    * length: Length of string to iterate through.
    * ramp: If true, ramp up from start_length till length; Otherwise, iterate over current length values.
    * have_letters: Include uppercase & lowercase letters; default: True.
    * have_symbols: Include symbols; default: True.
    * have_numbers: Include 0-9 digit; default: Trues.
    * start_length: The length of the string to begin ramping through; default: 1.
    * hash_type: Type of hash trying to crack.
    """

    results = "Not found"
    for password in brute(
        start_length=start_length,
        length=length,
        letters=have_letters,
        symbols=have_symbols,
        numbers=have_numbers,
        ramp=ramp,
    ):
        if hash_type == "md5":
            check = md5(password)
        elif hash_type == "sha256":
            check = sha256(password)
        elif hash_type == "sha512":
            check = sha512(password)
        else:
            check = HASH_CONTEXT.verify(password, hash_input)

        if check == hash_input:
            results = password
            break

    return results


def WordList(
    bar: QProgressBar, hash_input: str, file_path: str, hash_type: str = "other"
) -> str:
    """
    ----
    Parameters
    ----------
    * hash_input: Hash to crack.
    * file_path: Path to the word-list.
    * hash_type: Type of hash trying to crack.
    """
    TLines = get_file_lines(file_path)
    Line = 0
    p = 0
    bar.setValue(p)
    if not bar.isVisible():
        bar.setVisible(True)

    with open(file_path, "r", encoding="UTF-8") as file_obj:
        for password in file_obj:
            Line += 1
            p = Line // TLines * 100
            bar.setValue(p)
            password = password.strip()
            if hash_type == "MD5":
                check = md5(password)
            elif hash_type == "SHA256":
                check = sha256(password)
            elif hash_type == "SHA512":
                check = sha512(password)
            else:
                check = HASH_CONTEXT.verify(password, hash_input)

            if check == hash_input:
                results = password
                bar.setValue(100)
                break
        else:
            results = ""

    return results


def caesar_brute(input_string: str, alphabet: str) -> dict[str, str]:
    """
    Parameters:
    -----------
    *   input_string: the cipher-text that needs to be used during brute-force

    Optional:
    *   alphabet:  (None): the alphabet used to decode the cipher, if not
        specified, the standard english alphabet with upper and lowercase
        letters is used
    """

    brute_force_data = dict()
    for key in range(1, len(alphabet) + 1):
        key = -key
        keyMatch = caesar_cipher(input_string, key, alphabet)
        brute_force_data[f"Key {abs(key)}"] = keyMatch

    return brute_force_data
