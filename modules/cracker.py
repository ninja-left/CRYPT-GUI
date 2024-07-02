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
from multiprocessing import Pool
from passlib.context import CryptContext
import mmap
from PySide6.QtWidgets import QProgressBar
from modules.ciphers import (
    md5_b,
    sha256_b,
    sha512_b,
    md5,
    sha256,
    sha512,
    caesar_cipher,
)
from modules.brute import brute

# TODO: move everything to functions.py
# except brute-forcers
# TODO: move brute-forcers to ciphers.py & Crypt.py

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


def get_progress(c: int, t: int) -> int:
    """
    c: Current progress
    t: Total
    """
    return c // t * 100


def check_password(
    password: str | bytes, hash_input: str, hash_type: str, action: str = "w"
) -> str:
    if hash_type == "MD5":
        check = md5(password) if action == "b" else md5_b(password)
    elif hash_type == "SHA256":
        check = sha256(password) if action == "b" else sha256_b(password)
    elif hash_type == "SHA512":
        check = sha512(password) if action == "b" else sha512_b(password)
    else:
        check = HASH_CONTEXT.verify(password, hash_input)

    if check == hash_input:
        return password
    else:
        return ""

# TODO: move to Crypt.py
def wordlist_main(hash_input: str, file_path: str, hash_type: str = "other"):
    with open(file_path, "rb") as file_obj:
        for password in file_obj:
            password = password.strip(b"\n")
            if check_password(password, hash_input, hash_type):
                results = password
                break
        else:
            results = ""
    return results


def update_progressbar(bar: QProgressBar, t: int) -> None:
    for c in range(t):
        p = get_progress(c, t)
        bar.setValue(p)


def generate_possible_keys(
    length: int,
    ramp: bool,
    have_letters: bool,
    have_symbols: bool,
    have_numbers: bool,
    have_space: bool,
    start_length: int = 1,
) -> int:
    """
    This function calculates (Number of options) ^ (Length of password)
    and if ramp is True, calculate the same for each length and return sum.
    """
    total_combinations = 0
    total_options = 0
    L = 52  # Letters
    S = 32  # Symbols (Punctuations)
    D = 10  # Digits
    W = 6  # Whitespace
    if have_letters:
        total_options += L
    if have_symbols:
        total_options += S
    if have_numbers:
        total_options += D
    if have_space:
        total_options += W
    if start_length < 1:
        start_length = 1
    if ramp:
        for i in range(start_length, length + 1):
            t = total_options**i
            total_combinations += t
    else:
        total_combinations = total_options**length
    return total_combinations


def BruteForce(
    hash_input: str,
    length: int,
    ramp: bool,
    start_length: int,
    have_letters: bool,
    have_symbols: bool,
    have_numbers: bool,
    have_space: bool,
    hash_type: str,
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

    for password in brute(
        start_length=start_length,
        length=length,
        letters=have_letters,
        symbols=have_symbols,
        numbers=have_numbers,
        spaces=have_space,
        ramp=ramp,
    ):
        if check_password(password, hash_input, hash_type, "b"):
            results = password
            break
    else:
        results = ""

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
    Lines = get_file_lines(file_path)
    bar.setValue(0)
    if not bar.isVisible():
        bar.setVisible(True)

    # TODO: Make the progress bar update
    # Might be useful: https://stackoverflow.com/questions/58887540/progressbar-in-pyqt5-for-multiprocessing#59866351
    pool = Pool()

    pool.apply_async(update_progressbar, (bar, Lines))
    results = pool.apply_async(wordlist_main, (hash_input, file_path, hash_type))

    pool.close()
    pool.join()
    results = results.get()
    return results.decode()

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
