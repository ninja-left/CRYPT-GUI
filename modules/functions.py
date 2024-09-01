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
from pathlib import Path
from multiprocessing import Pool
from passlib.context import CryptContext
import mmap
from PySide6.QtWidgets import QProgressBar
from ruamel.yaml import YAML, YAMLError
from pluginlib import PluginLoader, PluginImportError
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
import modules.parent
from Crypt import Logger

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
    try:
        start_length = int(start_length)
    except:
        start_length = 1
    if start_length < 1:
        start_length = 1
    if ramp:
        for i in range(start_length, length + 1):
            t = total_options**i
            total_combinations += t
    else:
        total_combinations = total_options**length
    return total_combinations


def save_settings(data: dict | None = None) -> None:
    """
    if `data` is not specified, it will try to load
    """
    config_file = Path("config.yaml").absolute()
    default_config_file = Path("default_config.yaml").absolute()
    yaml = YAML(typ="safe")
    yaml.indent(4)
    yaml.allow_unicode = True
    yaml.default_flow_style = False
    if not data:
        with open(default_config_file, "r") as f:
            data = yaml.load(f)
    with open(config_file, "w") as f:
        yaml.dump(data, f)


def load_settings() -> dict:
    config_file = Path("config.yaml").absolute()
    default_config_file = Path("default_config.yaml").absolute()
    yaml = YAML(typ="safe")

    try:
        with open(config_file, "r") as f:
            return yaml.load(f)
    except:
        with open(default_config_file, "r") as f:
            data = yaml.load(f)
        save_settings(data)
        return data


def get_loader() -> dict:
    """return a dict of all plugins"""
    return PluginLoader(paths=["./modules/plugins"])


def hasKey(dic: dict, key) -> bool:
    try:
        dic[key]
        return True
    except:
        return False


def chKeySet(data: dict, key) -> None:
    if not hasKey(data, key):
        raise KeyError(f"`{key}` is not set in info.yaml")


def chKeyGood(data: dict, key, goal: object) -> None:
    if type(data[key]) != goal:
        raise ValueError(f"`{key}` must be of type `{goal}`")


def checkConfig(data: dict) -> None:
    chKeySet(data, "name")
    chKeyGood(data, "name", str)

    chKeySet(data, "version")
    chKeyGood(data, "version", str)

    chKeySet(data, "requirements")
    chKeyGood(data, "requirements", str)

    chKeySet(data, "config")
    chKeyGood(data, "config", dict)

    chKeySet(data["config"], "uses keys")
    chKeyGood(data["config"], "uses keys", bool)
    if data["config"]["uses keys"]:
        chKeySet(data["config"], "default key")

    chKeySet(data["config"], "can change alphabet")
    chKeyGood(data["config"], "can change alphabet", bool)
    if data["config"]["can change alphabet"]:
        chKeySet(data["config"], "alphabet")

    chKeySet(data["config"], "has encoder")
    chKeyGood(data["config"], "has encoder", bool)

    chKeySet(data["config"], "has decoder")
    chKeyGood(data["config"], "has decoder", bool)

    chKeySet(data["config"], "has brute")
    chKeyGood(data["config"], "has brute", bool)

    chKeySet(data["config"], "uses salt")
    chKeyGood(data["config"], "uses salt", bool)

    chKeySet(data["config"], "uses plaintext")
    chKeyGood(data["config"], "uses plaintext", bool)

    chKeySet(data["config"], "uses rounds")
    chKeyGood(data["config"], "uses rounds", bool)
    if data["config"]["uses rounds"]:
        chKeySet(data["config"], "default rounds")


def check_plugins(plugins: dict) -> dict:
    """Checks info.yaml file of all plugins and returns valid plugins"""
    bad = set()  # Add plugins with an invalid info.yaml file here

    for i in plugins:
        t = plugins[i]()
        info = t.get_info()
        try:
            checkConfig(info)
        except KeyError as e:
            Logger.error(e, exc_info=1)
            bad.add(i)

    for i in bad:
        plugins.pop(i)

    return plugins
