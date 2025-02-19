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

from pathlib import Path
from passlib.context import CryptContext
import mmap
from ruamel.yaml import YAML
from pluginlib import PluginLoader
from subprocess import run, CalledProcessError  # Used for installing requirements
from sys import exit
from re import compile as regComp  # Used for sanitizing requirements
from hashlib import md5, sha256, sha512
from modules.brute import brute
import modules.parent
from modules.logger_config import get_logger


HASH_CONTEXT = CryptContext(
    [
        "sha256_crypt",
        "sha512_crypt",
        "bcrypt",
        "argon2",
        "nthash",
        "pbkdf2_sha256",
        "pbkdf2_sha512",
    ]
)
Logger = get_logger()
VALID_PACKAGE = regComp(r"^[a-zA-Z0-9_.-]+$")
# This pattern allows alphanumerics, dashes, underscores, & periods

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


# NOTE: moved to here from ciphers.py for check_password()
def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def md5_bytes(text: bytes) -> str:
    return hashlib.md5(text).hexdigest()


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def sha256_bytes(text: bytes) -> str:
    return hashlib.sha256(text).hexdigest()


def sha512(text: str) -> str:
    return hashlib.sha512(text.encode()).hexdigest()


def sha512_bytes(text: bytes) -> str:
    return hashlib.sha512(text).hexdigest()


def check_password(
    password: str | bytes, hash_input: str, hash_type: str, action: str = "w"
) -> str:
    if hash_type == "MD5":
        check = md5(password) if action == "b" else md5_bytes(password)
    elif hash_type == "SHA256":
        check = sha256(password) if action == "b" else sha256_bytes(password)
    elif hash_type == "SHA512":
        check = sha512(password) if action == "b" else sha512_bytes(password)
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
    yaml = YAML(typ="safe")
    yaml.indent(4)
    yaml.allow_unicode = True
    yaml.default_flow_style = False
    if not data:
        with open(config_file, "r") as f:
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
        raise ValueError(f"`{key}` must be of type `{goal}`; It is `{type(data[key])}`")


def chRequirements(requirements: str, plugin_name: str) -> None:
    Logger.info("Checking `%s`'s requirements", plugin_name)
    loaded_plugins = load_settings()["other"]["loaded plugins"]
    Logger.debug("Loaded plugins: %s", loaded_plugins)
    if plugin_name in loaded_plugins:
        Logger.info("Skipping the check because this plugin was loaded in the past")
        return None
    if requirements == "":
        Logger.info("Plugin has no requirements")
        return None
    Logger.debug("Old Requirements: %s", requirements)
    # First, convert all ', ' to commas (,) and then convert all spaces to commas and finally separate requirements by comma
    # so 'R1, R2,R3 R4,R5' would become 'R1,R2,R3,R4,R5'
    requirements = ",".join(",".join(requirements.split(", ")).split(" ")).split(",")
    # Sanitize requirements
    requirements = [r.strip() for r in requirements if VALID_PACKAGE.match(r)]
    Logger.info("Found %d requirements", len(requirements))
    Logger.info("Requirements: %s", requirements)
    Logger.info("Installing...")
    try:
        if len(requirements) < 1:
            raise ValueError("No valid packages specified")
        results = run(["pip", "install"] + requirements, capture_output=True, text=True)
        results.check_returncode()
        Logger.info("%s", results.stdout)
        Logger.info("Done")
        return None
    except CalledProcessError:
        Logger.critical(
            "Something went wrong when installing requirements:\n %s",
            results.stderr,
            exc_info=1,
        )
        exit(1)
    except Exception as e:
        Logger.critical(
            "Something went wrong when installing requirements:\n %s",
            str(e),
            exc_info=1,
        )
        exit(1)


def checkConfig(data: dict) -> None:
    """checks required variables in plugin info.yaml"""
    chKeySet(data, "name")
    chKeyGood(data, "name", str)

    chKeySet(data, "version")
    chKeyGood(data, "version", str)

    chKeySet(data, "requirements")
    chKeyGood(data, "requirements", str)
    chRequirements(data["requirements"], data["name"])

    chKeySet(data, "config")
    chKeyGood(data, "config", dict)

    chKeySet(data["config"], "uses keys")
    chKeyGood(data["config"], "uses keys", bool)
    if data["config"]["uses keys"]:
        chKeySet(data["config"], "default key")
        if data["config"]["default key"] == "$default$":
            chKeySet(data["config"], "alt key")

    chKeySet(data["config"], "can change alphabet")
    chKeyGood(data["config"], "can change alphabet", bool)
    if data["config"]["can change alphabet"]:
        chKeySet(data["config"], "alphabet")
        if data["config"]["alphabet"] == "$default$":
            chKeySet(data["config"], "alt alphabet")

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
        if data["config"]["default rounds"] == "$default$":
            chKeySet(data["config"], "alt rounds")

    chKeySet(data, "license")
    chKeyGood(data, "license", str)


def check_plugins(plugins: dict) -> dict:
    """Checks info.yaml file of all plugins and returns valid plugins"""
    bad = set()  # Add plugins with an invalid info.yaml file here

    for i in plugins:
        t = plugins[i]()
        info = t.get_info()
        try:
            checkConfig(info)
            Logger.info("Checked `%s`", info["name"])
        except KeyError as e:
            Logger.error(e, exc_info=1)
            bad.add(i)

    Logger.debug("Bad plugins: %s", len(bad))
    for i in bad:
        plugins.pop(i)
        Logger.debug("Removed `%s`", i)

    return plugins


def getMarkdownAbout() -> str:
    """Returns markdown version of About text"""
    return """# About
CRYPT GUI is licensed under GPL v3.0 Copyright (c) 2024 Ninja Left\n
CRYPT was built using Python 3, Qt Designer & Pyside6.\n
Some plugins used in this app are from [This Repository](https://github.com/TheAlgorithms/Python) and are\n
licensed under MIT Copyright (c) 2016-2024 TheAlgorithms and contributors.\n
brute.py is a modified version of [brute](https://github.com/rdegges/brute)

## Shortcuts:
Ctrl + V : Paste\n
Ctrl + = : Zoom In\n
Ctrl + - : Zoom Out\n
Ctrl + , : Settings\n
Ctrl + B : Brute Force\n
Ctrl + D : Decode\n
Ctrl + E : Encode\n
Ctrl + C : Copy

## Icons credits:
[Configure icon by afif fudin - Flaticon](https://www.flaticon.com/free-icon/configuration_9780271)\n
[Login icon by FR_Media - Flaticon](https://www.flaticon.com/free-icon/login_5729989)\n
[Logout icon by FR_Media - Flaticon](https://www.flaticon.com/free-icon/logout_5729988)\n
[Locked icon by Aswell Studio - Flaticon](https://www.flaticon.com/free-icon/lock_2549910)\n
[Unlocked icon by Aswell Studio - Flaticon](https://www.flaticon.com/free-icon/unlock_2549951)\n
[Unsecure icon by juicy_fish - Flaticon](https://www.flaticon.com/free-icon/unsecure_5690981)\n
[Search icon by Pixel Perfect - Flaticon](https://www.flaticon.com/free-icon/search_1828057)\n
[Folder icon by Mehwish - Flaticon](https://www.flaticon.com/free-icon/folder_3307447)\n
[Floppy disk icon by heisenberg_jr - Flaticon](https://www.flaticon.com/free-icon/floppy-disk_12629050)\n
"""


def run_tests() -> int:
    import pytest

    return pytest.main(["-q", "--tb=short", "modules/tests/"])
