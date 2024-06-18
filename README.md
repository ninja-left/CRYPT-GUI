# CRYPT, an encryption/decryption tool
![head](./assets/head.png)

<div align=center>
  <a href="https://github.com/ninja-left/CRYPT-GUI/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/ninja-left/CRYPT-GUI">
  </a>
  <a href="https://github.com/ninja-left/CRYPT-GUI">
    <img src="https://img.shields.io/github/commit-activity/m/ninja-left/CRYPT-GUI">
  </a>

![Latest version](https://img.shields.io/github/v/tag/ninja-left/CRYPT-GUI?label=Version&color=black) ![Code style](https://img.shields.io/badge/code%20style-black-000000.svg)

</div>


## What?
CRYPT is a tool that allows you to encrypt or decrypt texts; Now with a GUI.

## Why?
Because I wanted to learn creating GUI programs. Also, the GUI menu is more neat.

## What encodings, ciphers, and hashes are supported?
1. Encodings:
   - Base16
   - Base32
   - Base64
   - Base85

2. Ciphers:
   - Caesar Cipher
   - Morse Code
   - Baconian Cipher
   - Vigenère Cipher

3. Hashes:
   - MD5
   - Md5 Crypt
   - SHA256 & SHA512
   - SHA256 & SHA512 Crypt
   - NT
   - BCrypt
   - Argon2
   - PBKDF2+SHA256 & PBKDF2+SHA512
   - Hash Cracking with a wordlist or by Bruteforcing

## Installation
1. Install Python3
2. Clone this git repository OR Download source code from Releases page
3. Unpack the zip or tar
4. (Recommended) Create a virtual environment and use that:
    ```shell
    python3 -m venv venv
    ```
    On Mac/Linux:
    ```shell
    source ./venv/bin/activate
    ```
    On Windows
    ```shell
    .\venv\Scripts\activate
    ```
5. install the libraries in `requirements.txt` using:
    ```shell
    pip install -r requirements.txt
    ```

Note: This app uses `pyclip3` for copy/paste functions.
1. On Windows, no additional modules are needed.
2. On Mac, this module makes use of the pbcopy and pbpaste commands, which should come with the os.
3. On Linux, this module makes use of the xclip or xsel commands, which should come with the os. Otherwise run “sudo apt-get install xclip” or “sudo apt-get install xsel” (Note: xsel does not always seem to work.)

## Usage
```shell
python3 Crypt-?.?.?.py
```
or
```shell
./Crypt-?.?.?.py
```
Where `?.?.?` is the version.

## Support
If you encounter any issues or bugs, feel free to open an issue about it on this repo and I'll try to help.

## License
This project is licensed under GPL v3.0. See [LICENSE] file for details.

## Contributing
Thanks in advance for considering to help me on this project.
You can read [CONTRIBUTING.md] for details on contributing to the project.

## Roadmap
See [ROADMAP.md] for details.


[LICENSE]: ./LICENSE
[CONTRIBUTING.md]: ./CONTRIBUTING.md
[ROADMAP.md]: ./ROADMAP.md
