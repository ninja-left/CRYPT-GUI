# CRYPT, an encryption/decryption tool
![header]

<div align=center>

![Project License]
![Commit meter]
![Latest version]
![Code style]

</div>

## What?
CRYPT is a tool that allows you to apply different functions on texts; Now with a GUI.

## Why?
Because I wanted to learn creating GUI programs. Also, the GUI uses tabs which is more neat.

## What functions are implemented?
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
   - MD5 & MD5 Crypt
   - SHA256 & SHA512
   - SHA256 & SHA512 Crypt
   - NThash
   - BCrypt
   - Argon2
   - PBKDF2+SHA256 & PBKDF2+SHA512
   - Hash Cracking with a wordlist or by Bruteforcing
4. Plugins:
   - XOR
   - Affine Cipher
   - a1z26

## Installation & Usage
### Using compiled binary
1. Go to the [Releases page]
2. Download the Linux, MacOS, or Windows Tar or Zip depending on your operating system
3. Extract and open CRYPT folder
4. Run or Double-click on `./Crypt` (On Linux and MacOS) and `.\Crypt.exe` (On Windows)

### Using source code
1. Install Python 3.11
2. Clone this repository or Download source code from [Releases page]
3. Unpack the downloaded Zip or Tar
4. (Recommended) Create a virtual environment and use that:
    ```shell
    python3 -m venv venv
    ```
    On Mac/Linux:
    ```shell
    source ./venv/bin/activate
    ```
    On Windows
    ```powershell
    .\venv\Scripts\activate
    ```
5. install the libraries in `requirements.txt` using:
    ```shell
    pip install -r requirements.txt
    ```
6. Run with `python3 Crypt.py` or simply `./Crypt.py`

## Support
If you encounter any issues or bugs, feel free to open an issue about it on this repo and I'll try to help.
### Security
Read [SECURITY.md] for guide on how to report security issues.

## License
This project is licensed under GPL v3.0. See [LICENSE] file for details.

## Contributing
Thanks in advance for considering to help me on this project.
You can read [CONTRIBUTING.md] for details on contributing to the project.

## Roadmap
See [ROADMAP.md] for details.

[header]: ./modules/design/images/head.png
[LICENSE]: ./LICENSE
[SECURITY.md]: ./SECURITY.md
[CONTRIBUTING.md]: ./Docs/CONTRIBUTING.md
[ROADMAP.md]: ./Docs/ROADMAP.md
[pyperclip repository]: https://github.com/spyoungtech/pyclip?tab=readme-ov-file#installation
[Project License]: https://img.shields.io/github/license/ninja-left/CRYPT-GUI
[Commit meter]: https://img.shields.io/github/commit-activity/m/ninja-left/CRYPT-GUI
[Latest version]: https://img.shields.io/github/v/tag/ninja-left/CRYPT-GUI?label=Version&color=black
[Code style]: https://img.shields.io/badge/code%20style-black-000000.svg
[Releases page]: https://github.com/ninja-left/CRYPT-GUI/releases/latest

