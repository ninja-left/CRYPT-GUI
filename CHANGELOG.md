# Changelog
## [0.1.5]
### Added
- Config file for setting different variables
- Some variables now use the default set in config.yaml
- Functions to save & load settings
- Added Save and Load icons
- Added Config ui
- Implemented config window
### Changed
- Included a condition for salt patterns to check if SALT & INPUT are specified
- compile_uic.sh & compile_fix.sh: Included config ui files
- functions.py: SaveSettings no longer returns a boolean
- Renamed assets to images
- Moved all UI files to design folder
- compile_*.sh: Adapted to the renames and moves
- Fixed imports
- Fixed README header file location

## [0.1.4]
### Added
- Zoom in & Zoom out buttons
- GUI: Added Config button
- GUI: Brute-force dialog
- compile_uic.sh: Brute-force UI
- Code: Caesar Cipher & WordList brute-force functions
- compile_fix.sh: Fixes resource file imports after compiling UI files
- brute.py: [brute](https://github.com/rdegges/brute) library with fixed bug
- Code: Fully Implemented Brute-forcers
### Changed
- ROADMAP.md: Replaced link with list of features to add
- compile.sh: Includes fix script
- Code: class Window -> MainWindow
- functions.py: Moved cracker functions to Crypt.py & Renamed it to functions.py
### Removed
- Code: Alert on pasting successfully

## [0.1.3]
### Added
- Code: 2 Custom error classes
- Code: 2 new alphabets (Base32 & Base85)
- GUI: a "Rounds" option for bCrypt, Argon2, PBKDF2 functions
- GUI: Default alphabets loaded in Setting tab when choosing a function that supports it.
- GUI: Added accessibility names, tooltips, descriptions & ...
- Encoders, decoders, hash functions, and hash verifiers
- requirements.txt: passlib, bCrypt, & Argon2 libraries
- ciphers.py: Verifier functions for bCrypt, Argon2, & PBKDF2
### Changed
- Code: Replaced all message box codes with a function
- Code: Copy & Paste functions
### Fixes
- CHANGELOG.md: Fixed typo in repository name

## [0.1.2]
### Added
- ciphers.py: file containing functions for encoding, decoding input.
- cracker.py: Contains functions for brute-forcing hashes and some ciphers.
- Alphabets for encoders and decoders
- Setting fields turn on based on chosen operation
### Changes
- GUI Setting tab: Added fields alphabet, key, salt, and salt pattern.
- Crypt.py: Using a variable for the paste timeout
- compile.sh: Moved environment activation from individual scripts to there.
### Fixes
- compile.sh: Now it works.

## [0.1.1] - 2024-06-21
### Added
- Timeout for paste function (It won't freeze in case of empty clipboard on KDE Plasma Wayland)
### Changed
- Paste now appends data
- Renamed Crypt-VERSION.py to Crypt.py

## [0.1.0] - 2024-06-13
### Added
- Copy and Paste functions
- Buttons change based on chosen operation mode

[0.1.4]: https://github.com/ninja-left/CRYPT-GUI/releases/tag/v0.1.4
[0.1.3]: https://github.com/ninja-left/CRYPT-GUI/releases/tag/v0.1.3
[0.1.2]: https://github.com/ninja-left/CRYPT-GUI/releases/tag/v0.1.2
[0.1.1]: https://github.com/ninja-left/CRYPT-GUI/releases/tag/v0.1.1
[0.1.0]: https://github.com/ninja-left/CRYPT-GUI/releases/tag/v0.1.0
