# Changelog
## 0.2.3
### Changes
- Moved step env variables to job env
- Bumped dependency version to newer ones
- release outputs repo_name & version and build-* jobs use these outputs
- Moved get_desc to prepare
- Moved some of step.if to step.run
- Merged fake asset creation with original ones
- Moved repo_name to workflow env
- Changed actions for uploading assets and creating release
### Fixes
- Corrected env variable use in compress steps
- Fixed Windows-build hash input file
- Added missing old_version to release job.env

## 0.2.2
### Added
- Compiled archives for each release
### Changes
- Release triggered only when merging a pull-request for CHANGELOG.md
- Used job.outputs to share release url between jobs
- Renamed dist/ to dist/CRYPT when moving files/folders to correct location for compression
### Fixed
- Release triggered on any push
- if logic in prepare job
- missing checkout@v4 steps in release & finish-up jobs
- Added env variables for jobs
- Fixed windows pyinstaller command
- Fixed compiled name variables

## 0.2.1
### Changed
- Excluded .ui , .qrc , compile scripts and LICENSE_WIKI files when creating release assets
### Fixes
- Fixed release body

## 0.2.0
### Added
- Config file for setting different variables
- Some variables now use the default set in config.yaml
- Functions to save & load settings
- Added Save and Load icons
- Added Config ui
- Implemented config window
- Plugins system
  - a1z26, Affine cipher, & XOR cipher plugin
- new config value: default logging level
- Logging system for tracking errors
- Plugin license shown on About tab
### Changed
- Included a condition for salt patterns to check if SALT & INPUT are specified
- compile_uic.sh & compile_fix.sh: Included config ui files
- functions.py: SaveSettings no longer returns a boolean
- Renamed assets to images
- Moved all UI files to design folder
- compile_*.sh: Adapted to the renames and moves
- Moved documents to /Docs
### Fixes
- Fixed imports
- Fixed README header file location
- Fixed log level and base85 settings for config dialog

## 0.1.4
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

## 0.1.3
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

## 0.1.2
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

## 0.1.1
### Added
- Timeout for paste function (It won't freeze in case of empty clipboard on KDE Plasma Wayland)
### Changed
- Paste now appends data
- Renamed Crypt-VERSION.py to Crypt.py

## 0.1.0
### Added
- Copy and Paste functions
- Buttons change based on chosen operation mode
