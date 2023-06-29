![Logo: random data visualization](https://i.imgur.com/kZc0el8.png)

# tird

[![License](https://img.shields.io/badge/License-CC0-blue)](https://github.com/hakavlad/tird/blob/main/LICENSE)
[![Releases](https://img.shields.io/github/v/release/hakavlad/tird)](https://github.com/hakavlad/tird/releases)
[![PyPI](https://img.shields.io/pypi/v/tird?color=blue&label=PyPI)](https://pypi.org/project/tird/)

`tird` *(an acronym for "this is random data")* is a tool for encrypting and hiding file contents among random data.

![Mode 2 screenshot](https://i.imgur.com/UbKFLG5.png)

## Install

```bash
$ pip install tird
```
or
```bash
$ git clone -b v0.1.0 https://github.com/hakavlad/tird.git && cd tird
$ sudo make install
```

## Usage

Just run the script and answer its questions:
```
$ tird

                        MENU
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    0. Exit               1. Get info
    2. Encrypt            3. Decrypt
    4. Hide               5. Unhide
    6. Encrypt and hide   7. Unhide and decrypt
    8. Create w/ urandom  9. Overwrite w/ urandom
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Please enter [0-9]: 
```

## Requirements

- Python >= 3.6

