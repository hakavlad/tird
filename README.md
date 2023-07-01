![Logo: random data visualization](https://i.imgur.com/kZc0el8.png)

# tird

[![License](https://img.shields.io/badge/License-CC0-blue)](https://github.com/hakavlad/tird/blob/main/LICENSE)
[![Releases](https://img.shields.io/github/v/release/hakavlad/tird)](https://github.com/hakavlad/tird/releases)
[![PyPI](https://img.shields.io/pypi/v/tird?color=blue&label=PyPI)](https://pypi.org/project/tird/)

`tird` *(an acronym for "this is random data")* is a tool for encrypting and hiding file contents among random data.

## Features

- The result of encryption (mode 2) is PURB-like objects (call this "cryptoblob").
- Cryptoblobs are indistinguishable from random data.
- `tird` allows you to hide cryptoblobs among other random data (mode 6), use arrays of any other random data as containers for hiding cryptoblobs. Thus, deniable encryption is implemented.
- Auxiliary modes (8 and 9) allow you to create arrays of random data: create files with random data (mode 8) and overwrite files or devices with random data (mode 9) for subsequent hiding of cryptoblobs.
- `tird` supports an unlimited number of passphrases and keyfiles for encryption.
- Directories and devices can also be used as keys.
- `tird` allows you to add metadata (description) and an authentication tag to the encrypted file contents.
- Any file larger than a certain minimum size is a valid `tird` cryptoblob: the use of any keys when decrypting will give some output with the result `OK`.
- `tird` only provides symmetric encryption with stream cipher based on XORing plaintext with keystream blocks.
- SHAKE256 XOF output is used to create keystream blocks (chunks of pseudo-random size are used mixed in a pseudo-random way).
- Presumably, `tird` can provide a key space larger than 256 bits: when constructing a keystream block, three different outputs of SHAKE256 are used, for which different parts of the key input are used.
- `tird` is written in Python and uses only the Python standard library (`hashlib` module and the hash functions: `BLAKE2b` for files hashing, `scrypt` as KDF, `SHAKE256` for building keystrem blocks).
- `tird` uses randomized padding with max size up to 20% (by default) of the message size.
- When encrypting, you can set custom values for the block size of the keystream, number of rounds, derived keys length, metadata size, padding size, and enable debug messages.
- `tird` is a single Python file with no external dependencies.
- `tird` has no config file and no command line options. Looking at the bash history will not provide information on how `tird` was used.
- `tird` can also be called software for steganography: a cryptoblob can be written over a flash drive or disk. Then the existence of a cryptoblob cannot be detected without statistical analysis to identify areas of high entropy (even this will only suspect, not prove the existence of a cryptoblob).
- If random data is encrypted with default options (without MAC and metadata specified), then it is impossible to prove that this or that key was used for encryption: the decryption result will always be random data.
- `tird` does not report whether this or that decryption key is correct. If a MAC was added during encryption, then when using the correct key, it can be reported "MAC is valid: True". If the MAC was not added during encryption (this is the default behavior), then the only way to find out to pick up the correct key is to statistically analyze the output files.
- `tird` does not force you to use any standard extension for output file names. The name of the output file is always set by the user.
- Keyed `BLAKE2b` is used for creating message authentication code (MAC is not added by default). Adding a MAC will help you check the integrity of the data when decrypting.
- The ability to almost unlimitedly increase the key space and the complexity of encryption/decryption when using custom options. You can set dk_len=2047M, keystrem_block_size=2047M, num_rounds=1000000. The downside of complexity is that the encryption/decryption rate is down.

## Tradeoffs and limitations

- `tird` does not support asymmetric encryption and signatures.
- `tird` does not support file compression.
- `tird` does not support ASCII armored output.
- `tird` does not support Reed–Solomon error correction.
- `tird` does not support splitting the output into chunks.
- `tird` does not provide a graphical user interface.
- `tird` does not provide a password generator.
- `tird` does not wipe sensitive data from the heap.
- `tird` can only encrypt one file per iteration. Encryption of directories and multiple files is not supported.
- `tird` does not fake timestamps (may be implemented in the future, but not yet planned).
- `tird` encryption/decryption speed is relatively low (tens of megabytes per second in default settings).

## Warnings

- The author is not an expert in cryptography.
- `tird` has not been independently audited.
- Development is ongoing, there may be backward compatibility issues in the future.
- `tird` probably won't help much when used in a compromised environment.
- Parts of the keys may leak into the swap space.
- A huge key space by itself does not give advantages when using short and predictable keys. It is recommended to use long and unpredictable key sets.

## Cryptoblob structure
```
                   |----------------------------|
                   |  file contents  | metadata |
                   |----------------------------|-----|
                   |            message         | MAC |
                   |----------------------------------|
                   |              plaintext           |
|------------------|----------------------------------|------------------|
| salt_h | padding | ciphertext (plaintext^keystream) | padding | salt_f |
|------------------------------------------------------------------------|
|   urandom data   |           encrypted data         |   urandom data   |
|------------------------------------------------------------------------|
|                             random-looking data                        |
|------------------------------------------------------------------------|
```

## Usage

Just run the script, select the option you want and then answer the questions.
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

![Mode 2 screenshot](https://i.imgur.com/UbKFLG5.png)

## Requirements

- Python >= 3.6

## Install

```bash
$ pip install tird
```
or
```bash
$ git clone -b v0.1.0 https://github.com/hakavlad/tird.git && cd tird
$ sudo make install
```
