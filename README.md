![Logo: random data visualization](https://i.imgur.com/SB44MiB.png)

# tird

[![CodeQL](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql)
[![Releases](https://img.shields.io/github/v/release/hakavlad/tird)](https://github.com/hakavlad/tird/releases)
[![PyPI](https://img.shields.io/pypi/v/tird?color=blue&label=PyPI)](https://pypi.org/project/tird/)

`tird` *(an acronym for "this is random data")* is a tool for encrypting file contents and hiding random data among other random data.

![screenshot: menu](https://i.imgur.com/T5gXTko.png)

## Features

- `tird` is a single Python module with no external dependencies (uses `hashlib` module from the standard library for keyfile hashing, keys derivation and for encryption).
- `tird` has no config file and no command line options (except `-d/--debug`). Looking at the shell history will not provide information on how `tird` was used.
- The result of encryption (mode 2) is [PURB](https://en.wikipedia.org/wiki/PURB_(cryptography))-like objects (call this "cryptoblob").
- Cryptoblobs are indistinguishable from random data.
- `tird` uses [randomized padding](https://en.wikipedia.org/wiki/Padding_(cryptography)#Randomized_padding) with max size up to 20% (by default) of the message size.
- `tird` allows you to hide cryptoblobs among other random data (mode 6), use arrays of any other random data as containers for hiding cryptoblobs. Thus, deniable encryption is implemented.
- Auxiliary modes (8 and 9) allow you to create arrays of random data: create files with random data (mode 8) and overwrite files or devices with random data (mode 9) for subsequent hiding of cryptoblobs.
- `tird` supports an unlimited number of passphrases and keyfiles for encryption.
- Directories and devices can also be used as keys.
- `tird` allows you to add comments (description) and an authentication tag to the encrypted file contents.
- Any file larger than a certain minimum size is a valid `tird` cryptoblob: the use of any keys when decrypting will give some output with the result `completed successfully`.
- `tird` only provides symmetric encryption with stream cipher based on XORing plaintext with keystream blocks.
- SHAKE256 XOF output is used to create keystream blocks.
- When encrypting, you can set custom values: randomized padding max %, catpig memory-hard function space and time, and optionally add fake authentication tag.
- `tird` can also be called software for steganography: a cryptoblob can be written over a flash drive or disk. Then the existence of a cryptoblob cannot be detected without statistical analysis to identify areas of high entropy (even this will only suspect, not prove the existence of a cryptoblob).
- If random data is encrypted with default options (without MAC and comments specified), then it is impossible to prove that this or that key was used for encryption: the decryption result will always be random data.
- `tird` does not force you to use any standard extension for output file names. The name of the output file is always set by the user.
- Keyed `BLAKE2b` is used for creating message authentication code (MAC is added by default and can be optionally faked). Adding a MAC will help you check the integrity of the data when decrypting.
- `tird` does not provide reliable data on whether the entered dectyption keys are correct. This is based on the fact that adding an authentication tag is optional. If a MAC was added during encryption, then when using the correct key, it can be reported "authentication failed!" and "completed successfully". If the MAC was not added during encryption (this is the default behavior), then the only way to find out to pick up the correct key is to statistically analyze the output files.

## Tradeoffs and limitations

- `tird` does not support asymmetric encryption and signatures.
- `tird` does not support file compression.
- `tird` does not support ASCII armored output.
- `tird` does not support Reed–Solomon error correction.
- `tird` does not support splitting the output into chunks.
- `tird` does not support low-level device reading and writing when used on MS Windows (devices cannot be used as keyfiles, cannot be overwritten, cannot be encrypted or hidden).
- `tird` does not provide a graphical user interface (may be implemented later).
- `tird` does not provide a password generator.
- `tird` does not wipe sensitive data from the heap.
- `tird` can only encrypt one file per iteration. Encryption of directories and multiple files is not supported.
- `tird` does not fake file timestamps (atime, mtime, ctime).
- `tird` encryption/decryption speed is not very fast: 105-115 MiB/s.

## Warnings

- The author is not an expert in cryptography.
- `tird` has not been independently audited.
- Development is ongoing, there may be backward compatibility issues in the future.
- `tird` probably won't help much when used in a compromised environment.
- Parts of the keys may leak into the swap space.
- Use long and unpredictable key sets!

## Cryptoblob structure
```
                         0+B         512B
                 +---------------+----------+
                 | file contents | comments |
                 +---------------+----------+
  24B     0+B    |      message/payload     | 64B     0+B     24B
+------+---------+--------------------------+-----+---------+------+
| salt | padding |         ciphertext       | MAC | padding | salt |
+------+---------+--------------------------+-----+---------+------+
|  urandom data  | encrypted random-looking data  |  urandom data  |
+----------------+--------------------------------+----------------+
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

## Requirements

- Python >= 3.6

## Install

```bash
$ pip install tird
```
or
```bash
$ git clone -b v0.3.0 https://github.com/hakavlad/tird.git && cd tird
$ sudo make install
```

## Feedback

Test reports are welcome. Feel free to post any questions, feedback or criticisms to the [Issues](https://github.com/hakavlad/tird/issues).

## License

[Creative Commons Zero v1.0 Universal](https://github.com/hakavlad/tird/blob/main/LICENSE) (Public Domain Dedication).
