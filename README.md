![Logo: random data visualization](https://i.imgur.com/SB44MiB.png)

# tird

[![CodeQL](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql)
[![Releases](https://img.shields.io/github/v/release/hakavlad/tird)](https://github.com/hakavlad/tird/releases)
[![PyPI](https://img.shields.io/pypi/v/tird?color=blue&label=PyPI)](https://pypi.org/project/tird/)

`tird` *(an acronym for "this is random data")* is a tool for encrypting file contents and hiding random data among other random data.

![screenshot: MENU](https://i.imgur.com/37GEudr.png)

## Goals

- Providing protection for individual files, including:
  - symmetric encryption;
  - minimizing metadata leakage;
  - plausible deniability;
  - data hiding (prevention of detection).
- Keep it simple: refusal to implement functions that are not directly related to primary security goals.
- Providing a stable encryption format with no cryptographic agility for long-term data storage.

## Cryptographic primitives

- BLAKE2b:
  - salted and personalized BLAKE2b as part of a key derivation scheme;
  - keyed BLAKE2b for data authentication.
- Argon2 memory-hard function for key stretching and key derivation.
- ChaCha20-IETF cipher for data encryption.

## Cryptoblob structure
```
                     512B          0+B
                 +----------+---------------+
                 | comments | file contents |
                 +----------+---------------+
  16B     0+B    |        plaintext         | 64B     0+B     16B
+------+---------+--------------------------+-----+---------+------+
| salt | padding |        ciphertext        | MAC | padding | salt |
+------+---------+--------------------------+-----+---------+------+
|  urandom data  |      random-looking data       |  urandom data  |
+----------------+--------------------------------+----------------+
```

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
- `tird` encryption speed is not very fast: up to 186 MiB/s (in my tests).

## Warnings

![ACHTUNG MINEN](https://i.imgur.com/mESTDyh.jpeg)

- 🚩 The author is not a cryptographer.
- 🚩 `tird` has not been independently audited.
- 🚩 `tird` probably won't help much when used in a compromised environment.
- 🚩 `tird` probably won't help much when used with short and predictable keys.
- 🚩 Keys may leak into the swap space.
- 🚩 `tird` violates [The Cryptographic Doom Principle](https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html) (releases unverified plaintext).
- 🚩 `tird` does not sort digests of passphrases and keyfiles in constant time.
- 🚩 Development is ongoing, there may be backward compatibility issues in the future.

## Usage

Just run the script, select the option you want and then answer the questions.

## Requirements

- Python >= 3.6
- PyNaCl >= 1.2.0 (provides `Argon2` KDF)
- PyCryptodomex >= 3.6.2 (provides `ChaCha20` cipher)

## Install

Install python3 and python3-pip (or python-pip), than run
```bash
$ pip install tird
```

Binary builds (made with [PyInstaller](https://pyinstaller.org/en/stable/)) are also available (see [Releases](https://github.com/hakavlad/tird/releases)).

## TODO

Write documentation.

## Feedback

Test reports are welcome. Feel free to post any questions, feedback or criticisms to the [Discussions](https://github.com/hakavlad/tird/discussions).

## License

[Creative Commons Zero v1.0 Universal](https://github.com/hakavlad/tird/blob/main/LICENSE) (Public Domain Dedication).
