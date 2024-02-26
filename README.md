![Logo: random data visualization](https://i.imgur.com/I7vAash.png)

# tird

[![CodeQL](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql)
[![Releases](https://img.shields.io/github/v/release/hakavlad/tird?label=Release)](https://github.com/hakavlad/tird/releases)
[![PyPI](https://img.shields.io/pypi/v/tird?color=008080&label=PyPI)](https://pypi.org/project/tird/)

`tird` *(an acronym for "this is random data")* is a tool for writing random bytes, encrypting file contents, and hiding encrypted data.

`tird` can create files with random data, overwrite file contents with random data, encrypt file contents and comments, hide encrypted data among random data, minimize metadata leakage, and can provide some forms of [plausible deniability](https://en.wikipedia.org/wiki/Plausible_deniability#Use_in_cryptography).

`tird` aims to provide a stable encryption format for long-term data storage using modern and standardized cryptographic primitives.

![screenshot: MENU](https://i.imgur.com/cZX73zg.png)

## Goals

- Providing protection for individual files, including:
  - symmetric encryption;
  - reducing metadata leakage;
  - hiding encrypted data;
  - plausible deniability.
- Providing a stable encryption format with no [cryptographic agility](https://en.wikipedia.org/wiki/Cryptographic_agility) for long-term data storage.
- Simplicity and no [feature creep](https://en.wikipedia.org/wiki/Feature_creep): refusal to implement features that are not directly related to primary security goals.

## Cryptographic primitives

`tird` uses the following cryptographic primitives:
- `BLAKE2` ([RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693.html)):
  - salted and personalized `BLAKE2b` for hashing keyfiles and passphrases;
  - keyed `BLAKE2b` for message authentication.
- `Argon2` memory-hard function ([RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106/)) for key stretching and key derivation.
- `ChaCha20` cipher ([RFC 7539](https://datatracker.ietf.org/doc/html/rfc7539)) for data encryption.

## Encryption format (cryptoblob structure)

```
                     512B          0+B
                 +----------+---------------+
                 | comments | file contents |
                 +----------+---------------+
  16B     0+B    |     plaintext/payload    | 64B     0+B     16B
+------+---------+--------------------------+-----+---------+------+
| salt | padding |        ciphertext        | MAC | padding | salt |
+------+---------+--------------------------+-----+---------+------+
|  random bytes  |    random-looking bytes        |  random bytes  |
+----------------+--------------------------------+----------------+
```

## Tradeoffs and limitations

- `tird` does not support public-key cryptography.
- `tird` does not support file compression.
- `tird` does not support ASCII armored output.
- `tird` does not support Reed–Solomon error correction.
- `tird` does not support splitting the output into chunks.
- `tird` does not support low-level device reading and writing when used on MS Windows (devices cannot be used as keyfiles, cannot be overwritten, cannot be encrypted or hidden).
- `tird` does not provide a graphical user interface.
- `tird` does not provide a password generator.
- `tird` does not wipe sensitive data from the heap.
- `tird` can only encrypt one file per iteration. Encryption of directories and multiple files is not supported.
- `tird` does not fake file timestamps (atime, mtime, ctime).
- `tird` encryption speed is not very fast: up to 180 MiB/s (in my tests).

## Warnings

- ⚠️ The author is not a cryptographer.
- ⚠️ `tird` has not been independently audited.
- ⚠️ `tird` probably won't help much when used in a compromised environment.
- ⚠️ `tird` probably won't help much when used with short and predictable keys.
- ⚠️ Keys may leak into the swap space.
- ⚠️ `tird` always releases unverified plaintext (violates [The Cryptographic Doom Principle](https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html)).
- ⚠️ `tird` does not sort digests of keyfiles and passphrases in constant time.
- ⚠️ Development is ongoing, there may be backward compatibility issues in the future.

## Usage

You don't need to remember command line options to use `tird`.

Just start `tird`, select a menu option, and then answer the questions that `tird` will ask:

```bash
$ tird
```

## Debug

Start `tird` with the option `--debug` or `-d` to look under the hood while the program is running:

```bash
$ tird -d
```

## Requirements

- Python >= 3.6
- [PyNaCl](https://pypi.org/project/PyNaCl/) >= 1.2.0 (provides `Argon2`)
- [PyCryptodomex](https://pypi.org/project/pycryptodomex/) >= 3.6.2 (provides `ChaCha20`)

## Install

Install `python3` and `python3-pip` (or `python-pip`), then run

```bash
$ pip install tird
```

Standalone executables (made with [PyInstaller](https://pyinstaller.org/en/stable/)) are also available (see [Releases](https://github.com/hakavlad/tird/releases)).

![tird.exe](https://i.imgur.com/4Usuzwa.png)

## TODO

Write documentation:
- Features;
- Specification;
- Design rationale;
- User guide.

## Feedback

Feel free to post any questions, feedback or criticisms to the [Discussions](https://github.com/hakavlad/tird/discussions).

## License

This project is licensed under the terms of the [Creative Commons Zero v1.0 Universal License](https://github.com/hakavlad/tird/blob/main/LICENSE) (Public Domain Dedication).
