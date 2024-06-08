![Logo: random data visualization](https://raw.githubusercontent.com/hakavlad/tird/main/images/logo.png)

# tird

[![CodeQL](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql)
[![Releases](https://img.shields.io/github/v/release/hakavlad/tird?label=Release)](https://github.com/hakavlad/tird/releases)
[![PyPI](https://img.shields.io/pypi/v/tird?color=008080&label=PyPI)](https://pypi.org/project/tird/)
[![Tutorial](https://img.shields.io/badge/%F0%9F%93%96-Tutorial-808)](https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md)
[![man page](https://img.shields.io/badge/tird(1)-man%20page-666)](https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md)
[![Specification](https://img.shields.io/badge/%F0%9F%93%84-Specification-000)](https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md)

`tird` *(an acronym for "this is random data")* is a tool for encrypting files and hiding encrypted data.

Using `tird` you can:

1. Create files with random data. Use them as containers or keyfiles.
2. Overwrite the contents of devices and regular files with random data. This can be used to prepare containers and to destroy residual data.
3. Encrypt file contents and comments with modern cryptographic primitives. The encrypted file format (cryptoblob) is [padded uniform random blob (PURB)](https://en.wikipedia.org/wiki/PURB_(cryptography)): it looks like random data and has randomized size. This reduces metadata leakage through file format and length, and also allows cryptoblobs to be hidden among random data.
4. Create [steganographic](https://en.wikipedia.org/wiki/Steganography) (hidden, undetectable) user-driven file systems inside container files and devices. Unlike [VeraCrypt](https://veracrypt.fr) and [Shufflecake](https://shufflecake.net/) containers, `tird` containers do not contain headers at all: the user specifies the location of the data in the container and is responsible for ensuring that this location is separated from the container.
5. Resist [coercive](https://en.wikipedia.org/wiki/Coercion) attacks (keywords: [key disclosure law](https://en.wikipedia.org/wiki/Key_disclosure_law), [rubber-hose cryptanalysis](https://en.wikipedia.org/wiki/Deniable_encryption), [xkcd 538](https://xkcd.com/538/)). `tird` provides some forms of [plausible deniability](https://en.wikipedia.org/wiki/Plausible_deniability) out of the box even if you encrypt files without hiding them in containers.

---

## Goals

- Providing protection for individual files, including:
  - symmetric encryption and authentication;
  - minimizing metadata leakage;
  - preventing access to data in case of user coercion;
  - plausible deniability of payload existence;
  - hiding encrypted data.
- Providing a stable encryption format with no [cryptographic agility](https://en.wikipedia.org/wiki/Cryptographic_agility) for long-term data storage.
- Simplicity and no [feature creep](https://en.wikipedia.org/wiki/Feature_creep): refusal to implement features that are not directly related to primary security goals.

---

## Cryptographic primitives

`tird` uses the following cryptographic primitives:

- `BLAKE2` ([RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693.html)):
  - salted and personalized `BLAKE2b-512` for hashing keyfiles and passphrases;
  - keyed `BLAKE2b-512` for creating message authentication codes;
  - `BLAKE2b-256` for creating message checksums.
- `Argon2` memory-hard function ([RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106/)) for key stretching and key derivation.
- `ChaCha20` cipher ([RFC 7539](https://datatracker.ietf.org/doc/html/rfc7539)) for data encryption.

---

## Encrypted file format

`tird` encrypted files (cryptoblobs) are indistinguishable from random data and have no identifiable headers. `tird` produces cryptoblobs contain bilateral [randomized padding](https://en.wikipedia.org/wiki/Padding_(cryptography)#Randomized_padding) with uniform random data (PURBs). This minimizes metadata leaks from the file format and makes it possible to hide cryptoblobs among other random data.

See the [specification](https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md) for more details.

---

## Hidden user-driven file system and container file format

You can encrypt files and write cryptoblobs over containers starting with arbitary positions.
After finishing writing the cryptoblob, you will be asked to remember the location of the cryptoblob in the container (positions of the beginning and end of the cryptoblob), which can be used in the future to extract the cryptoblob. In this way, you can create a **hidden user-driven file system** inside a container.

It is **hidden** because it is impossible to distinguish between random container data and random cryptoblob data, and it is impossible to determine the location of written cryptoblobs without knowing the positions and keys.

Containers do not contain *any* headers, all data about cryptoblob locations must be stored separately by the user.

The location of the start of the cryptoblob in the container is user-defined, and the location of the start and end positions of the cryptoblob must be stored by the user separately from the container. This is why this "file system" is called a **user-driven file system**.

Container structure (as an example):

```
+—————————+—————————————+— Position 0
|         |             |
|         | Random data |
|         |             |
|         +—————————————+— Cryptoblob1 start position
| Header- |             |
| less    | Cryptoblob1 |
|         |             |
| Layer   +—————————————+— Cryptoblob1 end position
|         | Random data |
| Cake    +—————————————+— Cryptoblob2 start position
|         |             |
|         | Cryptoblob2 |
|         |             |
|         +—————————————+— Cryptoblob2 end position
|         | Random data |
+—————————+—————————————+
```

---

## Usage

You don't need to remember command line options to use `tird`.

Just start `tird`, select a menu option, and then answer the questions that `tird` will ask:

```bash
$ tird
```

![screenshot: MENU](https://i.imgur.com/h2KG9iy.png)

---

## Debug

Start `tird` with the option `--debug` or `-d` to look under the hood while the program is running:

```bash
$ tird -d
```

Enabling debug messages additionally shows:

- opening and closing file descriptors;
- real paths to opened files;
- moving file pointers using the seek() method;
- salts, passphrases, digests, keys, nonces, tags;
- some other info.

---

## Documentation

- [man page](https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md)
- [Input options](https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md)
- [Specification](https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md)
- [Tutorial](https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md)

---

## Tradeoffs and limitations

- `tird` does not support public-key cryptography.
- `tird` does not support file compression.
- `tird` does not support ASCII armored output.
- `tird` does not support Reed–Solomon error correction.
- `tird` does not support splitting the output into chunks.
- `tird` does not support low-level device reading and writing when used on MS Windows (devices cannot be used as keyfiles, cannot be overwritten, cannot be encrypted or hidden).
- `tird` does not provide a graphical user interface.
- `tird` does not provide a password generator.
- `tird` can only encrypt one file per iteration. Encryption of directories and multiple files is not supported.
- `tird` does not fake file timestamps (atime, mtime, ctime).
- `tird` encryption speed is not very fast (up to 180 MiB/s in my tests).

---

## Warnings

- ⚠️ The author is not a cryptographer.
- ⚠️ `tird` has not been independently audited.
- ⚠️ `tird` probably won't help much when used in a compromised environment.
- ⚠️ `tird` probably won't help much when used with short and predictable keys.
- ⚠️ Sensitive data may leak into the swap space.
- ⚠️ `tird` does not erase sensitive data from memory after use.
- ⚠️ `tird` always releases unverified plaintext (violates [The Cryptographic Doom Principle](https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html)).
- ⚠️ Padding is not used to create a MAC tag (only ciphertext and salt will be authenticated).
- ⚠️ `tird` does not sort digests of keyfiles and passphrases in constant-time.
- ⚠️ Overwriting file contents does not mean securely destroying the data on the media.
- ⚠️ Development is not complete, there may be backward compatibility issues in the future.

---

## Requirements

- Python >= 3.6
- [PyNaCl](https://pypi.org/project/PyNaCl/) >= 1.2.0 (provides `Argon2`)
- [PyCryptodomex](https://pypi.org/project/pycryptodomex/) >= 3.6.2 (provides `ChaCha20`)

---

## Installation

### Installing from PyPI

Install `python3` and `python3-pip` (or `python-pip`), then run

```bash
$ pip install tird
```

### Building and installing the package on `deb`-based Linux distros

It's easy to build a `deb` package for Debian and Ubuntu-based distros with the latest git snapshot.

Install the build dependencies:

```bash
$ sudo apt install make fakeroot
```

Clone the repo (if `git` is already installed):

```bash
$ git clone https://github.com/hakavlad/tird.git && cd tird
```

Build the package:

```bash
$ make build-deb
```

Install or reinstall the package:

```bash
$ sudo make install-deb
```

### Standalone executables

Standalone executables (made with [PyInstaller](https://pyinstaller.org/en/stable/)) are also available (see [Releases](https://github.com/hakavlad/tird/releases)) for MS Windows and Linux amd64.

> [!WARNING]
> Use them only if you're brave enough!

![tird.exe](https://i.imgur.com/hjnarbH.png)

<details>
<summary>How to verify signatures</summary>

Use [Minisign](https://jedisct1.github.io/minisign/) to verify signatures. You can find my public key [here](https://github.com/hakavlad/hakavlad). For example:

```
$ minisign -Vm  tird-v0.14.0-linux-amd64.zip -P RWQLYkPbRQ8b56zEe8QdbjLFqC9UrjOaYxW5JxwsWV7v0ct/F/XfJlel
```

This requires the signature `tird-v0.14.0-linux-amd64.zip.minisig` to be present in the same directory.
</details>

---

## TODO

Write or improve the documentation:

- Features;
- User guide;
- Specification;
- Design rationale.

---

## Feedback

Feel free to post any questions, reviews, or criticisms in the [Discussions](https://github.com/hakavlad/tird/discussions).
