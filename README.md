![Logo: random data visualization](https://raw.githubusercontent.com/hakavlad/tird/main/images/logo.png)

# tird

[![CodeQL](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql)
[![Releases](https://img.shields.io/github/v/release/hakavlad/tird?label=Release)](https://github.com/hakavlad/tird/releases)
[![PyPI](https://img.shields.io/pypi/v/tird?color=008080&label=PyPI)](https://pypi.org/project/tird/)
[![Tutorial](https://img.shields.io/badge/%F0%9F%93%96-Tutorial-808)](https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md)
[![man page](https://img.shields.io/badge/tird(1)-man%20page-666)](https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md)
[![Specification](https://img.shields.io/badge/%F0%9F%93%84-Specification-000)](https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md)

`tird` *(an acronym for "this is random data")* is a tool for encrypting files and hiding encrypted data.

With `tird`, you can:

1. Create files filled with random data to use as containers or keyfiles.
2. Overwrite the contents of devices and regular files with random data. This can be used to prepare containers and to destroy residual data.
3. Encrypt file contents and comments with modern cryptographic primitives. The encrypted file format (cryptoblob) is a [padded uniform random blob (PURB)](https://en.wikipedia.org/wiki/PURB_(cryptography)): it looks like random data and has a randomized size. This reduces metadata leakage through file format and length, and also allows cryptoblobs to be hidden among random data. You can use keyfiles and passphrases at your choice to enhance security.
4. Create [steganographic](https://en.wikipedia.org/wiki/Steganography) (hidden, undetectable) user-driven file systems inside container files and devices. Unlike [VeraCrypt](https://veracrypt.fr) and [Shufflecake](https://shufflecake.net/) containers, `tird` containers do not contain headers at all; the user specifies the location of the data in the container and is responsible for ensuring that this location is separated from the container.
5. Resist [coercive](https://en.wikipedia.org/wiki/Coercion) attacks (keywords: [key disclosure law](https://en.wikipedia.org/wiki/Key_disclosure_law), [rubber-hose cryptanalysis](https://en.wikipedia.org/wiki/Deniable_encryption), [xkcd 538](https://xkcd.com/538/)). `tird` provides some forms of [plausible deniability](https://en.wikipedia.org/wiki/Plausible_deniability) out of the box, even if you encrypt files without hiding them in containers.

## Goals

- **File Protection:** Ensuring protection for individual files, including:
  - Symmetric encryption and authentication.
  - Minimizing metadata leakage.
  - Preventing access to data in cases of user coercion.
  - Plausible deniability of payload existence.
  - Hiding encrypted data.
- **Stable Format:** Ensuring a stable encryption format with no [cryptographic agility](https://en.wikipedia.org/wiki/Cryptographic_agility) for long-term data storage.
- **Simplicity:** Ensuring simplicity and avoiding [feature creep](https://en.wikipedia.org/wiki/Feature_creep): refusal to implement features that are not directly related to primary security goals.

## Cryptographic Primitives

The following cryptographic primitives are utilized by `tird`:

- `ChaCha20` cipher ([RFC 7539](https://www.rfc-editor.org/rfc/rfc7539.html)) for data encryption.
- `BLAKE2` ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)) for hashing and authentication.
- `Argon2` memory-hard function ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)) for key stretching and key derivation.

For more details, refer to the [specification](https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md).

## Encrypted File Format

Files encrypted with `tird` (cryptoblobs) cannot be distinguished from random data without knowledge of the keys and have no identifiable headers. `tird` produces cryptoblobs that contain bilateral [randomized padding](https://en.wikipedia.org/wiki/Padding_(cryptography)#Randomized_padding) with uniform random data (PURBs). This minimizes metadata leaks from the file format and makes it possible to hide cryptoblobs among other random data.

For more details, refer to the [specification](https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md).

## Hidden User-Driven File System and Container Format

You can encrypt files and embed cryptoblobs into containers starting at arbitrary positions. After writing the cryptoblob, you will need to remember its location in the container (the starting and ending positions), which will be used later to extract the cryptoblobs. In this way, you can create a **hidden, headerless, user-driven file system** inside a container:

- It is **hidden** because it is impossible to distinguish between random container data and cryptoblob data, as well as to determine the location of written cryptoblobs without knowing the positions and keys.
- It is **headerless** because containers do not contain any headers; all data about cryptoblob locations must be stored separately by the user.
- The starting position of the cryptoblob in the container is **user-defined**, and the **user must** store both the starting and ending positions separately from the container. This is why this "file system" is called a **user-driven file system**.

Any file, disk, or partition larger than ~1 KiB can be a valid container. Cryptoblobs can be embedded into any area.

**Examples of valid containers include:**

1. Specially generated files with random data.
2. Disk areas containing random data. For example, you can overwrite a disk with random data, format it in FAT32 or exFAT, and use a large portion of the disk, leaving a few dozen MB from the beginning. The disk will appear empty unless you add some files to it.
3. `tird` cryptoblobs, as they contain unauthenticated padding of random data by default, which can be used to embed smaller cryptoblobs.
4. VeraCrypt containers, even those that already contain hidden volumes.

**Example of Container Structure:**

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

## Usage

You don’t need to memorize command-line options to use `tird`.

Just start `tird`, select a menu option, and then answer the questions that `tird` will ask:

```
$ tird

                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ random  9. Overwrite w/ random
    ———————————————————————————————————————————
[01] Select an option [0-9]:
```

## Input Options

`tird` has the following input options:

```
[01] Select an option
[02] Use custom settings?
[03] Argon2 time cost
[04] Max padding size
[05] Set a fake MAC tag?
[06] Input file path
[07] Output file path
[08] Output file size
[09] Start position
[10] End position
[11] Comments
[12] Keyfile path
[13] Passphrase
[14] Proceed?
```

A detailed description of these options with examples can be found [here](https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md).

## Debug Mode

Start `tird` with the option `--debug` or `-d` to look under the hood while the program is running:

```bash
$ tird -d
```

Enabling debug messages additionally shows:

- Opening and closing file descriptors.
- Real paths to opened files.
- Moving file pointers using the `seek()` method.
- Salts, passphrases, digests, keys, nonces, tags.
- Some other information.

## Documentation

- [man page](https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md)
- [Input options](https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md)
- [Specification](https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md)
- [Tutorial](https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md)

## Tradeoffs and Limitations

- `tird` does not support [public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography).
- `tird` does not support file compression.
- `tird` does not support ASCII armored output.
- `tird` does not support [Reed–Solomon error correction](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction).
- `tird` does not support splitting the output into chunks.
- `tird` does not support the use of [standard streams](https://en.wikipedia.org/wiki/Standard_streams) for payload transmission.
- `tird` does not support low-level device reading and writing when used on MS Windows (devices cannot be used as keyfiles, cannot be overwritten, and cannot be encrypted or hidden).
- `tird` does not provide a graphical user interface.
- `tird` does not provide a password generator.
- `tird` cannot handle (encrypt/embed) more than one file in one pass. Encryption of directories and multiple files is not supported.
- `tird` does not fake file access, modification, and creation timestamps (atime, mtime, ctime).
- `tird`'s encryption speed is not very fast (up to 180 MiB/s in my tests).

## Warnings

- ⚠️ The author does not have a background in cryptography.
- ⚠️ `tird` has not been independently audited.
- ⚠️ `tird` is unlikely to be effective when used in a compromised environment.
- ⚠️ `tird` is unlikely to be effective when used with short and predictable keys.
- ⚠️ Sensitive data may leak into swap space.
- ⚠️ `tird` does not erase sensitive data from memory after use.
- ⚠️ `tird` always releases unverified plaintext, violating [The Cryptographic Doom Principle](https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html).
- ⚠️ Padding is not used to create a MAC tag (only ciphertext and salt will be authenticated).
- ⚠️ `tird` does not sort digests of keyfiles and passphrases in constant-time.
- ⚠️ Overwriting file contents does not guarantee secure destruction of the data on the media.
- ⚠️ You cannot prove to an adversary that your random-looking data does not contain encrypted data.
- ⚠️ Development is not complete; there may be backward compatibility issues in the future.

<details>
<summary>Image</summary>

![Strong encryption, weak password](https://i.imgur.com/onTA8IX.jpeg)
</details>

## Requirements

- Python >= 3.9
- [PyCryptodomex](https://pypi.org/project/pycryptodomex/) >= 3.6.2 (provides `ChaCha20`)
- [PyNaCl](https://pypi.org/project/PyNaCl/) >= 1.2.0 (provides `BLAKE2` and `Argon2`)

## Installation

### Installation from PyPI

Install `python3` and `python3-pip` (or `python-pip`), then run

```bash
$ pip install tird
```

### Building and Installing the Package on Debian-based Linux Distros

It's easy to build a deb package for Debian and Ubuntu-based distros with the latest git snapshot.

1. Install the build dependencies:

```bash
$ sudo apt install make fakeroot
```

2. Clone the repository (if `git` is already installed) and enter the directory:

```bash
$ git clone https://github.com/hakavlad/tird.git && cd tird
```

3. Build the package:

```bash
$ make build-deb
```

4. Install or reinstall the package:

```bash
$ sudo make install-deb
```

### Standalone Executables

Standalone executables (made with [PyInstaller](https://pyinstaller.org/en/stable/)) are also available (see [Releases](https://github.com/hakavlad/tird/releases)) for MS Windows and Linux amd64. Use at your own risk.

![tird.exe](https://i.imgur.com/hjnarbH.png)

<details>
<summary>How to verify signatures</summary>

Use [Minisign](https://jedisct1.github.io/minisign/) to verify signatures. You can find my public key [here](https://github.com/hakavlad/hakavlad).

For example:

```
$ minisign -Vm  tird-v0.16.0-linux-amd64.zip -P RWQLYkPbRQ8b56zEe8QdbjLFqC9UrjOaYxW5JxwsWV7v0ct/F/XfJlel
```

This requires the signature `tird-v0.16.0-linux-amd64.zip.minisig` to be present in the same directory.
</details>

## TODO

Write or improve the documentation:

- Features
- User Guide
- Specification
- Design Rationale

## Feedback

Please feel free to ask questions, leave feedback, or provide critiques in the [Discussions](https://github.com/hakavlad/tird/discussions) section.
