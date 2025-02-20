<p align="left">
  <img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/container.png" width="850" alt="Logo: visualization of embedding">
</p>

# tird [![Releases](https://img.shields.io/github/v/release/hakavlad/tird?color=blue&label=Release)](https://github.com/hakavlad/tird/releases)&nbsp;[![PyPI](https://img.shields.io/pypi/v/tird?color=blue&label=PyPI)](https://pypi.org/project/tird/)

<h3 align="left">
  <a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">📜&nbsp;man&nbsp;page</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">📑&nbsp;Specification</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">📄&nbsp;Input&nbsp;Options</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">📖&nbsp;Tutorial</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">❓&nbsp;FAQ</a>
</h3>

<details>
  <summary>&nbsp;<b>Contents</b></summary>

> - [About](#about)
> - [Goals](#goals)
> - [Cryptographic Primitives](#cryptographic-primitives)
> - [Encrypted Data Format](#encrypted-data-format)
> - [Hidden File System and Container Format](#hidden-file-system-and-container-format)
> - [Storing and Carrying Concealed Encrypted Data](#storing-and-carrying-concealed-encrypted-data)
> - [Usage](#usage)
> - [Input Options](#input-options)
> - [Debug Mode](#debug-mode)
> - [Tradeoffs and Limitations](#tradeoffs-and-limitations)
> - [Warnings](#warnings)
> - [Requirements](#requirements)
> - [Installation](#installation)
> - [TODO](#todo)
> - [Feedback](#feedback)

</details>

## About

`tird` *(an acronym for "this is random data")* is a **file encryption tool** focused on
- **minimizing metadata** and
- **hiding encrypted data**.

With `tird`, you can:

1. Create files filled with random data to use as containers or keyfiles.
2. Overwrite the contents of block devices and regular files with random data. This can be used to prepare containers and to destroy residual data.
3. Encrypt file contents and comments with modern cryptographic primitives. The encrypted data format (called cryptoblob) is a [padded uniform random blob (PURB)](https://en.wikipedia.org/wiki/PURB_(cryptography)): it looks like random data and has a randomized size. This reduces metadata leakage from file format and length, and also allows cryptoblobs to be hidden among random data. You can use keyfiles and passphrases at your choice to enhance security.
4. Create [steganographic](https://en.wikipedia.org/wiki/Steganography) (hidden, undetectable) user-driven file systems inside container files and block devices. Unlike [VeraCrypt](https://veracrypt.fr) and [Shufflecake](https://shufflecake.net/) containers, `tird` containers do not contain headers at all; the user specifies the location of the data in the container and is responsible for ensuring that this location is separated from the container.
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

## Encrypted Data Format

```
+————————————————————————————————————————+—————————+
| Salt for key stretching (Argon2): 16 B |         |
+————————————————————————————————————————+ Random  |
| Randomized padding: 0-20% of the       | data    |
| unpadded cryptoblob size by default    |         |
+————————————————————————————————————————+—————————+
| Ciphertext (ChaCha20): 512+ B,         |         |
| consists of:                           |         |
| - Encrypted padded/truncated           | Random- |
|   comments, always 512 B               | looking |
| - Encrypted payload file               | data    |
|   contents, 0+ B                       |         |
+————————————————————————————————————————+         |
| Optional MAC tag (BLAKE2/random): 64 B |         |
+————————————————————————————————————————+—————————+
| Randomized padding: 0-20% of the       |         |
| unpadded cryptoblob size by default    | Random  |
+————————————————————————————————————————+ data    |
| Salt for prehashing (BLAKE2): 16 B     |         |
+————————————————————————————————————————+—————————+
```

Files encrypted with `tird` cannot be distinguished from random data without knowledge of the keys and have no identifiable headers. `tird` produces cryptoblobs that contain bilateral [randomized padding](https://en.wikipedia.org/wiki/Padding_(cryptography)#Randomized_padding) with uniform random data (PURBs). This minimizes metadata leaks from the file format and makes it possible to hide cryptoblobs among other random data.

## Hidden File System and Container Format

`tird` employs a technique that is [described](https://en.wikipedia.org/wiki/List_of_steganography_techniques#Digital) as follows:

> Concealing data within encrypted data or within random data. The message to conceal is encrypted, then used to overwrite part of a much larger block of encrypted data or a block of random data (an unbreakable cipher like the one-time pad generates ciphertexts that look perfectly random without the private key).

You can encrypt files and embed cryptoblobs into containers starting at arbitrary positions. After writing the cryptoblob, you will need to remember its location in the container (the starting and ending positions), which will be used later to extract the cryptoblobs. In this way, you can create a **hidden, headerless, user-driven file system** inside a container:

- It is **hidden** because it is impossible to distinguish between random container data and cryptoblob data, as well as to determine the location of written cryptoblobs without knowing the positions and keys.
- It is **headerless** because containers do not contain any headers; all data about cryptoblob locations must be stored separately by the user.
- The starting position of the cryptoblob in the container is **user-defined**, and the **user must** store both the starting and ending positions separately from the container. This is why it is called a **user-driven file system**.

Any file, disk, or partition larger than the minimum cryptonlob size (608 B) can be a valid container. Cryptoblobs can be embedded into any area.

**Examples of Valid Containers Include:**

1. Specially generated files with random data.
2. Disk areas containing random data. For example, you can overwrite a disk with random data, format it in FAT32 or exFAT, and use a large portion of the disk, leaving a few dozen MB from the beginning. The disk will appear empty unless you add some files to it.
3. `tird` cryptoblobs, as they contain unauthenticated padding of random data by default, which can be used to embed smaller cryptoblobs.
4. VeraCrypt containers, even those that already contain hidden volumes.

**Example of Container Structure:**

```
+—————————+—————————————+ <— Position 0 of the container
|         |             |
|         | Random data |
|         |             |
|         +—————————————+ <— Cryptoblob1 start position
| Header- |             |
| less    | Cryptoblob1 |
|         |             |
| Layer   +—————————————+ <— Cryptoblob1 end position
|         | Random data |
| Cake    +—————————————+ <— Cryptoblob2 start position
|         |             |
|         | Cryptoblob2 |
|         |             |
|         +—————————————+ <— Cryptoblob2 end position
|         | Random data |
+—————————+—————————————+
```

**Visualization of Embedding**

The next image visualizes how hard it is to distinguish one random data entry from another and the process of embedding cryptoblobs in a container.

<details>
  <summary>&nbsp;<b>Show Images</b></summary>

<br>

- Empty container with random data:

<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/container.png" width="850" alt="Container">
<br>


- One cryptoblob embedded in the container:

<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/embed1.png" width="850" alt="Embedded1">
<br>

- Two cryptoblobs embedded in the container:

<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/embed2.png" width="850" alt="Embedded2">
<br>

- Three cryptoblobs embedded in the container:

<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/embed3.png" width="850" alt="Embedded3">
<br>

- Animation: visualization of embedding:

<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/embedding.gif" width="850" alt="GIF: visualization of embedding">

</details>

## Storing and Carrying Concealed Encrypted Data

Please look at at the following screenshot.

<img src="https://i.imgur.com/2tpEhTw.png" width="839" alt="Screenshot">

It looks like this 16 GB volume contains only one 8.7 MiB file. Is it really true? Maybe yes, maybe no.

The file system tells us that there is only one file here. But is there really only one file on the volume? We cannot find this out using the file system. In fact, data may be located outside the file system and be undetectable by file system tools. 15.2 GiB of space marked as free may be occupied by a hidden file system. This "free" space may be taken up by hidden encrypted data.

Can the existence of this data be disproven? Yes, for example, by examining the entropy level of this free space using `binwalk`. Low entropy indicates a probable absence of hidden data. High entropy *does not*, *by itself*, prove the presence of encrypted hidden data. Areas with high entropy can be either just residual data or hidden encrypted data.

If you are interested in hiding data outside the visible file system, then `tird` is at your service.

## Usage

You don't need to memorize command-line options to use `tird`. This tool features a prompt-based CLI: simply start it, select a menu option, and answer the questions that will follow.

```
$ tird

                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
[00] Select an option [0-9]:
```

## Input Options

There are 5 groups of input options. They are numbered for ease of description.

```
+———————————————————————————+——————————————————————————+
| [00] Select an option     | [00] Select an action    |
+———————————————————————————+——————————————————————————+
| [10] Use custom settings? |                          |
| [11] Time cost            | [1x] Set custom settings |
| [12] Max padding size     |                          |
| [13] Set fake MAC tag?    |                          |
+———————————————————————————+——————————————————————————+
| [21] Input file path      |                          |
| [22] Comments             | [2x] Enter data,         |
| [23] Output file path     |      data location,      |
| [24] Output file size     |      data size           |
| [25] Start position       |                          |
| [26] End position         |                          |
+———————————————————————————+——————————————————————————+
| [31] Keyfile path         | [3x] Specify input       |
| [32] Passphrase           |      keying material     |
+———————————————————————————+——————————————————————————+
| [40] Proceed?             | [40] Confirm to continue |
+———————————————————————————+——————————————————————————+
```

A detailed description of these options with examples can be found [here](https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md).

## Debug Mode

Start `tird` with the `--debug` option to look under the hood while the program is running:

```bash
$ tird --debug
```

Enabling debug messages additionally shows:

- File operations:
  - Opening and closing of file descriptors.
  - Real paths to opened files.
  - Movement of file pointers.
- Byte strings related to cryptographic operations: salts, passphrases, digests, keys, nonces, and tags.
- Some other information, including various sizes.

## Tradeoffs and Limitations

- `tird` does not support:
  - [Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography).
  - File compression.
  - ASCII armored output.
  - [Reed–Solomon error correction](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction).
  - Splitting the output into chunks.
  - The use of [standard streams](https://en.wikipedia.org/wiki/Standard_streams) for processing files.
  - Low-level block device reading and writing on MS Windows. As a result, these devices cannot be used as keyfiles, cannot be overwritten, and cannot be encrypted or embedded.
- `tird` does not provide:
  - A graphical user interface.
  - A password generator.
- `tird` cannot handle (encrypt/embed) more than one file in one pass. Encryption of directories and multiple files is not supported.
- `tird` does not fake file access, modification, and creation timestamps (atime, mtime, ctime).
- `tird`'s encryption speed is not very high (up to 420 MiB/s in my tests).

## Warnings

![DANGER MINES](https://i.imgur.com/JaMXwNV.jpeg)

- ⚠️ The author does not have a background in cryptography.
- ⚠️ The code has 0% test coverage.
- ⚠️ `tird` has not been independently audited.
- ⚠️ `tird` is ineffective in a compromised environment; executing it in such cases may cause disastrous data leaks.
- ⚠️ `tird` is unlikely to be effective when used with short and predictable keys.
- ⚠️ Sensitive data may leak into swap space.
- ⚠️ `tird` does not erase its sensitive data from memory after use.
- ⚠️ `tird` always releases unverified plaintext, violating [The Cryptographic Doom Principle](https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html); decrypted output is untrusted by default.
- ⚠️ Padding contents are never authenticated; authentication only applies to the ciphertext, salts, and certain sizes.
- ⚠️ Padding sizes depend on secret values.
- ⚠️ `tird` does not sort digests of keyfiles and passphrases in constant-time.
- ⚠️ Overwriting file contents does not guarantee secure destruction of data on the media.
- ⚠️ You cannot prove to an adversary that your random data does not contain encrypted information.
- ⚠️ `tird` protects data, not the user; it cannot prevent torture if you are under suspicion.
- ⚠️ Development is not complete, and there may be backward compatibility issues.

## Requirements

- Python >= 3.9.2
- [cryptography](https://pypi.org/project/cryptography/) >= 2.1 (provides `ChaCha20`)
- [PyNaCl](https://pypi.org/project/PyNaCl/) >= 1.2.0 (provides `Argon2` and `BLAKE2`)

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

Standalone executables (made with [PyInstaller](https://pyinstaller.org/en/stable/)) are also available (see [Releases](https://github.com/hakavlad/tird/releases)) for Windows and Linux (amd64). Please use at your own risk.

![tird.exe](https://i.imgur.com/yaUKt6X.png)

<details>
  <summary>&nbsp;<b>How to Verify Signatures</b></summary>

<br>
Use [Minisign](https://jedisct1.github.io/minisign/) to verify signatures. You can find my public key [here](https://github.com/hakavlad/hakavlad).

For example:

```
$ minisign -Vm  tird-v0.18.0-linux-amd64.zip -P RWQLYkPbRQ8b56zEe8QdbjLFqC9UrjOaYxW5JxwsWV7v0ct/F/XfJlel
```

This requires the signature `tird-v0.18.0-linux-amd64.zip.minisig` to be present in the same directory.
</details>

## TODO

Write or improve the documentation:

- Features
- User Guide
- Specification
- Design Rationale

## Feedback

Please feel free to ask questions, leave feedback, or provide critiques in the [Discussions](https://github.com/hakavlad/tird/discussions) section.
