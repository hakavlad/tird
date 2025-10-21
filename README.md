<img src="https://raw.githubusercontent.com/hakavlad/tird/main/images/logo2.png" width="800" alt="Logo">

<h4 align="left">
  📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">man&nbsp;page</a>&nbsp;&nbsp;&nbsp;
  📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a>&nbsp;&nbsp;&nbsp;
  📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a>&nbsp;&nbsp;&nbsp;
  📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial</a>&nbsp;&nbsp;&nbsp;
  ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ</a>&nbsp;&nbsp;&nbsp;
  📥&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INSTALLATION.md">Installation</a>
</h4><br>

[![Releases](https://img.shields.io/github/v/release/hakavlad/tird?color=blue&label=Release)](https://github.com/hakavlad/tird/releases)
[![PyPI](https://img.shields.io/pypi/v/tird?color=blue&label=PyPI)](https://pypi.org/project/tird/)
[![CodeQL](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/github-code-scanning/codeql)
[![trivy](https://github.com/hakavlad/tird/actions/workflows/trivy.yml/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/trivy.yml)
[![Bandit](https://github.com/hakavlad/tird/actions/workflows/bandit.yml/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/bandit.yml)
[![Semgrep](https://github.com/hakavlad/tird/actions/workflows/semgrep.yml/badge.svg)](https://github.com/hakavlad/tird/actions/workflows/semgrep.yml)

<details>
  <summary>&nbsp;<b>Table of Contents</b></summary>

> - [About](#about)
> - [Goals](#goals)
> - [Features](#features)
> - [Usage](#usage)
> - [Input Options](#input-options)
> - [Payload](#payload)
> - [Input Keying Material](#input-keying-material)
> - [Encrypted Data Format](#encrypted-data-format)
> - [Low Observability and Minimizing Metadata](#low-observability-and-minimizing-metadata)
> - [Hidden File System and Container Format](#hidden-file-system-and-container-format)
> - [Storing and Carrying Concealed Encrypted Data](#storing-and-carrying-concealed-encrypted-data)
> - [Time-lock Encryption](#time-lock-encryption)
> - [Command-line Options](#command-line-options)
> - [Unsafe Debug Mode](#unsafe-debug-mode)
> - [Unsafe Decrypt Mode](#unsafe-decrypt-mode)
> - [Tradeoffs and Limitations](#tradeoffs-and-limitations)
> - [Warnings](#warnings)
> - [LLM reports](#llm-reports)
> - [Requirements](#requirements)
> - [Documentation](#documentation)
> - [TODO](#todo)
> - [Feedback](#feedback)

</details>

## About

`tird` /tɪrd/ *(an acronym for "this is random data")* is a file encryption tool focused on minimizing metadata and resisting coercive attacks.

With `tird`, you can:

1. Create files filled with random data to use as containers or keyfiles.
2. Overwrite the contents of block devices and regular files with random data to prepare containers or destroy residual data.
3. Encrypt file contents and comments with keyfiles and passphrases. The encrypted data format (cryptoblob) is a [padded uniform random blob (PURB)](https://en.wikipedia.org/wiki/PURB_(cryptography)): it looks like random data and has a randomized size. This reduces metadata leakage from file format and length and allows cryptoblobs to be hidden among random data. 
4. Create [steganographic](https://en.wikipedia.org/wiki/Steganography) (hidden, undetectable) user-driven filesystems inside container files and block devices. Unlike [VeraCrypt](https://veracrypt.fr) and [Shufflecake](https://shufflecake.net/), `tird` containers do not contain headers; the user specifies the data locations inside the container and is responsible for keeping those locations separate. Any random-looking region of a file or block device may be used as a container.
5. Prevent fast access to decrypted data using time-lock encryption.

`tird` is designed to resist [coercive](https://en.wikipedia.org/wiki/Coercion) [key-disclosure](https://en.wikipedia.org/wiki/Key_disclosure_law) attacks ([rubber-hose cryptanalysis](https://en.wikipedia.org/wiki/Deniable_encryption), [xkcd 538](https://xkcd.com/538/)) and offers built-in [plausible deniability](https://en.wikipedia.org/wiki/Plausible_deniability) — even when encrypted files are stored outside containers.

> \[!WARNING]
> Before using `tird`, please read the "[Warnings](#warnings)" section. Security depends not only on the tool but on your actions: secure key storage, operating in a safe environment, and avoiding debug mode with real data.

🔜 Format stabilization and a formal specification are planned for v1.0.0.

## Goals

- 🛡️ **File protection:** Ensure protection of individual files, including:
    - Authenticated symmetric encryption.
    - Minimizing metadata leakage.
    - Resisting coercive attacks.
- ⚓ **Stable format:** Ensure a stable encrypted-data format with no [cryptographic agility](https://en.wikipedia.org/wiki/Cryptographic_agility) for long-term storage.
- ⚪ **Simplicity:** Ensure simplicity and avoid [feature creep](https://en.wikipedia.org/wiki/Feature_creep); refuse to implement features not directly related to the primary security goals.

## Features 

- [x] **PURB-format encrypted blobs:** randomized size and uniformly random contents; metadata-limited (only total size leaks — no headers, types, or plaintext hints).
- [x] **Padded and encrypted comments:** no plaintext hints about content.
- [x] **Hidden data embedding (optional):** conceal cryptoblobs inside random/encrypted containers for plausible deniability.
- [x] **Time-lock encryption (optional):** slow offline PoW-based key derivation to delay decryption (anti-coercion).
- [x] **Fully committing ChaCha20-BLAKE2b AEAD:** secure authenticated encryption.
- [x] **Strong key stretching:** Argon2id (libsodium "sensitive" profile) — 1 GiB memory, 1 lane, 4 passes (default and minimum).
- [x] **Arbitrary key material:** derive keys from passphrases, files, block devices, or directories — order does not matter.
- [x] **Prompt-based CLI:** intuitive and interactive, no flags to memorize.
- [ ] \[TODO] **Stable, documented format:** planned for long-term archival and interoperability.

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
A0. SELECT AN OPTION [0-9]:
```

## Input Options

There are 4 groups of input options: A (Action), D (Data), K (Keys), P (Proceed). They are numbered for ease of description.

```
+——————————————————————+————————————————————————+
| A0. SELECT AN OPTION | A. Select an action    |
+——————————————————————+————————————————————————+
| D1. INPUT FILE PATH  |                        |
| D2. COMMENTS         | D. Enter data,         |
| D3. OUTPUT FILE PATH |    data location,      |
| D4. OUTPUT FILE SIZE |    data size           |
| D5. START POSITION   |                        |
| D6. END POSITION     |                        |
+——————————————————————+————————————————————————+
| K1. KEYFILE PATH     | K. Enter values        |
| K2. PASSPHRASE       |    related to          |
| K3. TIME COST        |    key derivation      |
+——————————————————————+————————————————————————+
| P0. PROCEED?         | P. Confirm to continue |
+——————————————————————+————————————————————————+
```

A detailed description of these options with examples can be found [here](https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md).

## Payload

The payload that will be encrypted during cryptoblob creation consists of:

- **Contents of one file (optional):** A regular file or a block device (entire disk/partition). If omitted, an empty file payload is encrypted.
- **Comments (optional):** Arbitrary UTF‑8 string, up to 1 KiB. By default, the input file name is used. Decrypted comments are shown upon decryption.

Specifying the payload in the UI looks as follows:

```
D1. FILE TO ENCRYPT (OPT): files.zip
    I: path: 'files.zip'; size: 2,824,230,648 B (2.6 GiB)
D2. COMMENTS (DEFAULT='files.zip'): The X-Files, zip (секретные материалы)
    I: comments will be shown as ['The X-Files, zip (секретные материалы)']
```

## Input Keying Material

`tird` provides the option to use the contents of keyfiles and a passphrase to derive one-time keys.

- **Keyfiles (optional):** Zero, one, or multiple keyfile paths; order of inputs does not matter. A keyfile path may be:
  - A <ins>regular file</ins>. The contents of the keyfile will be hashed, and its digest will be used for further key stretching and key derivation.
  - A <ins>block device</ins>. Handled the same as a regular keyfile: contents will be hashed.
  - A <ins>directory</ins>. All files within the directory will be hashed and used as keyfiles.
- **Passphrase (optional):** Up to 2048 bytes after Unicode [normalization](https://www.unicode.org/reports/tr15/) (form C); may be omitted.

Specifying IKM in the UI looks as follows:

```
K1. KEYFILE PATH (OPT): key 
    I: path: 'key'; size: 32 B
    I: reading and hashing contents of 'key'
    I: keyfile accepted
K1. KEYFILE PATH (OPT): 
K2. PASSPHRASE (OPT): 
K2. CONFIRM PASSPHRASE: 
    I: passphrase accepted
```

## Encrypted Data Format

<img src="https://i.imgur.com/wAJyAJc.png" width="280" alt="256 shades of grey">

- **PURB format**:
  - Data that looks random and contains no identifiable headers; it cannot be distinguished from random data without the corresponding keys. This property allows cryptoblobs to be hidden among other random data.
  - [Randomized size](https://en.wikipedia.org/wiki/Padding_(cryptography)#Randomized_padding): padding length is chosen uniformly between 0% and 25% of the unpadded cryptoblob size (equivalently, up to 20% of the final cryptoblob size). Padding length is chosen uniformly from the allowed interval.
- **Comments** are padded (or truncated) to a fixed size of 1 KiB before encryption, fully concealing their original length. 
- **Bilaterally applied salts**: overwriting the beginning or the end of the cryptoblob (or storing an incomplete cryptoblob) makes successful decryption impossible.

<details>
  <summary>&nbsp;<b>Show cryptoblob scheme</b></summary>

```
+————————————————————————————————————————————————————————+
| CSPRNG output:                                         |
|     Salt for key stretching used with Argon2 (16 B)    |
+————————————————————————————————————————————————————————+
| ChaCha20 output:                                       |
|     Encrypted pad_ikm (8 B)                            |
+————————————————————————————————————————————————————————+
| CSPRNG/BLAKE2 output:                                  |
|     Randomized padding (0-25% of the unpadded size)    |
|     + MAC tag (32 B)                                   |
+————————————————————————————————————————————————————————+
| ChaCha20/BLAKE2 output:                                |
|     Encrypted payload file contents + MAC tags (0+ B)  |
+————————————————————————————————————————————————————————+
| ChaCha20/BLAKE2 output:                                |
|     Encrypted padded comments (1 KiB) + MAC tag (32 B) |
+————————————————————————————————————————————————————————+
| CSPRNG output:                                         |
|     Salt for pre‑hashing IKM used with BLAKE2 (16 B)   |
+————————————————————————————————————————————————————————+
```

</details>

For more details, refer to the [specification](https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md).

## Low Observability and Minimizing Metadata

> While the content of an encrypted message is protected, its size, its provenance, its destination… are not. Data is hidden, metadata is shown.

<i>— <a href="https://loup-vaillant.fr/articles/rolling-your-own-crypto">Loup Vaillant</a></i>

|![](https://i.imgur.com/ArRAis1.jpeg)<br>Vs.<br>![](https://i.imgur.com/Oa3y3qg.jpeg)|
|-|

- PURB format:
  - Encrypted files look like random data.
  - Encrypted files have a randomized size: do not reveal the payload size.
- Comments are constant-padded, do not reveal their size or existence.
- Does not prove that the entered keys are incorrect.
- Prompt-based CLI: no leakage of used options through shell history.
- The output file path is user-defined and is not related to the input file path by default.
- Optional: hiding encrypted data in containers.

## Hidden File System and Container Format

`tird` employs a technique that is [described](https://en.wikipedia.org/wiki/List_of_steganography_techniques#Digital) as follows:

> Concealing data within encrypted data or within random data. The message to conceal is encrypted, then used to overwrite part of a much larger block of encrypted data or a block of random data (an unbreakable cipher like the one-time pad generates ciphertexts that look perfectly random without the private key).

You can encrypt files and embed cryptoblobs into containers starting at arbitrary positions. After writing the cryptoblob, you will need to remember its location in the container (the starting and ending positions), which will be used later to extract the cryptoblobs. In this way, you can create a **hidden, headerless, user-driven file system** inside a container:

- It is **hidden** because it is impossible to distinguish between random container data and cryptoblob data, as well as to determine the location of written cryptoblobs without knowing the positions and keys.
- It is **headerless** because containers do not contain any headers; all data about cryptoblob locations must be stored separately by the user.
- The starting position of the cryptoblob in the container is **user-defined**, and the **user must** store both the starting and ending positions separately from the container. This is why it is called a **user-driven file system**.

Any file, disk, or partition larger than the minimum cryptoblob size (1128 B) can be a valid container. Cryptoblobs can be embedded into any area.

**Examples of Valid Containers include:**

1. Specially generated files with random data.
2. Disk areas containing random data. For example, you can overwrite a disk with random data, format it in FAT32 or exFAT, and use a large portion of the disk, leaving a few dozen MB from the beginning. The disk will appear empty unless you add some files to it.
3. [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) encrypted volumes.
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

#### Visualization of Embedding

The next image visualizes how hard it is to distinguish one random data entry from another and the process of embedding cryptoblobs in a container.

<details>
  <summary>&nbsp;<b>Show Images</b></summary>

<br>

*Empty container with random data:*
<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/container.png" width="800" alt="Container">

*One cryptoblob embedded in the container:*
<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/embed1.png" width="800" alt="Embedded1">

*Two cryptoblobs embedded in the container:*
<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/embed2.png" width="800" alt="Embedded2">

*Three cryptoblobs embedded in the container:*
<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/embed3.png" width="800" alt="Embedded3">

*Animation: visualization of embedding:*
<img src="https://raw.githubusercontent.com/hakavlad/tird/refs/heads/main/images/embedding/embedding.gif" width="800" alt="GIF: visualization of embedding">

</details>

## Storing and Carrying Concealed Encrypted Data

Please look at the following screenshot.

<img src="https://i.imgur.com/2tpEhTw.png" width="839" alt="Screenshot">

It looks like this 16 GB volume contains only one 8.7 MiB file. Is it really true? Maybe yes, maybe no.

The file system tells us that there is only one file here. But is there really only one file on the volume? We cannot determine this using the file system. In fact, data may be located outside the file system and be undetectable by file system tools. The 15.2 GiB of space marked as free may be occupied by a hidden file system. This "free" space may be taken up by hidden encrypted data.

Can we disprove the existence of this data? Yes, for example, by examining the entropy level of this free space using `binwalk`. Low entropy indicates a likely absence of hidden data. High entropy *does not*, *by itself*, prove the presence of encrypted hidden data. Areas with high entropy can be either just residual data or hidden encrypted data.

If you are interested in hiding data outside the visible file system, then `tird` is at your service to provide an Invisibility Cloak for your files.

## Time-lock Encryption

<img src="https://i.imgur.com/65xm1mK.jpeg" width="280" alt="TLE image">

Time-lock encryption (TLE) can be used to prevent an adversary from quickly accessing plaintexts in the event of an IKM compromise (in case of user coercion, for example). In our implementation, it is actually a PoW-based time-lock key derivation. The "Time cost" input option specifies the number of Argon2 passes. If you specify a sufficiently high number of passes, it will take a significant amount of time to perform them. However, an attacker will require the same amount of time when using similar hardware. The execution of Argon2 cannot be accelerated through parallelization, so it is expected that the time spent by an attacker will be approximately the same as that spent by the defender.

This TLE implementation works offline, unlike [tlock](https://github.com/drand/tlock).

Set the desired `TIME COST` value:

```
K3. TIME COST (DEFAULT=4): 1000000
    I: time cost: 1,000,000
    W: decryption will require the same "TIME COST" value!
```

**Plausible TLE:** The adversary does not know the actual value of the time cost, so you can plausibly misrepresent the number of passes. The adversary cannot refute your claim until they attempt to decrypt the cryptoblob using the specified time cost value.

## Command-line Options

`tird` requires no command-line options for normal use.

```
$ tird --help
tird v0.30.0
        A tool for encrypting files and hiding encrypted data.
        Homepage: https://github.com/hakavlad/tird

Usage:
    tird [--unsafe-debug] [--unsafe-decrypt]

    Start without options for normal usage.

Options:
    --help            print this help message and exit
    --unsafe-debug    enable unsafe debug mode
    --unsafe-decrypt  release plaintext even if MAC verification
                      failed (dangerous)

Examples:
    $ tird
    $ tird --unsafe-debug
```

## Unsafe Debug Mode

> \[!WARNING]
> Debug mode is not intended for use in production!

Start `tird` with the `--unsafe-debug` option to look under the hood while the program is running.

Enabling debug mode additionally shows:

- File operations:
  - Opening and closing of file descriptors.
  - Real paths to opened files.
  - Movement of file pointers.
- Byte strings related to cryptographic operations: salts, passphrases, digests, keys, nonces, and tags.
- Some other information, including various sizes.

## Unsafe Decrypt Mode

> \[!WARNING]
> In this mode the returned plaintext may have been modified or substituted by an attacker!

In unsafe decrypt mode `tird` will release plaintext even if authentication fails. Use only if you prioritize availability over integrity, when you cannot successfully decrypt a cryptoblob in normal mode.

## Tradeoffs and Limitations

- `tird` does not support:
  - [Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography).
  - File compression.
  - ASCII armored output.
  - [Reed–Solomon error correction](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction).
  - Splitting the output into chunks.
  - Use of [standard streams](https://en.wikipedia.org/wiki/Standard_streams) for processing files (not intended for automated scripts).
  - Low-level block device reading and writing on MS Windows. As a result, these devices cannot be used as keyfiles, cannot be overwritten, and cannot be encrypted or embedded.
- `tird` does not provide:
  - A graphical user interface.
  - A password generator.
- `tird` cannot handle (encrypt/embed) more than one file in one pass. Encryption of directories and multiple files is not supported.
- `tird` does not sanitize filesystem metadata (atime, mtime, ctime).
- `tird`'s encryption speed is not very high (up to 430 MiB/s in my tests).

## Warnings

> Crypto can help, but it won’t save you from misuse, vulnerabilities, social engineering, or physical threats.

<i>— <a href="https://loup-vaillant.fr/articles/rolling-your-own-crypto">Loup Vaillant</a></i>

<img src="https://i.imgur.com/g84qgw8.jpeg" width="600" alt="DANGER MINES">

- ⚠️ The author does not have a background in cryptography.
- ⚠️ The code has no automated test coverage.
- ⚠️ `tird` has not been independently security audited by humans.
- ⚠️ `tird` is ineffective in a compromised environment; executing it in such cases may cause disastrous data leaks.
- ⚠️ `tird` is unlikely to be effective when used with short and predictable keys.
- ⚠️ `tird` does not erase its sensitive data from memory after use; keys may persist in memory after program exit.
- ⚠️ Sensitive data may leak into swap space.
- ⚠️ Filesystem timestamps are not sanitized — may leak operational metadata.
- ⚠️ `tird` does not sort digests of keyfiles and passphrases in constant-time.
- ⚠️ Overwriting file contents does not guarantee secure destruction of data on the media.
- ⚠️ You cannot prove to an adversary that your random data does not contain encrypted information.
- ⚠️ `tird` protects data, not the user; it cannot prevent torture if you are under suspicion.
- ⚠️ Key derivation consumes 1 GiB RAM, which may lead to performance issues or crashes on low-memory systems.
- ⚠️ Integrity/authenticity over availability — altering even a single byte of a cryptoblob prevents decryption.
- ⚠️ Development is not complete, and there may be backward compatibility issues.

## LLM reports

<img src="https://i.imgur.com/Ab8rSlc.jpeg" width="200" alt="">

- [Tird Code Security Audit Report (v0.19.0)](https://gemini.google.com/share/6390743bb873); Target: [d016bd5](https://github.com/hakavlad/tird/tree/d016bd51571cd24ea0b21b8959dc01c4e7a69bee); Date: April 13, 2025; Auditor: Gemini 2.5 Pro (experimental)
- [Security Audit Report: tird.py (v0.19.0)](https://gemini.google.com/share/82c80109c0c9); Target: [105f2dd](https://github.com/hakavlad/tird/tree/105f2ddbcace2802e2372f25c7aaae028ae4b357); Date: April 24, 2025; Auditor: Gemini 2.5 Pro (experimental)
- [Tird Security Review (v0.20.0)](https://gemini.google.com/share/754c591bab98); Target: [ba504f9](https://github.com/hakavlad/tird/tree/ba504f92f5f40a8557ab4e1e5c6cc7fbc689a0cd); Date: May 4, 2025; Auditor: Gemini 2.5 Pro (experimental)

## Requirements

- Python >= 3.9.2
- [cryptography](https://pypi.org/project/cryptography/) >= 2.1 (provides `HKDF` and a fast `ChaCha20` implementation)
- [PyNaCl](https://pypi.org/project/PyNaCl/) >= 1.2.0 (provides fast implementations of `Argon2` and `BLAKE2`)
- [colorama](https://pypi.org/project/colorama/) >= 0.4.6 (Windows-specific)

## Documentation

- 📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">`tird`(1) man&nbsp;page</a>
- 📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a>
- 📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a>
- 📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial/Demo</a>
- ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ/Rationale</a>
- 📥&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INSTALLATION.md">Installation</a>

## TODO

Improve the documentation.

## Feedback

Please feel free to ask questions, leave feedback, or provide critiques in the [Discussions](https://github.com/hakavlad/tird/discussions) section.
