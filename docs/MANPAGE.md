% tird(1) | General Commands Manual

# NAME

tird - encrypt files and hide encrypted data

# SYNOPSIS

**tird** \[**\--debug**\]

# DESCRIPTION

**tird** /tɪrd/ *(an acronym for "this is random data")* is a file encryption tool focused on minimizing metadata and hiding encrypted data.

With **tird**, you can:

1. Create files filled with random data to use as containers or keyfiles.
2. Overwrite the contents of devices and regular files with random data. This can be used to prepare containers and to destroy residual data.
3. Encrypt file contents and comments. The encrypted file format (called cryptoblob) is a padded uniform random blob (PURB): it looks like random data and has a randomized size. This reduces metadata leakage from file format and length, and also allows cryptoblobs to be hidden among random data. You can use keyfiles and passphrases at your choice.
4. Create steganographic (hidden, undetectable) user-driven file systems inside container files and devices. Unlike VeraCrypt and Shufflecake containers, **tird** containers do not contain headers at all; the user specifies the location of the data in the container and is responsible for ensuring that this location is separated from the container.
5. Prevent or resist coercive attacks (keywords: key disclosure law, rubber-hose cryptanalysis, xkcd 538). **tird** provides some forms of plausible deniability out of the box, even if you encrypt files without hiding them in containers.

# COMMAND-LINE OPTIONS

#### \--debug

enable debug mode

# USAGE

You don't need to memorize command-line options to use **tird**. This tool features a prompt-based CLI: simply start it, select a menu option, and answer the questions that will follow.

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
A0. Select an option [0-9]:
```

A detailed description of these options with examples can be found here: <https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md>.

# INPUT OPTIONS

There are 5 groups of input options: A (Action), C (Custom), D (Data), K (Keys), P (Proceed). They are numbered for ease of description.

```
+——————————————————————————+————————————————————————+
| A0. Select an option     | A. Select an action    |
+——————————————————————————+————————————————————————+
| C0. Use custom settings? |                        |
| C1. Time cost            | C. Set custom settings |
| C2. Max padding size     |                        |
| C3. Set fake MAC tag?    |                        |
+——————————————————————————+————————————————————————+
| D1. Input file path      |                        |
| D2. Comments             | D. Enter data,         |
| D3. Output file path     |    data location,      |
| D4. Output file size     |    data size           |
| D5. Start position       |                        |
| D6. End position         |                        |
+——————————————————————————+————————————————————————+
| K1. Keyfile path         | K. Specify input       |
| K2. Passphrase           |    keying material     |
+——————————————————————————+————————————————————————+
| P0. Proceed?             | P. Confirm to continue |
+——————————————————————————+————————————————————————+
```

# GOALS

- **File Protection:** Ensuring protection for individual files, including:
  - Symmetric encryption and authentication.
  - Minimizing metadata leakage.
  - Preventing access to data in cases of user coercion.
  - Plausible deniability of payload existence.
  - Hiding encrypted data.
- **Stable Format:** Ensuring a stable encryption format with no cryptographic agility for long-term data storage.
- **Simplicity:** Ensuring simplicity and avoiding feature creep: refusal to implement features that are not directly related to primary security goals.

# PAYLOAD

The payload that will be encrypted during cryptoblob creation consists of:

- **Contents of one file:** This may be a regular file or a block device (an entire disk or partition). Maximum size: 16 exbibytes minus 832 bytes.
- **Comments (optional):** An arbitrary string of up to 512 bytes. Decrypted comments will be displayed during decryption.

Specifying the payload in the UI looks as follows:

```
D1. File to encrypt: list.txt
    I: path: 'list.txt'; size: 6,493 B (6.3 KiB)
D2. Comments (optional, up to 512 B): Epstein client list, txt
    I: comments will be shown as ['Epstein client list, txt']
```

# INPUT KEYING MATERIAL

**tird** provides the option to use passphrases and the contents of keyfiles to derive one-time keys.

- **Keyfiles:** Specify none, one, or multiple keyfile paths. A keyfile path may be:
  - A regular file. The contents of the keyfile will be hashed, and its digest will be used for further key stretching and key derivation.
  - A block device. Handled the same as a regular keyfile: contents will be hashed.
  - A directory. All files within the directory will be hashed and used as keyfiles.
- **Passphrases:** Specify none, one, or multiple passphrases of up to 2048 bytes.

The order of input does not matter.

Specifying IKM in the UI looks as follows:

```
K1. Keyfile path (optional): foo
    I: path: 'foo'; size: 1 B
    I: reading and hashing contents of 'foo'
    I: keyfile accepted
K1. Keyfile path (optional):
K2. Passphrase (optional):
K2. Confirm passphrase:
    I: passphrase accepted
```

# HIDDEN FILE SYSTEM AND CONTAINER FORMAT

You can encrypt files and embed cryptoblobs into containers starting at arbitrary positions. After writing the cryptoblob, you will need to remember its location in the container (the starting and ending positions), which will be used later to extract the cryptoblobs. In this way, you can create a **hidden, headerless, user-driven** file system inside a container:

- It is **hidden** because it is impossible to distinguish between random container data and cryptoblob data, as well as to determine the location of written cryptoblobs without knowing the positions and keys.
- It is **headerless** because containers do not contain any headers; all data about cryptoblob locations must be stored separately by the user.
- The starting position of the cryptoblob in the container is **user-defined**, and the **user must** store both the starting and ending positions separately from the container. This is why it is called a **user-driven file system**.

Any file, disk, or partition larger than the minimum cryptoblob size (831 B) can be a valid container. Cryptoblobs can be embedded into any area.

**Examples of valid containers include:**

1. Specially generated files with random data.
2. **tird** cryptoblobs, as they contain pockets — unauthenticated padding of random data — by default, which can be used to embed smaller cryptoblobs.
3. Disk areas containing random data. For example, you can overwrite a disk with random data, format it in FAT32 or exFAT, and use a large portion of the disk, leaving a few dozen MB from the beginning. The disk will appear empty unless you add some files to it.
4. LUKS encrypted volumes.
5. VeraCrypt containers, even those that already contain hidden volumes.

**Example of container structure:**

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

# TIME-LOCK ENCRYPTION

Time-lock encryption (TLE) can be used to prevent an adversary from quickly accessing plaintexts in the event of an IKM compromise (in case of user coercion, for example). In our implementation, it is actually a PoW-based time-lock key derivation. The "Time cost" input option specifies the number of Argon2 passes. If you specify a sufficiently high number of passes, it will take a significant amount of time to perform them. However, an attacker will require the same amount of time when using similar hardware. The execution of Argon2 cannot be accelerated through parallelization, so it is expected that the time spent by an attacker will be approximately the same as that spent by the defender.

This TLE implementation works offline, unlike **tlock**.

Use custom options and set the desired "Time cost" value:

```
C0. Use custom settings? (Y/N, default=N): y
    I: use custom settings: True
    W: decryption will require the same [C1] and [C2] values!
C1. Time cost (default=4): 1000000
    I: time cost: 1,000,000
```

**Plausible TLE:** The adversary does not know the actual value of the time cost, so you can plausibly misrepresent the number of passes. The adversary cannot refute your claim until they attempt to decrypt the cryptoblob using the specified time cost value.

# DEBUG MODE

**WARNING:** Debug mode is not intended for use in production!

Start **tird** with the option **\--debug** to look under the hood while the program is running.

Enabling debug mode additionally shows:

- File operations:
  - Opening and closing of file descriptors.
  - Real paths to opened files.
  - Movement of file pointers.
- Byte strings related to cryptographic operations: salts, passphrases, digests, keys, nonces, and tags.
- Some other information, including various sizes.

# TRADEOFFS AND LIMITATIONS

- **tird** does not support:
  - Public-key cryptography.
  - File compression.
  - ASCII armored output.
  - Reed–Solomon error correction.
  - Splitting the output into chunks.
  - Use of standard streams for processing files (not intended for automated scripts).
  - Low-level block device reading and writing on MS Windows. As a result, these devices cannot be used as keyfiles, cannot be overwritten, and cannot be encrypted or embedded.
- **tird** does not provide:
  - A graphical user interface.
  - A password generator.
- **tird** cannot handle (encrypt/embed) more than one file in one pass. Encryption of directories and multiple files is not supported.
- **tird** does not fake file access, modification, and creation timestamps (atime, mtime, ctime).
- **tird**'s encryption speed is not very high (up to 420 MiB/s in my tests).

# WARNINGS

- The author does not have a background in cryptography.
- The code has no automated test coverage.
- **tird** has not been independently security audited by humans.
- **tird** is ineffective in a compromised environment; executing it in such cases may cause disastrous data leaks.
- **tird** is unlikely to be effective when used with short and predictable keys.
- **tird** does not erase its sensitive data from memory after use.
- Sensitive data may leak into swap space.
- **tird** always releases unverified plaintext, violating the Cryptographic Doom Principle; decrypted output is untrusted until the MAC tag is verified.
- Padding contents are never authenticated; authentication only applies to the ciphertext, salts, and certain sizes.
- Padding sizes depend on secret values.
- **tird** does not sort digests of keyfiles and passphrases in constant-time.
- Overwriting file contents does not guarantee secure destruction of data on the media.
- You cannot prove to an adversary that your random data does not contain encrypted information.
- **tird** protects data, not the user; it cannot prevent torture if you are under suspicion.
- Key derivation consumes 1 GiB RAM, which may lead to performance issues or crashes on low-memory systems.
- Development is not complete, and there may be backward compatibility issues.

# REQUIREMENTS

- Python >= 3.9.2
- cryptography >= 2.1
- PyNaCl >= 1.2.0
- colorama >= 0.4.6 (Windows-specific)

# TUTORAL

Step-by-step guides and examples can be found here: <https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md>.

# SPECIFICATION

See <https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md>.

# REPORTING BUGS

Please report bugs at <https://github.com/hakavlad/tird/issues>.

# FEEDBACK

Please feel free to ask questions, leave feedback, or provide critiques in the Discussions <https://github.com/hakavlad/tird/discussions> section.

# AUTHOR

Alexey Avramov <hakavlad@gmail.com>

# LICENSE

This project is licensed under the terms of the BSD Zero Clause License (0BSD):

```
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

# HOMEPAGE

Homepage is <https://github.com/hakavlad/tird>.
