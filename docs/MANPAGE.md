% tird(1) | General Commands Manual

# NAME

tird - encrypt files and hide encrypted data

# SYNOPSIS

**tird** \[**-d** | **--debug**\]

# DESCRIPTION

**tird** *(an acronym for "this is random data")* is a tool for encrypting files and hiding encrypted data.

With **tird**, you can:

1. Create files filled with random data to use as containers or keyfiles.
2. Overwrite the contents of devices and regular files with random data. This can be used to prepare containers and to destroy residual data.
3. Encrypt file contents and comments with modern cryptographic primitives. The encrypted file format (cryptoblob) is a padded uniform random blob (PURB): it looks like random data and has a randomized size. This reduces metadata leakage through file format and length, and also allows cryptoblobs to be hidden among random data. You can use keyfiles and passphrases at your choice to enhance security.
4. Create steganographic (hidden, undetectable) user-driven file systems inside container files and devices. Unlike VeraCrypt and Shufflecake containers, **tird** containers do not contain headers at all; the user specifies the location of the data in the container and is responsible for ensuring that this location is separated from the container.
5. Resist coercive attacks (keywords: key disclosure law, rubber-hose cryptanalysis, xkcd 538). **tird** provides some forms of plausible deniability out of the box, even if you encrypt files without hiding them in containers.

# COMMAND-LINE OPTIONS

#### -d, --debug

print debug messages

# INPUT OPTIONS

**tird** has the following input options:

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

For a detailed description of these options, see <https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md>.

# GOALS

- **File Protection:** Ensuring protection for individual files, including:
  - Symmetric encryption and authentication.
  - Minimizing metadata leakage.
  - Preventing access to data in cases of user coercion.
  - Plausible deniability of payload existence.
  - Hiding encrypted data.
- **Stable Format:** Ensuring a stable encryption format with no cryptographic agility for long-term data storage.
- **Simplicity:** Ensuring simplicity and avoiding feature creep: refusal to implement features that are not directly related to primary security goals.

# USAGE

You don’t need to memorize command-line options to use **tird**.

Just start **tird**, select a menu option, and then answer the questions that **tird** will ask:

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

# HIDDEN USER-DRIVEN FILE SYSTEM AND CONTAINER FORMAT

You can encrypt files and embed cryptoblobs into containers starting at arbitrary positions. After writing the cryptoblob, you will need to remember its location in the container (the starting and ending positions), which will be used later to extract the cryptoblobs. In this way, you can create a **hidden, headerless, user-driven** file system inside a container:

- It is **hidden** because it is impossible to distinguish between random container data and cryptoblob data, as well as to determine the location of written cryptoblobs without knowing the positions and keys.
- It is **headerless** because containers do not contain any headers; all data about cryptoblob locations must be stored separately by the user.
- The starting position of the cryptoblob in the container is **user-defined**, and the **user must** store both the starting and ending positions separately from the container. This is why this "file system" is called a **user-driven file system**.

Any file, disk, or partition larger than ~1 KiB can be a valid container. Cryptoblobs can be embedded into any area.

Examples of valid containers include:

1. Specially generated files with random data.
2. Disk areas containing random data. For example, you can overwrite a disk with random data, format it in FAT32 or exFAT, and use a large portion of the disk, leaving a few dozen MB from the beginning. The disk will appear empty unless you add some files to it.
3. **tird** cryptoblobs, as they contain unauthenticated padding of random data by default, which can be used to embed smaller cryptoblobs.
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

# DEBUG MODE

Start **tird** with the option **--debug** or **-d** to look under the hood while the program is running:

```
$ tird -d
```

Enabling debug messages additionally shows:

- Opening and closing file descriptors.
- Real paths to opened files.
- Moving file pointers using the seek() method.
- Salts, passphrases, digests, keys, nonces, tags.
- Some other information.

# TRADEOFFS AND LIMITATIONS

- **tird** does not support public-key cryptography.
- **tird** does not support file compression.
- **tird** does not support ASCII armored output.
- **tird** does not support Reed–Solomon error correction.
- **tird** does not support splitting the output into chunks.
- **tird** does not support the use of standard streams for payload transmission.
- **tird** does not support low-level device reading and writing when used on MS Windows (devices cannot be used as keyfiles, cannot be overwritten, and cannot be encrypted or hidden).
- **tird** does not provide a graphical user interface.
- **tird** does not provide a password generator.
- **tird** cannot handle (encrypt/embed) more than one file in one pass. Encryption of directories and multiple files is not supported.
- **tird** does not fake file access, modification, and creation timestamps (atime, mtime, ctime).
- **tird**'s encryption speed is not very fast (up to 180 MiB/s in my tests).

# WARNINGS

- The author does not have a background in cryptography.
- **tird** has not been independently audited.
- **tird** is unlikely to be effective when used in a compromised environment.
- **tird** is unlikely to be effective when used with short and predictable keys.
- Sensitive data may leak into swap space.
- **tird** does not erase sensitive data from memory after use.
- **tird** always releases unverified plaintext, violating The Cryptographic Doom Principle.
- Padding is not used to create a MAC tag (only ciphertext and salt will be authenticated).
- **tird** does not sort digests of keyfiles and passphrases in constant-time.
- Overwriting file contents does not guarantee secure destruction of the data on the media.
- You cannot prove to an adversary that your random-looking data does not contain encrypted data.
- Development is not complete; there may be backward compatibility issues in the future.

# REQUIREMENTS

- Python >= 3.9
- PyCryptodomex >= 3.6.2
- PyNaCl >= 1.2.0

# TUTORAL

Step-by-step guides and examples you can find here <https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md>.

# SPECIFICATION

See <https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md>.

# REPORTING BUGS

Please report bugs at <https://github.com/hakavlad/tird/issues>.

# FEEDBACK

Please feel free to ask questions, leave feedback, or provide critiques at <https://github.com/hakavlad/tird/discussions>.

# AUTHOR

Alexey Avramov <hakavlad@gmail.com>

# COPYRIGHT

This project is licensed under the terms of the Creative Commons Zero v1.0 Universal License (Public Domain Dedication).

# HOMEPAGE

Homepage is <https://github.com/hakavlad/tird>.
