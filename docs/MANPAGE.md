% tird(1) | General Commands Manual

# NAME

tird - encrypt files and hide encrypted data

# SYNOPSIS

**tird** \[**-d** | **--debug**\]

# DESCRIPTION

**tird** *(an acronym for "this is random data")* is a tool for encrypting files and hiding encrypted data.

Using **tird** you can:

1. Create files with random data. Use them as containers or keyfiles.
2. Overwrite the contents of devices and regular files with random data. This can be used to prepare containers and to destroy residual data.
3. Encrypt file contents and comments with modern cryptographic primitives. The encrypted file format (cryptoblob) is padded uniform random blob (PURB): it looks like random data and has randomized size. This reduces metadata leakage through file format and length, and also allows cryptoblobs to be hidden among random data.
4. Create steganographic (hidden, undetectable) user-driven file systems inside container files and devices. Unlike VeraCrypt and Shufflecake containers, **tird** containers do not contain headers at all: the user specifies the location of the data in the container and is responsible for ensuring that this location is separated from the container.
5. Resist coercive attacks (keywords: key disclosure law, rubber-hose cryptanalysis, xkcd 538). **tird** provides some forms of plausible deniability out of the box even if you encrypt files without hiding them in containers.

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
[08] Start position
[09] End position
[10] Comments
[11] Keyfile path
[12] Passphrase
[13] Proceed?
[14] Output file size
```

For a detailed description of these options, see <https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md>.

# GOALS

- Providing protection for individual files, including:
  - symmetric encryption and authentication;
  - minimizing metadata leakage;
  - preventing access to data in case of user coercion;
  - plausible deniability of payload existence;
  - hiding encrypted data.
- Providing a stable encryption format with no cryptographic agility for long-term data storage.
- Simplicity and no feature creep: refusal to implement features that are not directly related to primary security goals.

# USAGE

You don't need to remember command line options to use **tird**.

Just start **tird**, select a menu option, and then answer the questions that **tird** will ask:

```
$ tird
```

# HIDDEN USER-DRIVEN FILE SYSTEM AND CONTAINER FILE FORMAT

You can encrypt files and write cryptoblobs over containers starting with arbitary positions. After finishing writing the cryptoblob, you will be asked to remember the location of the cryptoblob in the container (positions of the beginning and end of the cryptoblob), which can be used in the future to extract the cryptoblob. In this way, you can create a hidden user-driven file system inside a container.

It is hidden because it is impossible to distinguish between random container data and random cryptoblob data, and it is impossible to determine the location of written cryptoblobs without knowing the positions and keys.

Containers do not contain any headers, all data about cryptoblob locations must be stored separately by the user.

The location of the start of the cryptoblob in the container is user-defined, and the location of the start and end positions of the cryptoblob must be stored by the user separately from the container. This is why this "file system" is called a user-driven file system.

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

# DEBUG

Start **tird** with the option **--debug** or **-d** to look under the hood while the program is running:

```
$ tird -d
```

Enabling debug messages additionally shows:

- opening and closing file descriptors;
- real paths to opened files;
- moving file pointers using the seek() method;
- salts, passphrases, digests, keys, nonces, tags;
- some other info.

# TRADEOFFS AND LIMITATIONS

- **tird** does not support public-key cryptography.
- **tird** does not support file compression.
- **tird** does not support ASCII armored output.
- **tird** does not support Reed–Solomon error correction.
- **tird** does not support splitting the output into chunks.
- **tird** does not support the use of standard streams for payload transmission.
- **tird** does not support low-level device reading and writing when used on MS Windows (devices cannot be used as keyfiles, cannot be overwritten, cannot be encrypted or hidden).
- **tird** does not provide a graphical user interface.
- **tird** does not provide a password generator.
- **tird** can only encrypt one file per iteration. Encryption of directories and multiple files is not supported.
- **tird** does not fake file timestamps (atime, mtime, ctime).
- **tird** encryption speed is not very fast (up to 180 MiB/s in my tests).

# WARNINGS

- The author is not a cryptographer.
- **tird** has not been independently audited.
- **tird** probably won't help much when used in a compromised environment.
- **tird** probably won't help much when used with short and predictable keys.
- Sensitive data may leak into the swap space.
- **tird** does not erase sensitive data from memory after use.
- **tird** always releases unverified plaintext (violates The Cryptographic Doom Principle).
- Padding is not used to create a MAC tag (only ciphertext and salt will be authenticated).
- **tird** does not sort digests of keyfiles and passphrases in constant-time.
- Overwriting file contents does not mean securely destroying the data on the media.
- Development is not complete, there may be backward compatibility issues in the future.

# REQUIREMENTS

- Python >= 3.9
- PyCryptodomex >= 3.6.2
- PyNaCl >= 1.2.0


# TUTORAL

Step-by-step guides and examples you can see here <https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md>.

# SPECIFICATION

See <https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md>.

# REPORTING BUGS

Please report bugs at <https://github.com/hakavlad/tird/issues>.

# FEEDBACK

Feel free to post any questions, reviews, or criticisms at <https://github.com/hakavlad/tird/discussions>.

# AUTHOR

Alexey Avramov <hakavlad@gmail.com>

# COPYRIGHT

This project is licensed under the terms of the Creative Commons Zero v1.0 Universal License (Public Domain Dedication).

# HOMEPAGE

Homepage is <https://github.com/hakavlad/tird>.
