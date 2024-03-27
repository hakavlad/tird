% tird(1) | General Commands Manual

# NAME

tird - write random bytes, encrypt file contents, and hide encrypted data

# SYNOPSIS

**tird** \[**-d** | **--debug**\]

# DESCRIPTION

**tird** *(an acronym for "this is random data")* is a tool for writing random bytes, encrypting file contents, and hiding encrypted data.

**tird** can create files with random data, overwrite file contents with random data, encrypt file contents and comments, hide encrypted data among random data, minimize metadata leakage, and can provide some forms of plausible deniability.

# COMMAND-LINE OPTIONS

#### -d, --debug

print debug messages

# GOALS

- Providing protection for individual files, including:
  - symmetric encryption;
  - reducing metadata leakage;
  - hiding encrypted data;
  - plausible deniability.
- Providing a stable encryption format with no cryptographic agility for long-term data storage.
- Simplicity and no feature creep: refusal to implement features that are not directly related to primary security goals.

# USAGE

You don't need to remember command line options to use **tird**.

Just start **tird**, select a menu option, and then answer the questions that **tird** will ask:

```
$ tird
```

# DEBUG

Start **tird** with the option **--debug** or **-d** to look under the hood while the program is running:

```
$ tird -d
```

# TRADEOFFS AND LIMITATIONS

- **tird** does not support public-key cryptography.
- **tird** does not support file compression.
- **tird** does not support ASCII armored output.
- **tird** does not support Reed–Solomon error correction.
- **tird** does not support splitting the output into chunks.
- **tird** does not support low-level device reading and writing when used on MS Windows (devices cannot be used as keyfiles, cannot be overwritten, cannot be encrypted or hidden).
- **tird** does not provide a graphical user interface.
- **tird** does not provide a password generator.
- **tird** does not wipe sensitive data from the heap.
- **tird** can only encrypt one file per iteration. Encryption of directories and multiple files is not supported.
- **tird** does not fake file timestamps (atime, mtime, ctime).
- **tird** encryption speed is not very fast: up to 180 MiB/s (in my tests).

# WARNINGS

- The author is not a cryptographer.
- **tird** has not been independently audited.
- **tird** probably won't help much when used in a compromised environment.
- **tird** probably won't help much when used with short and predictable keys.
- Keys may leak into the swap space.
- **tird** always releases unverified plaintext (violates The Cryptographic Doom Principle).
- **tird** does not sort digests of keyfiles and passphrases in constant time.
- Development is ongoing, there may be backward compatibility issues in the future.

# REQUIREMENTS

- Python >= 3.6
- PyNaCl >= 1.2.0
- PyCryptodomex >= 3.6.2

# REPORTING BUGS

Please report bugs at <https://github.com/hakavlad/tird/issues>.

# FEEDBACK

Feel free to post any questions, feedback or criticisms at <https://github.com/hakavlad/tird/discussions>.

# AUTHOR

Alexey Avramov <hakavlad@gmail.com>

# COPYRIGHT

This project is licensed under the terms of the Creative Commons Zero v1.0 Universal License (Public Domain Dedication).

# HOMEPAGE

Homepage is <https://github.com/hakavlad/tird>.
