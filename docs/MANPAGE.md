% tird(1) | General Commands Manual

# NAME

tird - encrypt file contents and hide encrypted data

# SYNOPSIS

**tird** \[**-d** | **--debug**\]

# DESCRIPTION

**tird** *(an acronym for "this is random data")* is a tool for encrypting file contents and hiding encrypted data.

**tird** can provide protection for individual files, including:

- symmetric encryption;
- reducing metadata leakage;
- hiding encrypted data;
- plausible deniability.

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
- No feature creep: refusal to implement features that are not directly related to primary security goals.

# USAGE

Just run the script, select the option you want and then answer the questions.

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
