<h4>
  🏠&nbsp;<a href="https://github.com/hakavlad/tird">Home</a>&nbsp;&nbsp;&nbsp;
  📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a>&nbsp;&nbsp;&nbsp;
  📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">man&nbsp;page</a>&nbsp;&nbsp;&nbsp;
  📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a>&nbsp;&nbsp;&nbsp;
  📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial</a>&nbsp;&nbsp;&nbsp;
  ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ</a>&nbsp;&nbsp;&nbsp;
  📥&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INSTALLATION.md">Install</a>
</h4>

---

# Installation

See also:

- [Warnings](https://github.com/hakavlad/tird#warnings)
- [Requirements](https://github.com/hakavlad/tird#requirements)

---

## Installation from PyPI

Install `python3` and `python3-pip` (or `python-pip`), then run

```bash
$ pip install --user tird
```

The drawback of this installation method is that the package will only be available to the user who installed it and won't be accessible when using `sudo`.

---

## Standalone Executables

- Standalone executables (made with [PyInstaller](https://pyinstaller.org/en/stable/)) are available (see [Releases](https://github.com/hakavlad/tird/releases)) for Windows and Linux (amd64).
- Please use at your own risk.

![tird.exe](https://i.imgur.com/A7iaQhW.jpeg)

<details>
  <summary>&nbsp;<b>How to Verify Signatures</b></summary>

Use [Minisign](https://jedisct1.github.io/minisign/) to verify signatures. You can find my public key [here](https://github.com/hakavlad/hakavlad).

For example:

```bash
$ minisign -Vm  tird-v0.30.0-linux-amd64.zip -P RWQLYkPbRQ8b56zEe8QdbjLFqC9UrjOaYxW5JxwsWV7v0ct/F/XfJlel
```

This requires the signature `tird-v0.30.0-linux-amd64.zip.minisig` to be present in the same directory.
</details>

---

## Building and Installing the Package on Debian-based Linux Distros

It's easy to build a deb package for Debian and Ubuntu-based distros with the latest git snapshot.

**1. Install the build dependencies:**

```bash
$ sudo apt install make fakeroot
```

**2. Clone the repository and enter the directory:**

```bash
$ git clone https://github.com/hakavlad/tird.git && cd tird
```

**3. Build the package:**

```bash
$ make build-deb
```

**4. Install or reinstall the package:**

```bash
$ sudo make install-deb
```

---

## Installing on Linux with `make install`

- This is a universal installation method for GNU/Linux distributions that makes the script available to run with root privileges.
- You will need the `make` utility and two dependencies of `tird` itself.
- You should install the dependencies, clone the repository (or download a release), change into the project directory, and run `sudo make install`.
- The script and its man page will be installed in `/usr/local`.

### Install Dependencies

For **Debian-based (apt)**:

```bash
$ sudo apt install make python3-cryptography python3-nacl
```

For **Arch Linux (pacman)**:

```bash
$ sudo pacman -S make python-cryptography python-pynacl
```

For **Fedora / RHEL-based (dnf)**:

```bash
$ sudo dnf install make python3-cryptography python3-pynacl
```

For **openSUSE (zypper)**:

```bash
$ sudo zypper install make python3-cryptography python3-PyNaCl
```

### Clone and Install

Latest stable release (recommended):

```bash
$ git clone --branch v0.30.0 --depth 1 https://github.com/hakavlad/tird.git && cd tird
$ sudo make install
```

From main branch:

```bash
$ git clone https://github.com/hakavlad/tird.git && cd tird
$ sudo make install
```
