
<h4 align="left">
  📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">man&nbsp;page</a>&nbsp;&nbsp;&nbsp;
  📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a>&nbsp;&nbsp;&nbsp;
  📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a>&nbsp;&nbsp;&nbsp;
  📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial</a>&nbsp;&nbsp;&nbsp;
  ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ</a>&nbsp;&nbsp;&nbsp;
  📥&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INSTALLATION.md">Installation</a>
</h4>

---

# Basics: Start, Exit, Info, Debug

## Start

Start the app without options, then simply answer the questions provided. An endless cycle of actions will follow until you interrupt it.

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

## Exit

Select action `0` from the menu, or press `Ctrl+C`.

Exit by selecting an action:

```
                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. Select an option [0-9]: 0
    I: action #0:
        exit application
```

Exit by pressing `Ctrl+C`:

```
                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. Select an option [0-9]: ^C
    I: caught signal 2
```

## Info & Warnings

To get the application version, a brief description, a link to the homepage, and a list of warnings, select action `1`.

```
                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. Select an option [0-9]: 1
    I: action #1:
        display info and warnings
    I: tird v0.20.0
        A file encryption tool focused on
            minimizing metadata and hiding encrypted data.
        Homepage: https://github.com/hakavlad/tird
    W: The author does not have a background in cryptography.
    W: The code has no automated test coverage.
    W: tird has not been independently security audited by humans.
    W: tird is ineffective in a compromised environment; executing it in such cases may cause disastrous data leaks.
    W: tird is unlikely to be effective when used with short and predictable keys.
    W: tird does not erase its sensitive data from memory after use.
    W: Sensitive data may leak into swap space.
    W: tird always releases unverified plaintext, violating the Cryptographic Doom Principle; decrypted output is untrusted until the MAC tag is verified.
    W: Padding contents are never authenticated; authentication only applies to the ciphertext, salts, and certain sizes.
    W: Padding sizes depend on secret values.
    W: tird does not sort digests of keyfiles and passphrases in constant-time.
    W: Overwriting file contents does not guarantee secure destruction of data on the media.
    W: You cannot prove to an adversary that your random data does not contain encrypted information.
    W: tird protects data, not the user; it cannot prevent torture if you are under suspicion.
    W: Key derivation consumes 1 GiB RAM, which may lead to performance issues or crashes on low-memory systems.
    W: Development is not complete, and there may be backward compatibility issues.
```

In debug mode, the version of Python being used will also be displayed.

## Debug

> \[!WARNING]
> Debug mode is not intended for use in production!

Start the app with the `--debug` option to look under the hood:

```
$ tird --debug
    W: debug mode enabled! Sensitive data will be exposed!

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
