
<h4 align="left">
  🏠&nbsp;<a href="https://github.com/hakavlad/tird">Homepage</a> &nbsp;
  📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">man&nbsp;page</a> &nbsp;
  📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a> &nbsp;
  📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a> &nbsp;
  📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial</a> &nbsp;
  ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ</a>
</h4>

---

# Creating Keyfiles with Random Data

Answer 3 questions to create a keyfile:

```
A0. Select an option [0-9]:
D3. Output file:
D4. Output file size in bytes:
```

#### 1. Select option (action) 8

```
                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. Select an option [0-9]: 8
    I: action #8:
        create file of specified size with random data
```

#### 2. Enter output path

```
D3. Output file: key
    I: new file 'key' created
```

#### 3. Enter size in bytes

32 or larger may be OK.

```
D4. Output file size in bytes: 32
    I: size: 32 B
```

#### Then action will be completed

```
    I: writing random data
    I: written 100.0%; 32 B in 0.0s; avg 0.4 MiB/s
    I: action completed
```

**Keep keyfiles secret!**
