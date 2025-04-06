
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

> [!IMPORTANT]
> Keyfiles must be kept secret!

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
    I: new empty file 'key' created
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
    I: written 100.0%; 32 B in 0.0s; avg 0.9 MiB/s
    I: action completed
```

<details>
  <summary>&nbsp;<b>Show the full dialog</b></summary>

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
D3. Output file: key
    I: new empty file 'key' created
D4. Output file size in bytes: 32
    I: size: 32 B
    I: writing random data
    I: written 100.0%; 32 B in 0.0s; avg 0.9 MiB/s
    I: action completed
```

</details>

<details>
  <summary>&nbsp;<b>Show the full dialog with debug mode enabled</b></summary>

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
D3. Output file: key
    D: real path: '/tmpfs/test/key'
    D: opening file 'key' in mode 'wb'
    D: opened file object: <_io.BufferedWriter name='key'>
    I: new empty file 'key' created
D4. Output file size in bytes: 32
    I: size: 32 B
    I: writing random data
    D: written 32 B to <_io.BufferedWriter name='key'>; position moved from 0 to 32
    I: written 100.0%; 32 B in 0.0s; avg 0.6 MiB/s
    D: closing <_io.BufferedWriter name='key'>
    D: <_io.BufferedWriter name='key'> closed
    I: action completed
```

</details>
