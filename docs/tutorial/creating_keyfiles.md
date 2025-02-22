
# Creating Keyfiles with Random Data

Easy! Just answer 3 questions:

```
[00] Select an option [0-9]:
[23] Output file:
[24] Output file size in bytes:
```

1. Select option (action) 8:

```
                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
[00] Select an option [0-9]: 8
I: action #8:
    create file of specified size with random data
```

2. Enter output path:

```
[23] Output file: key
I: new file 'key' created
```

3. Enter size in bytes. 32 or larger may be OK.

```
[24] Output file size in bytes: 32
I: size: 32 B
```

Then action will be completed:

```
I: writing random data
I: written 100.0%; 32 B in 0.0s; avg 0.4 MiB/s
I: action completed
```

Keep keyfiles secret!

