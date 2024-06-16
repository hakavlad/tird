
# Input options

This page describes `tird` input options.

## Table of contents

- [[01] Select an option](#01-select-an-option)
- [[02] Use custom settings?](#02-use-custom-settings)
- [[03] Argon2 time cost](#03-argon2-time-cost)
- [[04] Max padding size](#04-max-padding-size)
- [[05] Set a fake MAC tag?](#05-set-a-fake-mac-tag)
- [[06] Input file path](#06-input-file-path)
- [[07] Output file path](#07-output-file-path)
- [[08] Start position](#08-start-position)
- [[09] End position](#09-end-position)
- [[10] Comments](#10-comments)
- [[11] Keyfile path](#11-keyfile-path)
- [[12] Passphrase](#12-passphrase)
- [[13] Proceed?](#13-proceed)
- [[14] Output file size](#14-output-file-size)

---

## [01] Select an option

**Function:** `select_action()`

**Data type:** `int`

**Valid values:** from the range `[0; 9]`

**Default value:** (not defined)

### Description

Select an option from the MENU list (select the action to perform).

Enter a number and press Enter.

### List of available actions

#### `  0. Exit  `

Exiting `tird`.

#### `  1. Info & warnings  `

Displaying info and warnings.

#### `  2. Encrypt  `

Encrypt file contents and comments; write the cryptoblob to a new file.

#### `  3. Decrypt  `

Decrypt a file; display the decrypted comments and write the decrypted contents to a new file.

#### `  4. Embed  `

Embed file contents (no encryption): write input file contents over output file contents.

#### `  5. Extract  `

Extract file contents (no decryption) to a new file.

#### `  6. Encrypt & embed  `

Encrypt file contents and comments; write the cryptoblob over a container.

#### `  7. Extract & decrypt  `

Extract and decrypt cryptoblob; display the decrypted comments and write the decrypted contents to a new file.

#### `  8. Create w/ random  `

Create a file of the specified size with random data.

#### `  9. Overwrite w/ random  `

Overwrite file contents with random data.

### Examples

Selecting action 8:
```
$ tird

                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & embed   7. Extract & decrypt
    8. Create w/ random  9. Overwrite w/ random
    ———————————————————————————————————————————
[01] Select an option [0-9]: 8
I: action #8:
    create a file of the specified size with random data
```

Selecting action 2 with debug messages enabled:
```
$ tird -d
W: debug messages enabled!

                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & embed   7. Extract & decrypt
    8. Create w/ random  9. Overwrite w/ random
    ———————————————————————————————————————————
[01] Select an option [0-9]: 2
I: action #2:
    encrypt file contents and comments;
    write the cryptoblob to a new file
```

---

## [02] Use custom settings?

**Used in:** actions `2|3|6|7`

**Function:** `is_custom()`

**Data type:** `bool`

**Valid values:** `Y|y|1|N|n|0`

**Default value:** `False`


### Examples

Context: actions 2, 3, 6, 7 with default value:
```
[02] Use custom settings? (Y/N, default=N):
I: use custom settings: False
```

Context: actions 2, 6:
```
[02] Use custom settings? (Y/N, default=N): y
I: use custom settings: True
W: decryption will require the same custom values!
    [03] Argon2 time cost (default=4): 999999
    [04] Max padding size, % (default=20): 111
    [05] Set a fake MAC tag? (Y/N, default=N):
```

Context: actions 3, 7:
```
[02] Use custom settings? (Y/N, default=N): 1
I: use custom settings: True
    [03] Argon2 time cost (default=4):
    [04] Max padding size, % (default=20): 200
```

Context: actions 2, 6 with default values, with debug messages enabled
```
[02] Use custom settings? (Y/N, default=N):
I: use custom settings: False
D: Argon2 time cost: 4
D: max padding size, %: 20
D: set fake MAC tag: False
```

Context: actions 3, 7 with default values, with debug messages enabled:
```
[02] Use custom settings? (Y/N, default=N):
I: use custom settings: False
D: Argon2 time cost: 4
D: max padding size, %: 20
```

Context: actions 3, 7 with custom settings, with debug messages enabled:
```
[02] Use custom settings? (Y/N, default=N): y
I: use custom settings: True
    [03] Argon2 time cost (default=4):
    [04] Max padding size, % (default=20): 100
D: Argon2 time cost: 4
D: max padding size, %: 100
```

---

## [03] Argon2 time cost

**Used in:** actions `2|3|6|7`

**Function:** `get_argon2_time_cost()`

**Data type:** `int`

**Valid values:** from the range `[1; 4294967295]`

**Default value:** `4`


### Examples

See [[02] Use custom settings?](#02-use-custom-settings)


---

## [04] Max padding size

**Used in:** actions `2|3|6|7`

**Function:** `get_max_pad_size_percent()`

**Data type:** `int`

**Valid values:** `>= 0`

**Default value:** `20`


### Examples

See [[02] Use custom settings?](#02-use-custom-settings)


---

## [05] Set a fake MAC tag?

**Used in:** actions `2|6`

**Function:** `is_fake_mac()`

**Data type:** `bool`

**Valid values:** `Y|y|1|N|n|0`

**Default value:** `False`


### Examples

See [[02] Use custom settings?](#02-use-custom-settings)


---

## [06] Input file path

**Used in:** actions `2|3|4|5|6|7`

**Function:** `get_input_file()`

**Data type:** `str`

**Valid values:** path to existing and readable file

**Default value:** (not defined)


### Examples


Context: action 2:
```
[06] File to encrypt: secret.zip
I: path: "secret.zip"; size: 234026 B, 228.5 KiB
```

Context: action 2 with debug messages enabled:
```
[06] File to encrypt: secret.zip
D: real path: "/tmpfs/test/secret.zip"
D: opening file "secret.zip" in mode "rb"
D: opened file (object): <_io.BufferedReader name='secret.zip'>
I: path: "secret.zip"; size: 234026 B, 228.5 KiB
D: ciphertext_size: 234538
D: min_cryptoblob_size: 234634
D: max_pad: 46906
D: max_cryptoblob_size: 281540
```

Context: action 3:
```
[06] File to decrypt: file.bin
I: path: "file.bin"; size: 23845 B, 23.3 KiB
```


Context: action 3 with debug messages enabled:
```
[06] File to decrypt: file.bin
D: real path: "/tmpfs/test/file.bin"
D: opening file "file.bin" in mode "rb"
D: opened file (object): <_io.BufferedReader name='file.bin'>
I: path: "file.bin"; size: 23845 B, 23.3 KiB
```

Context: action 4:
```
[06] File to embed: file.bin
I: path: "file.bin"; size: 23845 B, 23.3 KiB
```

Context: action 4 with debug messages enabled:
```
[06] File to embed: file.bin
D: real path: "/tmpfs/test/file.bin"
D: opening file "file.bin" in mode "rb"
D: opened file (object): <_io.BufferedReader name='file.bin'>
I: path: "file.bin"; size: 23845 B, 23.3 KiB
```

Context: actions 5, 7:
```
[06] Container: container.bin
I: path: "container.bin"; size: 1000000 B, 976.6 KiB
```

Context: actions 5, 7 with debug messages enabled:
```
[06] Container: container.bin
D: real path: "/tmpfs/test/container.bin"
D: opening file "container.bin" in mode "rb"
D: opened file (object): <_io.BufferedReader name='container.bin'>
I: path: "container.bin"; size: 1000000 B, 976.6 KiB
```

Context: action 6:
```
[06] File to encrypt and embed: secret.zip
I: path: "secret.zip"; size: 234026 B, 228.5 KiB
```

Context: action 6 with debug messages enabled:
```
[06] File to encrypt and embed: secret.zip
D: real path: "/tmpfs/test/secret.zip"
D: opening file "secret.zip" in mode "rb"
D: opened file (object): <_io.BufferedReader name='secret.zip'>
I: path: "secret.zip"; size: 234026 B, 228.5 KiB
D: ciphertext_size: 234538
D: min_cryptoblob_size: 234634
D: max_pad: 46906
D: max_cryptoblob_size: 281540
```

---

## [07] Output file path

**Used in:** actions `2|3|4|5|6|7|8|9`

**Functions:** `get_output_file_new()`, `get_output_file_exist()`

**Data type:** `str`

**Valid values:** path to an existing or non-existent file (depending on context)

**Default value:** (not defined)



### Examples


Context: action 2:
```
[07] Output (encrypted) file: file2.bin
I: new file "file2.bin" has been created
```

Context: action 2 with debug messages enabled:
```
[07] Output (encrypted) file: file3.bin
D: real path: "/tmpfs/test/file3.bin"
D: opening file "file3.bin" in mode "wb"
D: opened file (object): <_io.BufferedWriter name='file3.bin'>
I: new file "file3.bin" has been created
```

Context: actions 3, 7:
```
[07] Output (decrypted) file: file4.bin
I: new file "file4.bin" has been created
```

Context: actions 3, 7 with debug messages enabled:
```
[07] Output (decrypted) file: file5.bin
D: real path: "/tmpfs/test/file5.bin"
D: opening file "file5.bin" in mode "wb"
D: opened file (object): <_io.BufferedWriter name='file5.bin'>
I: new file "file5.bin" has been created
```

Context: actions 4, 6:
```
[07] File to overwrite (container): container.bin
I: path: "container.bin"
I: size: 1000000 B, 976.6 KiB
```

Context: actions 4, 6 with debug messages enabled:
```
[07] File to overwrite (container): container.bin
D: real path: "/tmpfs/test/container.bin"
D: opening file "container.bin" in mode "rb+"
D: opened file (object): <_io.BufferedRandom name='container.bin'>
I: path: "container.bin"
I: size: 1000000 B, 976.6 KiB
```

Context: actions 5, 8:
```
[07] Output file: file6.bin
I: new file "file6.bin" has been created
```

Context: actions 5, 8 with debug messages enabled:
```
[07] Output file: file7.bin
D: real path: "/tmpfs/test/file7.bin"
D: opening file "file7.bin" in mode "wb"
D: opened file (object): <_io.BufferedWriter name='file7.bin'>
I: new file "file7.bin" has been created
```

Context: action 9:
```
[07] File to overwrite: /dev/sdc
I: path: "/dev/sdc"; size: 16357785600 B, 15.2 GiB
```

Context: action 9 with debug messages enabled:
```
[07] File to overwrite: /dev/sdc
D: real path: "/dev/sdc"
D: opening file "/dev/sdc" in mode "rb+"
D: opened file (object): <_io.BufferedRandom name='/dev/sdc'>
I: path: "/dev/sdc"; size: 16357785600 B, 15.2 GiB
```



---


## [08] Start position

**Used in:** actions `4|5|6|7|9`

**Function:** `get_start_pos()`

**Data type:** `int`

**Valid values:** from `0` to file size; depends on the context

**Default value:** not defined for actions `4|5|6|7`, `0` for action `9`


### Examples


Context: action 4:
```
[08] Start position, valid values are [0; 976155]: 1234
I: start position: 1234
I: end position: 25079
```


Context: actions 5, 6, 7:
```
[08] Start position, valid values are [0; 999999]: 1234
I: start position: 1234
```

Context: action 9:
```
[08] Start position, valid values are [0; 16357785600], default=0:
I: start position: 0
```


---

## [09] End position

**Used in:** actions `5|7|9`

**Function:** `get_end_pos()`

**Data type:** `int`

**Valid values:** >= `start_pos` and <= `file_size`

**Default value:** not defined for actions `5|7`, `output_file_size` in action `9`




### Examples


Context: action 5:
```
[09] End position, valid values are [1234; 1000000]: 456788
I: end position: 456788
I: message size to retrieve: 455554 B
```

Context: action 7:
```
[09] End position, valid values are [1842; 1000000]: 56789
I: end position: 56789
```

Context: action 9:
```
[09] End position, valid values are [0; 16357785600], default=16357785600:
I: end position: 16357785600
I: data size to write: 16357785600 B, 15.2 GiB
```



---

## [10] Comments


**Used in:** actions `2|6`

**Function:** `get_pot_comments()`

**Data type:** `str`

**Valid values:** arbitary string

**Default value:** (none)


### Examples


Comments are not specified (by default):
```
[10] Comments (optional, up to 512 B):
I: comments will be shown as: [None]
```


Comments are not specified with debug messages enabled:
```
[10] Comments (optional, up to 512 B):
D: comments: [''], size: 0 B
D: pot_comments: [b'\xb0 F\xfe;~\x0b\xf5\xdf\xe7Xmg\xc6c\x86ml\xad\x90\xdexK\x9fy\x15;c\xec\xf4\x1eL\x91\xc2?`b\x95\xfe\xfd\x9d\xbcb\xd4\xda4Z\xde\x93?=\xcd&\xdc\x83\x97$\xa0!?\x06\xfe^\\\xce\x15U\xa6\xc8\x02z\xa7[k\x9d.\xfe\xea6|\xc1\xeaG\xd8\xe3l\xa4\xf7\xb9\x80*\xc4\x06G\xb3M\xcc\x00\xd1\xd9y\xaf\xf6zh\xf2\x93\x8b\xf4\x95\x07p\xbaWxd\xb2\xfcW\x1cul\xdei\x1e\xdbC\xa5D*n\x93j\x10\xee\x04\xfc\x03&\xc1G\xd0=W}\x84\xe1TZ\xb3\xd3\xc6\x00Sx\xc9\xb5\xa3\xd4+\xc0\x97\xd24\x14\xa5\xa23\xee\xa0T\xd1\xfa\xd3\n\x8f\xc3\x05\xe7\xbe\x1a\x16A\r\xf1\xccH\x82J\xdd\x03\xb4\xe9/\x07\x1cyi\xbd\xd6C\x05`K\xb0\xba\x13\x1a\xd7\xde\x9a\xcb9\xfa\t9s*0\xa4@\x84\xb7\x0e%\x88\x1e\xac\'\x17\xec=\xe2J\xfd\xb9HP\xc82D\x9d&\xd9\xcc\xc2\xb5\x99\xd1uZ=I\xb3~\x92gpl\xf7\x9c_\x0f\xbc\x0e\xc1\xf0\xd4$\xd7;\x86~\x9e\xfdn\x94\xc2|\x93|)\x8a`*+\x1d\x92\xb0\xf5\x16;\xdc\x1c\'\xe6\xcc|\x9b\xe5a>?\x95\n\xb50@\x9fr"k\xfa\x1d\xb3G=?P\xe7\xc0a\xd5\xb6\xa6\xc2p\xe4\xc7\xde@\xbdZt\x9a\xed\x18\xd6\x9eM\x00\xff\xc3/\x9a\x8c(F\xff\xa8\x9d\x86\xe9\x0b\x03\xfek\xc5\x93\xb9\x9f\xfe\xf6B\xde\xb1\x1e\xbb\x01ro\x1c\x08\xaa\x93\xce\xf25f\xaa\n\x8c\x7f|\r\xe7L5\xb6;\xfe\xf6\x10\xc7T\n\xec2f3vE<^\xae\x133\xef\x06\xb4\xde\xdd\xba\xa6\xbc*k\xb6\xda\x82\x90\xb53\xedIp\r\x0b\xb5_\xaf!\xcd%a\x9d\x15\xce\xdb\xe1W2\xbd\x19\xdd\xb8l\x99\xa9\xebGv\xe5\x1c/\xd1!\x8dP\xd9\x99\xde\xf2q?\x17\xe3tk\x99)P|\xc4\t\xdc\x16\xad\xd0\xee\xb0\x9f\xfa\xbaE\xc2\xaf?\x1e[\x9f\xb18\xd4\xcf\x8e\x12^\x95OC\xdbA\xaa\xf0\xeb\xaf\xe0$\x062\x90']
I: comments will be shown as: [None]
```


Short comments (up to 512 bytes):
```
[10] Comments (optional, up to 512 B): zip archive with some secret data
I: comments will be shown as: ['zip archive with some secret data']
```



Short comments (up to 512 bytes) with debug messages enabled:
```
[10] Comments (optional, up to 512 B): zip archive with some secret data
D: comments: ['zip archive with some secret data'], size: 33 B
D: pot_comments: [b'zip archive with some secret data\xff\xe0\xe7\xaf\xbf\x99\xa1V]\xe9\xe2\x16\xdc\tUk\n\xf8t\xc3<5\x13\xc0\x95\xea?\x18\xed\n\xf2\x95E\xb1\xbea\xe6\xb3^Q\x90<\xa5\xf2\xbc+f\xec\xa2\xcc\xf1z\x8d\x01T\x8dB\xf4\xf3\xd1\xd0\xe1\x05\xb0\x0b\xac.\xf2*\x97\'\xc5v\xf6\x0e\xd4\xcdX\xaa\xff<\x17\xdb\xee\xe7O\'\x0e\xa7>\x03\xea\xd6@QC\xcc\x9b\xa0x\x9e(l\xa6\xc0\x11Z\x04U\xaat8#\xb0l\x18|\x8b-E\xc0\x888c\x98\xd2xA\xbc\xcfj\x87SC\'+1\xfe\xbcn\xc0\x01@\xa5P2\xe4\xc5/\x8b=\x1e\'\x97g\x93\xc4 P\xa1\x88}\xe5\xeb\xc6~\x93\xe1\x99gA,,\xa4\xc2\x1d\xcb\xe6l\x8eX\xa6\x98\xa6\xf8\xfb\x1c\xd0\\\xc7\x15\xea\xdb\x86\xc2Q}\xe1\xe3\xa6\xb22CT-\xe7\xd7o}\nn\xf9\x06y\xfa\xd9Yxk\x00\xb3\xf6zm%\r\x82\xb3_\xa8F\xbb\x0e\xe0\xf1@!\xf1\x1b\xcc\xcb[,a\x94\xf8\x9f\x0b\xab\x8bK0iZ\xaa\xa1z\xee\xa9\xac.\xe9[\xfc/k/\xb4s1\x93\xf1\x8f\xb28\xa7\x93\x10\x8e\x93\x9a\xed\x1a\x1b\xefU\xd5\xa7Vl\x98\x90\x05y\x87\xb5_>\x14i$\xe8\t\xa7J\xabu\xe0\xb3\xe2\xa0F\x05E\x1cR\x04\'Q\xc8\xdez\x1cOo)D,7\xc1\xb5\xc5r\xf1\xef\xd4\xc2c\xeec\xe6\xd3aK\xd2\x08y\xbf\xd4\xa8\xfdO"\xb6\xb8&\x0c\xbc\x8aw\xbc\x013\xb8[\xfc\x9d\x0bC\xd8\x02u\xaaM+H\x17\x9c#\xf8x1b3Gd\xa1\xdcE\xf6\xe1\xc3\x16\x92\xf2n\x89\xe7\xd56E\xa3\xb7\x97\xceB\x90\xf16\xce3#M.b\x14\xcc&\xb2,)\xcd\xdd\x15\xb0[\xa4\x8c4\x86\xf5d<\rp\xde\xd9\x9a\xdb\x91R\xd1*\x02\xf46\xe9\xa8ci\xfb\xe1\xce\xc3\x9f\xa1[\xe7\x1f\xc71\xe1h<\xb6\x0e\x12\xa9\xf4\xda\xfa(\x84\xa9\xb9\xe7F\xe0\x81']
I: comments will be shown as: ['zip archive with some secret data']
```


Comments longer than 512 bytes:
```
[10] Comments (optional, up to 512 B): An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block counter, the maximum message length that can be safely encrypted by the IETF's variant is 232 blocks of 64 bytes (256 GiB). For applications where this is not enough, such as file or disk encryption, RFC 7539 proposes using the original algorithm with 64-bit nonce.
W: comments size: 776 B; comments will be truncated!
I: comments will be shown as: ["An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block c"]

```



Comments longer than 512 bytes with debug messages enabled:
```
[10] Comments (optional, up to 512 B): An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block counter, the maximum message length that can be safely encrypted by the IETF's variant is 232 blocks of 64 bytes (256 GiB). For applications where this is not enough, such as file or disk encryption, RFC 7539 proposes using the original algorithm with 64-bit nonce.
W: comments size: 776 B; comments will be truncated!
D: comments: ["An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block c"], size: 776 B
D: pot_comments: [b"An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block c"]
I: comments will be shown as: ["An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block c"]
```


---

## [11] Keyfile path

**Used in:** actions `2|3|6|7`

**Function:** `get_ikm_digest_list()`

**Data type:** `str`

**Valid values:** path to a readable file; path to a directory with readable files

**Default value:** (none)



### Examples

Keyfiles are not specified (skipped):
```
[11] Keyfile path (optional):
[12] Passphrase (optional):
```



---

## [12] Passphrase

**User in:** actions `2|3|6|7`

**Function:** `get_ikm_digest_list()`

**Data type:** `str`

**Valid values:** arbitary string

**Default value:** (none)


### Examples


```
[12] Passphrase (optional):
[12] Confirm passphrase:
I: passphrase accepted
```

```
[12] Passphrase (optional):
[12] Confirm passphrase:
E: passphrase confirmation failed
```


```
[12] Passphrase (optional):
I: entering keying material is completed
```

---

## [13] Proceed?

**Used in:** actions `2|3|4|5|6|7|8|9`

**Function:** `proceed()`

**Data type:** `bool`

**Valid values:** `Y|y|1|N|n|0`

**Default value:** not defined or True (depends on the context)



### Examples

```
W: output file contents will be partially overwritten!
[13] Proceed? (Y/N): y
I: writing random data...
```

```
W: output file contents will be partially overwritten!
[13] Proceed? (Y/N): n
I: stopped by user reques
```

```
W: output file contents will be partially overwritten!
[13] Proceed? (Y/N): y
I: reading, writing...
```


```
I: next it's offered to remove the output file path
[13] Proceed? (Y/N, default=Y):
I: path "fooo" has been removed
```

---

## [14] Output file size


**Used in:** action `8`

**Function:** `get_output_file_size()`

**Data type:** `int`

**Valid values:** `>= 0`

**Default value:** (not defined)


#### Examples

```
[14] Output file size in bytes: 1000000
I: size: 1000000 B, 976.6 KiB
```

