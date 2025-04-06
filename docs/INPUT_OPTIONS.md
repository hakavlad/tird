
<h4 align="left">
  🏠&nbsp;<a href="https://github.com/hakavlad/tird">Homepage</a> &nbsp;
  📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">man&nbsp;page</a> &nbsp;
  📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a> &nbsp;
  📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a> &nbsp;
  📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial</a> &nbsp;
  ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ</a>
</h4>

---

# \[WIP] Input Options

There are 5 groups of input options: A (Action), C (Custom), D (Data), K (Keys), P (Proceed).

<table>

<tr><td><b>A</b></td><td><b>
&nbsp;<a href="#a0-select-an-option">A0. Select an option</a></li>
</b></td></tr>

<tr><td><b>C</b></td><td><b>
&nbsp;<a href="#c0-use-custom-settings">C0. Use custom settings?</a><br>
&nbsp;<a href="#c1-time-cost">C1. Time cost</a><br>
&nbsp;<a href="#c2-max-padding-size">C2. Max padding size</a><br>
&nbsp;<a href="#c3-set-fake-mac-tag">C3. Set fake MAC tag?</a>
</b></td></tr>

<tr><td><b>D</b></td><td><b>
&nbsp;<a href="#d1-input-file-path">D1. Input file path</a><br>
&nbsp;<a href="#d2-comments">D2. Comments</a><br>
&nbsp;<a href="#d3-output-file-path">D3. Output file path</a><br>
&nbsp;<a href="#d4-output-file-size">D4. Output file size</a><br>
&nbsp;<a href="#d5-start-position">D5. Start position</a><br>
&nbsp;<a href="#d6-end-position">D6. End position</a><br>
</b></td></tr>

<tr><td><b>K</b></td><td><b>
&nbsp;<a href="#k1-keyfile-path">K1. Keyfile path</a><br>
&nbsp;<a href="#k2-passphrase">K2. Passphrase<a>
</b></td></tr>

<tr><td><b>P</b></td><td><b>
&nbsp;<a href="#p0-proceed">P0. Proceed?</a>
</b></td></tr>

</table>

---




## A0. Select an option

**Data type:** `int`

**Valid values:** From `0` to `9`

**Default value:** Not specified

### Description

Select an option from the MENU list (select the action to perform).

```
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

Enter a number and press Enter.

### List of available actions

<table>

<tr>
<th>Action ID</th>
<th>Short Description</th>
<th>Description</th>
</tr>

<tr>
<td><code>0</code></td>
<td><code>Exit</code></td>
<td>Exiting the application.</td>
</tr>

<tr>
<td><code>1</code></td>
<td><code>Info & Warnings</code></td>
<td>Displaying info and warnings.</td>
</tr>

<tr>
<td><code>2</code></td>
<td><code>Encrypt</code></td>
<td>Encrypt file contents and comments; write the cryptoblob to a new file.</td>
</tr>

<tr>
<td><code>3</code></td>
<td><code>Decrypt</code></td>
<td>Decrypt a file; display the decrypted comments and write the decrypted contents to a new file.</td>
</tr>

<tr>
<td><code>4</code></td>
<td><code>Embed</code></td>
<td>Embed file contents (no encryption): write input file contents over output file contents.</td>
</tr>

<tr>
<td><code>5</code></td>
<td><code>Extract</code></td>
<td>Extract file contents (no decryption) to a new file.</td>
</tr>

<tr>
<td><code>6</code></td>
<td><code>Encrypt & Embed</code></td>
<td>Encrypt file contents and comments; write the cryptoblob over a container.</td>
</tr>

<tr>
<td><code>7</code></td>
<td><code>Extract & Decrypt</code></td>
<td>Extract and decrypt cryptoblob; display the decrypted comments and write the decrypted contents to a new file.</td>
</tr>

<tr>
<td><code>8</code></td>
<td><code>Create w/ Random</code></td>
<td>Create a file of the specified size with random data.</td>
</tr>

<tr>
<td><code>9</code></td>
<td><code>Overwrite w/ Random</code></td>
<td>Overwrite file contents with random data.</td>
</tr>

</table>

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>

Selecting action `8`:
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
A0. Select an option [0-9]: 8
    I: action #8:
        create file of specified size with random data
```

Selecting action `2` with debug messages enabled:
```
$ tird --debug
    W: debug mode enabled! Sensitive data will be displayed!

                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. Select an option [0-9]: 2
    I: action #2:
        encrypt file contents and comments;
        write cryptoblob to new file
```

</details>

---







## C0. Use custom settings?

**Used in:** Actions `2`|`3`|`6`|`7`

**Data type:** `bool`

**Valid values:** `Y`|`y`|`1` to set `True`; `N`|`n`|`0` to set `False`

**Default value:** `False`

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>





Context: actions `2`|`3`|`6`|`7` with default value:
```
C0. Use custom settings? (Y/N, default=N):
    I: use custom settings: False
```



Context: `2`|`3`|`6`|`7` with default value with debug messages enabled:
```
C0. Use custom settings? (Y/N, default=N):
    I: use custom settings: False
    D: time cost: 4
    D: max padding size, %: 20
    D: set fake MAC tag: False
```





Context: actions `2`|`6`:
```
C0. Use custom settings? (Y/N, default=N): y
    I: use custom settings: True
    W: decryption will require the same [C1] and [C2] values!
```

Context: actions `3`|`7`:
```
C0. Use custom settings? (Y/N, default=N): y
    I: use custom settings: True
```

</details>

---














## C1. Time cost

**Used in:** Actions `2`|`3`|`6`|`7`

**Data type:** `int`

**Valid values:** From `1` to `2^32 - 1` (`4294967295`)

**Default value:** `4`

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>






Context: actions `2`|`3`|`6`|`7` with default value:
```
C1. Time cost (default=4):
    I: time cost: 4
```

Context: actions `2`|`3`|`6`|`7`:
```
C1. Time cost (default=4): 1000
    I: time cost: 1,000
```

</details>

---







## C2. Max padding size

**Used in:** Actions `2`|`3`|`6`|`7`

**Data type:** `int`

**Valid values:** From `0` to `10^20` (one hundred quintillion)

**Default value:** `20`

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>








Context: actions `2`|`3`|`6`|`7` with default value:
```
C2. Max padding size, % (default=20):
    I: max padding size, %: 20
```

Context: actions `2`|`3`|`6`|`7`:
```
C2. Max padding size, % (default=20): 1000
    I: max padding size, %: 1,000
```

</details>

---








## C3. Set fake MAC tag?

**Used in:** Actions `2`|`6`

**Data type:** `bool`

**Valid values:** `Y`|`y`|`1` to set `True`; `N`|`n`|`0` to set `False`

**Default value:** `False`

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>








Context: actions `2`|`6` with default value:
```
C3. Set fake MAC tag? (Y/N, default=N):
    I: set fake MAC tag: False
```

Context: actions `2`|`6`:
```
C3. Set fake MAC tag? (Y/N, default=N): 1
    I: set fake MAC tag: True
```

</details>

---










## D1. Input file path

**Used in:** Actions `2`-`7`

**Data type:** `str`

**Valid values:** Path to an existing, readable file

**Default value:** Not specified

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>





Context: action `2`:
```
D1. File to encrypt: secret.zip
    I: path: 'secret.zip'; size: 19,356,207 B (18.5 MiB)
```

Context: action `2` with debug messages enabled:
```
D1. File to encrypt: secret.zip
    D: real path: '/tmpfs/test/secret.zip'
    D: opening file 'secret.zip' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='secret.zip'>
    I: path: 'secret.zip'; size: 19,356,207 B (18.5 MiB)
    D: constant_padded_size:     19,357,070 B (18.5 MiB)
    D: max_randomized_pad_size:  3,871,414 B (3.7 MiB)
    D: max_total_padded_size:    23,228,484 B (22.2 MiB)
```



Context: action `3`:
```
D1. File to decrypt: file.bin
    I: path: 'file.bin'; size: 32,973,056 B (31.4 MiB)
```

Context: action `3` with debug messages enabled:
```
D1. File to decrypt: file.bin
    D: real path: '/tmpfs/test/file.bin'
    D: opening file 'file.bin' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='file.bin'>
    I: path: 'file.bin'; size: 32,973,056 B (31.4 MiB)
```




Context: action `4`:
```
D1. File to embed: file.bin
    I: path: 'file.bin'; size: 32,973,056 B (31.4 MiB)
```

Context: action `4` with debug messages enabled:
```
D1. File to embed: file.bin
    D: real path: '/tmpfs/test/file.bin'
    D: opening file 'file.bin' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='file.bin'>
    I: path: 'file.bin'; size: 32,973,056 B (31.4 MiB)
```





Context: actions `5`|`7`:
```
D1. Container: file.bin
    I: path: 'file.bin'; size: 32,973,056 B (31.4 MiB)
```

Context: actions `5`|`7` with debug messages enabled:
```
D1. Container: file.bin
    D: real path: '/tmpfs/test/file.bin'
    D: opening file 'file.bin' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='file.bin'>
    I: path: 'file.bin'; size: 32,973,056 B (31.4 MiB)
```





Context: action `6`:
```
D1. File to encrypt and embed: file.bin
    I: path: 'file.bin'; size: 32,973,056 B (31.4 MiB)
```



Context: action `6` with debug messages enabled:
```
D1. File to encrypt and embed: file.bin
    D: real path: '/tmpfs/test/file.bin'
    D: opening file 'file.bin' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='file.bin'>
    I: path: 'file.bin'; size: 32,973,056 B (31.4 MiB)
    D: constant_padded_size:     32,973,919 B (31.4 MiB)
    D: max_randomized_pad_size:  6,594,783 B (6.3 MiB)
    D: max_total_padded_size:    39,568,702 B (37.7 MiB)
```

</details>

---














## D2. Comments

**Used in:** Actions `2`|`6`

**Data type:** `str`

**Valid values:** Arbitrary UTF-8 string

**Default value:** Empty string (results in None after decryption)

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>









Comments are not specified (by default):
```
D2. Comments (optional, up to 512 B):
    I: comments will be shown as [None]
```

Comments are not specified with debug messages enabled:
```
D2. Comments (optional, up to 512 B):
    D: raw_comments: [''], size: 0 B
    D: processed_comments: [b'\x7f\xb0?\xf61\xb0\xbe\x96\xed\xecdVs@\x8f\xefq\x01\x1e\xe6r\x88\x08\xa0\x12\x13\xc3\xe2\x87\n_\xdb-\xd0\xbe\x19b\x18h&Y\xd3F\xaf\xb2\xe0\xbd\x9d\xa5R\xd9Pc\x19O\x1dd\xeaO\xcc\xc4\xf6I\xc3\xcb~\x02\xe8\x81\xda\xb0\x15\xb8/\xf2\xed\xf2Jy.\xcbho\xba\x1d5\x8d\x88S\x83\xf2\xef\x14\xd5\xca\x04P\n/\x95>z3\x8c\xaa\xee\x99\x84\x84\x15~A\x90\xea\xae\xfb\x8dq\xa3\x0cix\t\x7f\xdc}`\xcc\x89\x06\xfe\xda\x1b\xba3\x07\xe8\x1e\x84\xd5O\xbb\xaaB\xad\xf2|\xf1/\xb9\xe8V\x04}s\xb5\x97\x8f\xd1l`\xa2\x03\xe0\x06\xfd\xf8\xb5$X\x08"g\x85s\xf0\xf66++u\x1dT"\xc6V-\xf9\xde\x0c"\xe3\xc0\xc7\xcb\n\x0c\x98\xa1\xa6.\xf7\xbb\xd8\xebR\x84\xcd\xe3\x14\xf5\x0e\x19\x97\xbamJx\x97\xd47\x0f\x10+z\xe3\xb2Q\xf9|f\x06(\xee\x84\xa5g\x85UJY?\xdf\xaa\xd6\xad\xc2BP/\xe4jj\xb5g$d K\xdf\x01\xb5\xfe\xd2\xb88F\x9f\x9b\x94\xfdM\xb3\xa5\xb7\x87\xbf\xff\xa2T)\x80\xe9\xd6\\\x86R_\xcf\xc0g\x80b\x81\xa9\x87\x90\x85\x8c"#\xd5\xa17v\'\xb9\td`^\xc1o\x80\'\xc0*\x15\x02\xe9d\xa0\xcb\xea\x06\x03`\x0c\x82g\xd6\xa7\x91\x13}\x98\x08\x7f\xf3\xfci\x8aV\t\xdc\xe4MS\x18\x17\xb9\xd1\xf6T\xfd\xbbXpF\x89L\x8b\x05\x86.\xc8\xc6\x8f\xce\xb9\xa5}o\x8e\xcc\xc1\x1f\xd3!\x88S\xd6\xf8W\x03\xe3\xed\xd7\x1d\x1fw\xbf\xdb\xd11YZ\xe7\xf8\x9e`~\x15/\x03\xe4a\xa3\xee\xb1{\xd1\xd2\xef\xb2\x04\xb3U\xb9\xf3\xc5\xd7\x85\xf8e\xe7\x0f\xaa\xe4 \xf5\x9b\x89P\xfc\x05\x16\xcdTK\x95\xc1\xd0\r\xe1C@\x02/\xfdb}m\xb8f^]\x84M\xf1\x1b\x01\xccH\xcb\x9d\xcc:m\x9c\xe3\xb9\xddL\xbb;\xc7\xea\xfb.\'\x06\x150bhe\x06FF\x1b\xf6\xdd\xa1\x84_\xc13\xd95h\x0c\xab\xc4\xfc\x84\xbf\x18g\x9a\x1af'], size: 512 B
    I: comments will be shown as [None]
```










Short comments (up to 512 bytes):
```
D2. Comments (optional, up to 512 B): zip archive with some secret data
    I: comments will be shown as ['zip archive with some secret data']
```

Short comments (up to 512 bytes) with debug messages enabled:
```
D2. Comments (optional, up to 512 B): zip archive with some secret data
    D: raw_comments: ['zip archive with some secret data'], size: 33 B
    D: processed_comments: [b'zip archive with some secret data\xff\x0b\xee\x83\x07\x856\x1cWUR\xd4\xc9\x829^\xb3\x93\xac\n\x83\xb5\xcf\xdaE\xdb\x9e6\r\xb90a\x169hW\x06\x03\x19\xc5r\xa5\x96\x17\x9e\xa4\xd5j\xaaS{\x1b\x9a\xc1-\x03]JV\x03\xa7\xb5F\x1e^\xc1\x04Bq[iP\xa40\xe9\xc4\xf3p\xc56\xb4p\xa81hy#\x94\xb3\xfa\xd5\xa1\xeaQ\x14U\xc6~\xff3\x03\xa8\x1f)\x7f#\x8cm<\x8cjR\xcc\xcd\x02\x85\xc5k\x9a\xee!\xc1\x11+A_\xd8I\xe0\xeb\x8av\x8d\x8d&X\x1d\xe8\xd9a\xe70*l\x18\xa1\x952\xa8\n\t\xed\x86\x01\x87\xeb\x1c\x06\xc7\x11\x9e?\x80q\xc2\xf4<\x8d\xa4$\xcaYZ\x12\xbbj\x91n\xf3\xf5%\x88\x81\x843i\xf7\xf0f\xce\xd1\xef\x03W\xe7\xe0}\xdb\xc0\xf3\xb5\xc9\xa8\x11c\xb5\xf9T\xb2\xb7/\xcf\xa9x]\xa4\xab\xc14F\x1f\xec\xee}\xd3\x0bMi\xad\xa3%\x94A\xda,\xf6\xfc:\xf6\x8f\x7f\x1d\r\x1b4P\x0fu%k\x9a1\x18\xfdi\xf1\xae;oPF\xe0\xe6V\x07\x11\xa8sr\xd4\xbb\xb8]\xf4\x8c?K|\xfc\x06|B\x8eM3\xa5\x99@\x1ce\xf5\xd7\xdd\x10\xfeT\x11\xbc\x06!\xbd^$\xe4\xc3\xf1\xcckH\xad\x9ca\xddr\xbe\xfa~\x1f\xdb\xcd\xef\xb1\'\x99\xa6SI\xea\xd8m19\xc9\xbb\xf5{\xce.\xd00\xd9\xfa\xb2kc\xfe|\xec\x05j\x80\x07,\x193\x88`\xd8\xd5k"&\xcc\xc9"\xf6P\xf8\x8d\xd2\xcf\x8b|\xc9\x9f\xfe\xdc\xaa\xa8\x03P\xf0\xc8\xb2\xbf\x07\x9dj\x19]\xcb\xbf\xf58\xdb\x01\xba\xd5?j\xa11\x98OH\rl\xffxN\xdc\x08\xd9Yp\x82\x88\xbcE!_\xcfz\xa5\x82\x8f\x06\xc6\xa0\x94\x9e"\xbd\xaa*C\x1e\xc8\x8dt\xae\x9a\xe4c\xf2vl\xbf6\x80\xd36#\xc2\x9f?\xc5nl\xeb\x8a0)\x84%\x9e\x00K]\x99\x1du*d\xe5\x9d\x7fY\x19'], size: 512 B
    I: comments will be shown as ['zip archive with some secret data']
```











Comments longer than 512 bytes:
```
D2. Comments (optional, up to 512 B): An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block counter, the maximum message length that can be safely encrypted by the IETF's variant is 232 blocks of 64 bytes (256 GiB). For applications where this is not enough, such as file or disk encryption, RFC 7539 proposes using the original algorithm with 64-bit nonce.
    W: comments size: 776 B; it will be truncated!
    I: comments will be shown as ["An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block c"]
```

Comments longer than 512 bytes with debug messages enabled:
```
D2. Comments (optional, up to 512 B): An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block counter, the maximum message length that can be safely encrypted by the IETF's variant is 232 blocks of 64 bytes (256 GiB). For applications where this is not enough, such as file or disk encryption, RFC 7539 proposes using the original algorithm with 64-bit nonce.
    W: comments size: 776 B; it will be truncated!
    D: raw_comments: ["An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block counter, the maximum message length that can be safely encrypted by the IETF's variant is 232 blocks of 64 bytes (256 GiB). For applications where this is not enough, such as file or disk encryption, RFC 7539 proposes using the original algorithm with 64-bit nonce."], size: 776 B
    D: processed_comments: [b"An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block c"], size: 512 B
    I: comments will be shown as ["An implementation reference for ChaCha20 has been published in RFC 7539. The IETF's implementation modified Bernstein's published algorithm by changing the 64-bit nonce and 64-bit block counter to a 96-bit nonce and 32-bit block counter.[46] The name was not changed when the algorithm was modified, as it is cryptographically insignificant (both form what a cryptographer would recognize as a 128-bit nonce), but the interface change could be a source of confusion for developers. Because of the reduced block c"]
```

</details>

---








## D3. Output file path

**Used in:** Actions `2`-`9`

**Data type:** `str`

**Valid values:** Path to an existing container or a non-existent file (a new file will be created), depending on the context

**Default value:** Not specified

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>




Context: action `2`:
```
D3. Output (encrypted) file: random.bin
    I: new empty file 'random.bin' created
```

Context: action `2` with debug messages enabled:
```
D3. Output (encrypted) file: random.bin
    D: real path: '/tmpfs/test/random.bin'
    D: opening file 'random.bin' in mode 'wb'
    D: opened file (object): <_io.BufferedWriter name='random.bin'>
    I: new empty file 'random.bin' created
```





Context: actions `3`|`7`:
```
D3. Output (decrypted) file: plain.txt
    I: new empty file 'plain.txt' created
```

Context: actions `3`|`7` with debug messages enabled:
```
D3. Output (decrypted) file: plain.txt
    D: real path: '/tmpfs/test/plain.txt'
    D: opening file 'plain.txt' in mode 'wb'
    D: opened file (object): <_io.BufferedWriter name='plain.txt'>
    I: new empty file 'plain.txt' created
```





Context: actions `4`|`6`:
```
D3. File to overwrite (container): file.bin
    I: path: 'file.bin'
    I: size: 32,973,056 B (31.4 MiB)
```

Context: actions `4`|`6` with debug messages enabled:
```
D3. File to overwrite (container): file.bin
    D: real path: '/tmpfs/test/file.bin'
    D: opening file 'file.bin' in mode 'rb+'
    D: opened file (object): <_io.BufferedRandom name='file.bin'>
    I: path: 'file.bin'
    I: size: 32,973,056 B (31.4 MiB)
```





Context: actions `5`|`8`:
```
D3. Output file: random.bin
    I: new empty file 'random.bin' created
```

Context: actions `5`|`8` with debug messages enabled:
```
D3. Output file: random.bin
    D: real path: '/tmpfs/test/random.bin'
    D: opening file 'random.bin' in mode 'wb'
    D: opened file (object): <_io.BufferedWriter name='random.bin'>
    I: new empty file 'random.bin' created
```





Context: action `9`:
```
D3. File to overwrite: /dev/sdc
    I: path: '/dev/sdc'; size: 16,357,785,600 B (15.2 GiB)
```

Context: action `9` with debug messages enabled:
```
D3. File to overwrite: /dev/sdc
    D: real path: '/dev/sdc'
    D: opening file '/dev/sdc' in mode 'rb+'
    D: opened file (object): <_io.BufferedRandom name='/dev/sdc'>
    I: path: '/dev/sdc'; size: 16,357,785,600 B (15.2 GiB)
```

</details>

---






## D4. Output file size

**Used in:** Action `8`

**Data type:** `int`

**Valid values:** From `0` to `2^64` (i.e., up to 16 EiB in bytes)

**Default value:** Not specified

### Description

Desired output file size in bytes. The number of random bytes that will be written to the specified file.

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>







Specifying 32 B:
```
D4. Output file size in bytes: 32
    I: size: 32 B
```

</details>

---

















## D5. Start position

**Used in:** actions `4`|`5`|`6`|`7`|`9`

**Data type:** `int`

**Valid values:** From `0` to container file size in bytes

**Default value:** Not specified for actions `4`|`5`|`6`|`7`; defaults to `0` for action `9` (if not provided, `0` is used)








### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>



Context: action `4`:
```
D5. Start position [0; 56372322]: 34956
    I: start position: 34956 (offset: 34,956 B)
    I: end position: 33008012 (offset: 33,008,012 B)
```




Context: actions `5`|`6`|`7`:
```
D5. Start position [0; 32973056]: 395673
    I: start position: 395673 (offset: 395,673 B)
```



Context: action `9`:
```
D5. Start position [0; 32973056], default=0:
    I: start position: 0 (offset: 0 B)
```


```
D5. Start position [0; 32973056], default=0: 2623552
    I: start position: 2623552 (offset: 2,623,552 B)
```

</details>

---












## D6. End position

**Used in:** actions `5`|`7`|`9`

**Data type:** `int`

**Valid values:** From start position to container file size in bytes

**Default value:** Not specified for actions `5`|`7`; defaults to container file size in bytes for action `9`




### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>


Context: action `5`:
```
D6. End position [32442; 32973056]: 483764
    I: end position: 483764 (offset: 483,764 B)
    I: message size to retrieve: 451,322 B (440.7 KiB)
```




Context: action `7`:
```
D6. End position [55408; 32973056]: 5656465
    I: end position: 5656465 (offset: 5,656,465 B)
```



Context: action `9`:
```
D6. End position [0; 32973056], default=32973056:
    I: end position: 32973056 (offset: 32,973,056 B)
    I: data size to write: 32,973,056 B (31.4 MiB)
```


```
D6. End position [4423; 32973056], default=32973056: 543432
    I: end position: 543432 (offset: 543,432 B)
    I: data size to write: 539,009 B (526.4 KiB)
```

</details>

---








## K1. Keyfile path

**Used in:** Actions `2`|`3`|`6`|`7`

**Data type:** `str`

**Valid values:** Arbitrary path to a readable file, path to a directory with readable files, or nothing (option skipped)

**Default value:** Not specified

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>






Keyfiles and passphrases are not specified (skipped):
```
K1. Keyfile path (optional):
K2. Passphrase (optional):
    W: no keyfile or passphrase specified!
```


The same with debug messages enabled:
```
K1. Keyfile path (optional):
    W: entered passphrases will be displayed!
K2. Passphrase (optional):
    D: 0 IKM digests collected
    W: no keyfile or passphrase specified!
    D: collecting input keying material completed
    D: digest list is empty, nothing to sort
    D: hashing digest list
    D: list containing 0 digests hashed
```





Specifying only `keyfile.bin`:
```
K1. Keyfile path (optional): keyfile.bin
    I: path: 'keyfile.bin'; size: 32 B
    I: reading and hashing contents of 'keyfile.bin'
    I: keyfile accepted
K1. Keyfile path (optional):
K2. Passphrase (optional):
    I: deriving one-time keys
```



The same with debug messages enabled:
```
K1. Keyfile path (optional): keyfile.bin
    D: real path: '/tmpfs/test/keyfile.bin'
    I: path: 'keyfile.bin'; size: 32 B
    I: reading and hashing contents of 'keyfile.bin'
    D: opening file 'keyfile.bin' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='keyfile.bin'>
    D: read 32 B from <_io.BufferedReader name='keyfile.bin'>; position moved from 0 to 32
    D: closing <_io.BufferedReader name='keyfile.bin'>
    D: <_io.BufferedReader name='keyfile.bin'> closed
    D: digest of 'keyfile.bin' contents:
        691693749d3a3c058871474e71dfaebe55ef4e91abbbe40b31bf6503e2c1b9acd3504f4032e3c6febcb1e539f3ce86893041656315bd2673708fb8d02d497410
    I: keyfile accepted
K1. Keyfile path (optional):
    W: entered passphrases will be displayed!
K2. Passphrase (optional):
    D: 1 IKM digests collected
    D: collecting input keying material completed
    D: sorting digests of keying material
    D: sorted digests of keying material:
      - 691693749d3a3c058871474e71dfaebe55ef4e91abbbe40b31bf6503e2c1b9acd3504f4032e3c6febcb1e539f3ce86893041656315bd2673708fb8d02d497410
    D: hashing digest list
    D: list containing 1 digests hashed
    D: argon2_password:
        b1d9f8334f4d8be703e0072befe66f6bd448d224cbbfac58e1b28c0f0c2e270c84488e417d75c947189bb66f46480848a5446b90d15cf8ae027cb5010189953b
    I: deriving one-time keys
```






























Specifying `keydir` and `/bin/sh` as keyfile paths:
```
K1. Keyfile path (optional): keydir
    I: scanning directory 'keydir'
    I: found 3 files
    I: list of these files:
      - path: 'keydir/keyfile.bin'; size: 32 B
      - path: 'keydir/x/111'; size: 12,318 B (12.0 KiB)
      - path: 'keydir/x/444'; size: 32 B
    I: total size: 12,382 B (12.1 KiB)
    I: hashing files in directory 'keydir'
    I: 3 keyfiles accepted
K1. Keyfile path (optional): /bin/sh
    I: path: '/bin/sh'; size: 125,560 B (122.6 KiB)
    I: reading and hashing contents of '/bin/sh'
    I: keyfile accepted
```

The same with debug messages enabled:
```
K1. Keyfile path (optional): keydir
    D: real path: '/tmpfs/test/keydir'
    I: scanning directory 'keydir'
    I: found 3 files
    D: getting size of 'keydir/keyfile.bin' (real path: '/tmpfs/test/keydir/keyfile.bin')
    D: size: 32 B
    D: getting size of 'keydir/x/111' (real path: '/tmpfs/test/keydir/x/111')
    D: size: 12,318 B (12.0 KiB)
    D: getting size of 'keydir/x/444' (real path: '/tmpfs/test/keydir/x/444')
    D: size: 32 B
    I: list of these files:
      - path: 'keydir/keyfile.bin'; size: 32 B
      - path: 'keydir/x/111'; size: 12,318 B (12.0 KiB)
      - path: 'keydir/x/444'; size: 32 B
    I: total size: 12,382 B (12.1 KiB)
    I: hashing files in directory 'keydir'
    D: reading and hashing contents of 'keydir/keyfile.bin'
    D: opening file 'keydir/keyfile.bin' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='keydir/keyfile.bin'>
    D: read 32 B from <_io.BufferedReader name='keydir/keyfile.bin'>; position moved from 0 to 32
    D: closing <_io.BufferedReader name='keydir/keyfile.bin'>
    D: <_io.BufferedReader name='keydir/keyfile.bin'> closed
    D: digest of 'keydir/keyfile.bin' contents:
        d4fe1f52c510f69363a47db7c37511ae2673c61b5aa341ba69cc58c9d103e23f30c7db3fba04a1efdcddef7b207e8734217c6d3bd35e8958bb4bf547be0d7b5a
    D: reading and hashing contents of 'keydir/x/111'
    D: opening file 'keydir/x/111' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='keydir/x/111'>
    D: read 12,318 B (12.0 KiB) from <_io.BufferedReader name='keydir/x/111'>; position moved from 0 to 12,318
    D: closing <_io.BufferedReader name='keydir/x/111'>
    D: <_io.BufferedReader name='keydir/x/111'> closed
    D: digest of 'keydir/x/111' contents:
        e7221ae7ac1108885745c85e2fecd31dce6c305e4e6e088d0a2ee0c760919402f8194bf004590d27ef6fc122d9fdf1b89d15f6705f322c69ce306429b453cf7e
    D: reading and hashing contents of 'keydir/x/444'
    D: opening file 'keydir/x/444' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='keydir/x/444'>
    D: read 32 B from <_io.BufferedReader name='keydir/x/444'>; position moved from 0 to 32
    D: closing <_io.BufferedReader name='keydir/x/444'>
    D: <_io.BufferedReader name='keydir/x/444'> closed
    D: digest of 'keydir/x/444' contents:
        015c474606ebf8b5488f0bf103a7b8b77433efacf25504a1ad85c0018e7a8cb770b319865e0dc3c52140cd900d14d3c77a1d1f281cabc5625a99e83ae05111b4
    I: 3 keyfiles accepted
K1. Keyfile path (optional): /bin/sh
    D: real path: '/usr/bin/dash'
    I: path: '/bin/sh'; size: 125,560 B (122.6 KiB)
    I: reading and hashing contents of '/bin/sh'
    D: opening file '/bin/sh' in mode 'rb'
    D: opened file (object): <_io.BufferedReader name='/bin/sh'>
    D: read 125,560 B (122.6 KiB) from <_io.BufferedReader name='/bin/sh'>; position moved from 0 to 125,560
    D: closing <_io.BufferedReader name='/bin/sh'>
    D: <_io.BufferedReader name='/bin/sh'> closed
    D: digest of '/bin/sh' contents:
        7db1cc29b7bc3341cf12438ecc272dd5cfa0bd12d98f5ff1ff18fd1b7e958119fc74571c746d60855838d2fd16f4ea3a77e9f28bb17c918c3f2be75a676505bf
    I: keyfile accepted
```












Possible errors and warnings:
```
K1. Keyfile path (optional): /
    D: real path: '/'
    I: scanning directory '/'
    E: [Errno 13] Permission denied: '/sys/kernel/tracing/instances'
    E: keyfiles NOT accepted
K1. Keyfile path (optional): /dev/sda
    D: real path: '/dev/sda'
    E: [Errno 13] Permission denied: '/dev/sda'
    E: keyfile NOT accepted
K1. Keyfile path (optional): /---
    E: file '/---' not found
    E: keyfile NOT accepted
K1. Keyfile path (optional): emptydir
    D: real path: '/tmpfs/test/emptydir'
    I: scanning directory 'emptydir'
    I: found 0 files
    W: directory is empty; no keyfiles to accept!
```

</details>

---






## K2. Passphrase

**Used in:** Actions `2`|`3`|`6`|`7`

**Data type:** `str`

**Valid values:** Arbitrary string (minimum 1 byte) or nothing (option skipped)

**Default value:** Not specified

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>



Just specifying one passphrase:
```
K2. Passphrase (optional):
K2. Confirm passphrase:
    I: passphrase accepted
```

The same with debug messages enabled:
```
    W: entered passphrases will be displayed!
K2. Passphrase (optional):
    D: passphrase (raw):
        'correct horse battery staple'
    D: length: 28 B
    D: passphrase (normalized):
        'correct horse battery staple'
    D: length: 28 B
    D: passphrase (normalized, encoded, truncated):
        b'correct horse battery staple'
    D: length: 28 B
K2. Confirm passphrase:
    D: passphrase (raw):
        'correct horse battery staple'
    D: length: 28 B
    D: passphrase (normalized):
        'correct horse battery staple'
    D: length: 28 B
    D: passphrase (normalized, encoded, truncated):
        b'correct horse battery staple'
    D: length: 28 B
    D: passphrase digest:
        6620fb4dfabf8e838bf86d8297792cc80eedcf080eb83d7d754b3a7ff44164dd7d12350cb8133663abbae6596d1bb67da13b8f78c6aa33cd2f51a32de965af67
    I: passphrase accepted
```



Specify one passphrase, then fail to confirm passphrase, then specify another passphrase:
```
K2. Passphrase (optional):
K2. Confirm passphrase:
    I: passphrase accepted
K2. Passphrase (optional):
K2. Confirm passphrase:
    E: passphrase NOT accepted: confirmation failed
K2. Passphrase (optional):
K2. Confirm passphrase:
    I: passphrase accepted
```

The same with debug messages enabled:
```
K2. Passphrase (optional):
    D: passphrase (raw):
        '3333'
    D: length: 4 B
    D: passphrase (normalized):
        '3333'
    D: length: 4 B
    D: passphrase (normalized, encoded, truncated):
        b'3333'
    D: length: 4 B
K2. Confirm passphrase:
    D: passphrase (raw):
        '4444'
    D: length: 4 B
    D: passphrase (normalized):
        '4444'
    D: length: 4 B
    D: passphrase (normalized, encoded, truncated):
        b'4444'
    D: length: 4 B
    E: passphrase NOT accepted: confirmation failed
K2. Passphrase (optional):
    D: passphrase (raw):
        '5555'
    D: length: 4 B
    D: passphrase (normalized):
        '5555'
    D: length: 4 B
    D: passphrase (normalized, encoded, truncated):
        b'5555'
    D: length: 4 B
K2. Confirm passphrase:
    D: passphrase (raw):
        '5555'
    D: length: 4 B
    D: passphrase (normalized):
        '5555'
    D: length: 4 B
    D: passphrase (normalized, encoded, truncated):
        b'5555'
    D: length: 4 B
    D: passphrase digest:
        931362faccd5621fbcaa3a1a1b9a6982463ca2b2437e958ba4de6803517e72689f47ba86951d9e669a16dfed348c5a1f6b38d00d914ac485296a444a8bb0362b
    I: passphrase accepted
```

</details>

---













## P0. Proceed?

**Used in:** Actions `2`-`9`

**Data type:** `bool`

**Valid values:** `Y`|`y`|`1` to set `True`; `N`|`n`|`0` to set `False`

**Default value:** Depends on context; either not specified or defaults to `True`

Note: For some actions, the default behavior is to proceed without explicit confirmation, while in others the user must explicitly confirm.

### Examples

<details>
  <summary>&nbsp;<b>Show Examples</b></summary>


Context: action `4`:
```
    W: output file will be partially overwritten!
P0. Proceed overwriting? (Y/N): 1
    I: reading message from input and writing it over output

```

Context: action `6`:
```
    W: output file will be overwritten from 3785 to maximum 39568924!
P0. Proceed overwriting? (Y/N): 1
    I: deriving one-time keys
    I: keys derived in 1.9s
    I: reading plaintext, writing cryptoblob
```

Context: action `9`:
```
    W: output file will be partially overwritten!
P0. Proceed overwriting? (Y/N): 1
    I: writing random data
```


Context: actions `4`|`9`:
```
    W: output file will be partially overwritten!
P0. Proceed overwriting? (Y/N): n
    I: stopped by user request
```


Context: actions `2`-`9`:
```
    I: removing output file path
P0. Proceed removing? (Y/N, default=Y):
    I: path 'file.bin' removed
```



</details>







