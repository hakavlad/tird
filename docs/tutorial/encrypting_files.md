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

# Encrypting Files

To encrypt a file, you need to answer at least 7 questions.

```
A0. Select an option [0-9]:
C0. Use custom settings? (Y/N, default=N):
D1. File to encrypt:
D2. Comments (optional, up to 512 B):
D3. Output (encrypted) file:
K1. Keyfile path (optional):
K2. Passphrase (optional):
```

Some of them can be skipped by simply pressing Enter. Specifying the input file path and output file path is mandatory. It is highly recommended to provide a strong password and/or keyfile.

Let's consider 3 examples:

- Encrypting a file with a password.
- Encrypting a file and comment with passwords and keyfiles.
- Encrypting a file with custom options.

---

## Encrypting a File with a Password

#### 1. Select option (action) 2

```
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

#### 2. Skip custom settings

Just press Enter:

```
C0. Use custom settings? (Y/N, default=N):
    I: use custom settings: False
```

#### 3. Enter input file path

Enter the path to the file that should be encrypted and press Enter:

```
D1. File to encrypt: secret.zip
    I: path: 'secret.zip'; size: 1,000,000 B (976.6 KiB)
```

#### 4. Skip Comments

Just press Enter.

```
D2. Comments (optional, up to 512 B):
    I: comments will be shown as [None]
```

#### 5. Enter ouput file path

```
D3. Output (encrypted) file: random1.bin
    I: new empty file 'random1.bin' created
```

#### 6. Skip keyfile

Just press Enter:

```
K1. Keyfile path (optional):
```

#### 7. Specify passphrase

In our example, we are encrypting the file with a single password.
Enter the password, press Enter, and repeat the input.
When prompted for the new password again, just press Enter.

```
K2. Passphrase (optional):
K2. Confirm passphrase:
    I: passphrase accepted
K2. Passphrase (optional):
```

#### Then action will be completed

Key derivation will occur from the specified password and generated salts.

```
    I: deriving one-time keys
    I: keys derived in 6.9s
```

The contents of the input file will be read in chunks of 16 MiB, encrypted, and a cryptoblob will be formed containing the ciphertext and MAC tag, surrounded by random data.

```
    I: reading plaintext, writing cryptoblob
    I: written 100.0%; 1.1 MiB in 0.0s; avg 100.0 MiB/s
    I: writing completed; total of 1,168,368 B written
```

The location of the padding within the cryptoblob will be displayed:

```
    I: location of padding in output file (may be ignored):
        [16:9462] — 9,446 B (9.2 KiB)
        [1010038:1168352] — 158,314 B (154.6 KiB)
```

Upon successful completion of the action, you will see "action completed":

```
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
A0. Select an option [0-9]: 2
    I: action #2:
        encrypt file contents and comments;
        write cryptoblob to new file
C0. Use custom settings? (Y/N, default=N):
    I: use custom settings: False
D1. File to encrypt: secret.zip
    I: path: 'secret.zip'; size: 1,000,000 B (976.6 KiB)
D2. Comments (optional, up to 512 B):
    I: comments will be shown as [None]
D3. Output (encrypted) file: random1.bin
    I: new empty file 'random1.bin' created
K1. Keyfile path (optional):
K2. Passphrase (optional):
K2. Confirm passphrase:
    I: passphrase accepted
K2. Passphrase (optional):
    I: deriving one-time keys
    I: keys derived in 6.9s
    I: reading plaintext, writing cryptoblob
    I: written 100.0%; 1.1 MiB in 0.0s; avg 100.0 MiB/s
    I: writing completed; total of 1,168,368 B written
    I: location of padding in output file (may be ignored):
        [16:9462] — 9,446 B (9.2 KiB)
        [1010038:1168352] — 158,314 B (154.6 KiB)
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
A0. Select an option [0-9]: 2
    I: action #2:
        encrypt file contents and comments;
        write cryptoblob to new file
    W: debug mode enabled! Sensitive data will be exposed!
C0. Use custom settings? (Y/N, default=N):
    I: use custom settings: False
    D: time cost: 4
    D: max padding size, %: 20
    D: set fake MAC tag: False
D1. File to encrypt: secret.zip
    D: real path: '/tmp/test/secret.zip'
    D: opening file 'secret.zip' in mode 'rb'
    D: opened file object: <_io.BufferedReader name='secret.zip'>
    I: path: 'secret.zip'; size: 1,000,000 B (976.6 KiB)
    D: constant_padded_size:     1,000,863 B (977.4 KiB)
    D: max_randomized_pad_size:  200,172 B (195.5 KiB)
    D: max_total_padded_size:    1,201,035 B (1.1 MiB)
D2. Comments (optional, up to 512 B):
    D: raw_comments: [''], size: 0 B
    D: processed_comments: [b'\x1fO\xb1\x0b\x85\xec\x86\xcc\xe7ci\xd9\x17\x1dw\xfa\xa8\xa7\x14\x00\xe0\x11\xcd\xbe\xeb\xd0\x92\xf9\xfc\x0eB\x9b1\x05\xce\xd4\x06\x13<\xca\x93\x99\xcd\xd2\x9a\xc5\xb1S\x8am\x9eQ\x98\x9fC!\xa0\xa6 L\x0f5\x98+{\xc2\\\xb1Dh\xcbzu=>\xa4\xc4\xbfmb\xf7\xd6\xeb\x1dj\xfb\x98\x99r\xfd\x1a\xf1\xcapv\xde\xa4M\\x\xe8fV\x95F\xe3\xdf]+\xc8f4?\xbc_\x01b\x8a\xb3 =\xb3\xf3~P\x7fv\x97\x02\xeaG\xef\xb4@\xc4\xc2\xfdf\xa8\x87\xcd\xef\x19)\xb1\x15\xc8j\xcd\xb4\xbb3\x1cU\xcd\x7f\xb1\x02\xeb|\x14\x82\xf8+\xf4o@\x85\xe6S\x8c\xcdw\x93\xb6\x96\x03\xce\xfd\xbd&\xeeH\xc0\xc0\x8e\x9e#\xc5\xb4\xa3\x81X\xb0h\xb7\xaflQQ\xad\xf0B\xcd\xc7\x05\xb4\xe48\xbc}g\x92q\xe2+\x9b\x11\x0b3/G\x12\xc8\x935\xf1\x1e\xaf\xcc\x890\xe5uX\xea\xe1c\t\x92ikP\xcd\xcfBj\xd4\x96\x8a\xbc:\xe8\xba}f\xcb\xef\xa4[\xecO\xcd\xc3\x0c.\r\x13\x1c\x00\x9b\x1a\x8dcZ\xbc\x10C\xe0)\x1e\xa0\xdc\x17\xbe:5\xd2\x11\xf4j\xa0\x08\xd6\xdfE\xdd\x92\x82\xbd\x88\xe9\xff\xc6\xed\xd5\x9e\xd3\xdf\xc2T\xf4\x0eR\xb3\xd2\xfd^L_\x94\x04\xaf\xaf\x00\n"R\xf4\xcb#bS^g/e4\xc5\xff\x90\xc2P\xfe-9\x1b\xc2\xa4?\xdd\xda\x96V\xb20c"\xecQ\xcb\xb2vl\x8e;\xc0\xb2\'\xccY\xe14[\xf30\x00\x9f\xd8\x95\xb9\xffw\x91>\x0eD\xca\xe7\x11J=\xac\x0c\x8b\xf7ouANThB\x11\xdd8OK\x01\xa2\x0bV\xcbU\xc4zt/\xaf\xed\xfb\x06\x069SJ\xc2\xdbA\x8a\xac\xe5~\xe7\xea\xa6\xf6\xcbo&\x1c\xa9\x0b\x1d2H\xa7\xc4\x87\x0b\xad\xda\xa9\x15\xe1\xc8V\x94]\xe9\xc9e\xe7\n\xb9\xa9\xb2\xc1=~\xb5\xd9\xce^k\xb2\xb3\x02\xd0\xaa\x9f\x1dc\xbd~F\xd3\xfa\x0e\xe7\x96Z\x95\x0eD\x07\x8a\xc7\xd7f\x06{\x9141\x0eI\xd43\xff\x81\x86'], size: 512 B
    I: comments will be shown as [None]
D3. Output (encrypted) file: random2.bin
    D: opening file 'random2.bin' in mode 'xb'
    D: opened file object: <_io.BufferedWriter name='random2.bin'>
    D: real path: '/tmp/test/random2.bin'
    I: new empty file 'random2.bin' created
    D: getting salts
    D: salts:
        argon2_salt:  225b9b35006770986736a51e6d0491d3
        blake2_salt:  c26e5f12f50527ddcdef4daa6a620bae
    D: getting salts completed
    D: collecting IKM
K1. Keyfile path (optional):
    W: entered passphrases will be displayed!
K2. Passphrase (optional):
    D: passphrase (raw):
        'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase (normalized):
        'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase (normalized, encoded, truncated):
        b'Correct Horse Battery Staple'
    D: length: 28 B
K2. Confirm passphrase:
    D: passphrase (raw):
        'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase (normalized):
        'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase (normalized, encoded, truncated):
        b'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase digest:
        91f0c14336a4f4adf352983320b7e75856384feacd5a7f02c83793a29088829af872cc586ca4ccb0e7bdaab9715391dcbc7073d060825fdea8ca56e4a9c571fa
    I: passphrase accepted
K2. Passphrase (optional):
    D: collecting IKM completed
    D: 1 IKM digests collected
    D: sorting IKM digests
    D: sorted IKM digests:
      - 91f0c14336a4f4adf352983320b7e75856384feacd5a7f02c83793a29088829af872cc586ca4ccb0e7bdaab9715391dcbc7073d060825fdea8ca56e4a9c571fa
    D: hashing digest list
    D: list containing 1 digests hashed
    D: argon2_password:
        ca900dee8f793e7fd01afbcf2bd6117ebc3e3bae1b6c8b45278d9f864a16a792abe564e5acf636873f38f8c85e3d3cd8fc56435bee8e20c17117002322d49093
    I: deriving one-time keys
    D: argon2_tag:
        9bdf785386c9f851112718e3e97907eace69628ee5b630a275bea2cac1e21dc15475b0bfbeabeed0fb8681f7d916a06ae92e50861fd6374132409c75f747f6523a9133f1fdd95940a18cd66bef04bf1fd3a6f66ee68325d291aba1a204b738d333da576f8f5caa64b892ae73a15fe60c9594ab1c26fd1f67f5dcaf58e396ed32 (128 B)
    D: splitting argon2_tag into separate keys
    D: derived keys:
        pad_key_t:  9bdf785386c9f8511127 (10 B)
        pad_key_s:  18e3e97907eace69628e (10 B)
        nonce_key:  e5b630a275bea2cac1e21dc1 (12 B)
        enc_key:    5475b0bfbeabeed0fb8681f7d916a06ae92e50861fd6374132409c75f747f652 (32 B)
        mac_key:    3a9133f1fdd95940a18cd66bef04bf1fd3a6f66ee68325d291aba1a204b738d333da576f8f5caa64b892ae73a15fe60c9594ab1c26fd1f67f5dcaf58e396ed32 (64 B)
    I: keys derived in 6.9s
    D: nonce counter initialized to 59766736573936599630041102053
    D: MAC hash object initialized
    D: getting randomized_pad_size
    D: pad_key_t_int:                184491794173659285348251
    D: pad_key_t_int/PAD_KEY_SPACE:  0.1526080353155746
    D: constant_padded_size:     1,000,863 B (977.4 KiB)
    D: max_randomized_pad_size:  200,172 B (195.5 KiB)
    D: randomized_pad_size:      30,547 B (29.8 KiB), 3.1% of constant_padded_size, 15.3% of max_randomized_pad_size
    D: total_padded_size:        1,031,410 B (1007.2 KiB)
    D: splitting total_pad_size: getting header_pad_size and footer_pad_size
    D: pad_key_s_int:    672391445775250172273432
    D: header_pad_size:  13,050 B (12.7 KiB), 42.4% of total_pad_size
    D: footer_pad_size:  17,752 B (17.3 KiB), 57.6% of total_pad_size
    D: total_padded_size_bytes:  f2bc0f0000000000
    D: header_pad_size_bytes:    fa32000000000000
    D: footer_pad_size_bytes:    5845000000000000
    D: MAC updated with 16 B chunk
    D: MAC updated with 16 B chunk
    D: MAC updated with 8 B chunk
    D: MAC updated with 8 B chunk
    D: MAC updated with 8 B chunk
    D: calculating additional sizes
    D: payload file contents size:  1,000,000 B (976.6 KiB)
    D: output data size:            1,031,410 B (1007.2 KiB)
    I: reading plaintext, writing cryptoblob
    D: writing argon2_salt
    D: written 16 B to <_io.BufferedWriter name='random2.bin'>; position moved from 0 to 16
    D: argon2_salt written
    D: handling header padding
    D: written 13,050 B (12.7 KiB) to <_io.BufferedWriter name='random2.bin'>; position moved from 16 to 13,066
    D: handling header padding completed
    D: handling comments
    D: nonce counter incremented to 59766736573936599630041102054
    D: data chunk encrypted/decrypted:
        chunk size:  512 B
        nonce used:  e6b630a275bea2cac1e21dc1
    D: MAC updated with 512 B chunk
    D: written 512 B to <_io.BufferedWriter name='random2.bin'>; position moved from 13,066 to 13,578
    D: handling comments completed
    D: handling payload file contents
    D: read 1,000,000 B (976.6 KiB) from <_io.BufferedReader name='secret.zip'>; position moved from 0 to 1,000,000
    D: nonce counter incremented to 59766736573936599630041102055
    D: data chunk encrypted/decrypted:
        chunk size:  1,000,000 B (976.6 KiB)
        nonce used:  e7b630a275bea2cac1e21dc1
    D: written 1,000,000 B (976.6 KiB) to <_io.BufferedWriter name='random2.bin'>; position moved from 13,578 to 1,013,578
    D: MAC updated with 1,000,000 B (976.6 KiB) chunk
    D: handling payload file contents completed
    D: encryption completed
    D: total encrypted with ChaCha20: 2 chunks, 1,000,512 B (977.1 KiB)
    D: handling MAC tag
    D: computed MAC tag:
        db0f7cce74a5d03da3543fd0cfcb1ac283e0d385474305213468f9ee922d300ca69ccf4d43b9dd33fe8a7cca23736faffe3e755e070487baf154c4247fdb7acb
    D: fake MAC tag:
        0404cc1705a12d738c7691444c413a7861906b5cd35665d270600af5ba0492cddfd1e5a3d74a9a147b50dd288bf1f512f0e542bb640ec1e8b9761a1ba6ad8927
    D: MAC tag to write:
        db0f7cce74a5d03da3543fd0cfcb1ac283e0d385474305213468f9ee922d300ca69ccf4d43b9dd33fe8a7cca23736faffe3e755e070487baf154c4247fdb7acb
    D: written 64 B to <_io.BufferedWriter name='random2.bin'>; position moved from 1,013,578 to 1,013,642
    D: MAC tag written
    D: MAC message size handled: 1,000,568 B (977.1 KiB)
    D: handling MAC tag completed
    D: handling footer padding
    D: written 17,752 B (17.3 KiB) to <_io.BufferedWriter name='random2.bin'>; position moved from 1,013,642 to 1,031,394
    D: handling footer padding completed
    D: writing blake2_salt
    D: written 16 B to <_io.BufferedWriter name='random2.bin'>; position moved from 1,031,394 to 1,031,410
    D: blake2_salt written
    I: written 100.0%; 1007.2 KiB in 0.0s; avg 30.6 MiB/s
    I: writing completed; total of 1,031,410 B written
    I: location of padding in output file (may be ignored):
        [16:13066] — 13,050 B (12.7 KiB)
        [1013642:1031394] — 17,752 B (17.3 KiB)
    D: closing <_io.BufferedReader name='secret.zip'>
    D: <_io.BufferedReader name='secret.zip'> closed
    D: closing <_io.BufferedWriter name='random2.bin'>
    D: <_io.BufferedWriter name='random2.bin'> closed
    I: action completed
```

</details>

---

## Encrypting a File and Comments with Passwords and Keyfiles

#### 1. Select option (action) 2

```
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

#### 2. Skip custom settings

Just press Enter:

```
C0. Use custom settings? (Y/N, default=N):
    I: use custom settings: False
```

#### 3. Enter input file path

Enter the path to the file that should be encrypted and press Enter:

```
D1. File to encrypt: secret.zip
    I: path: 'secret.zip'; size: 1,000,000 B (976.6 KiB)
```

#### 4. Enter Comments

Enter an arbitrary comment. If the size of the comment exceeds 512 bytes, it will be truncated. This comment will be displayed during the decryption.

```
D2. Comments (optional, up to 512 B): secret files, zip
    I: comments will be shown as ['secret files, zip']
```

#### 5. Enter ouput file path

```
D3. Output (encrypted) file: random2.bin
    I: new empty file 'random2.bin' created
```

#### 6. Enter keyfile path

Enter the path to the keyfile and press Enter. It is acceptable to specify multiple keyfiles, one after another.

```
K1. Keyfile path (optional): key
    I: path: 'key'; size: 32 B
    I: reading and hashing contents of 'key'
    I: keyfile accepted
K1. Keyfile path (optional):
```

#### 7. Specify passphrase

Enter the password, press Enter, and repeat the input.
When prompted for the new password again, just press Enter.

```
K2. Passphrase (optional):
K2. Confirm passphrase:
    I: passphrase accepted
K2. Passphrase (optional):
```

#### Then action will be completed

Key derivation will occur from the specified password and generated salts.

```
    I: deriving one-time keys
    I: keys derived in 3.4s
```

The contents of the input file will be read in chunks of 16 MiB, encrypted, and a cryptoblob will be formed containing the ciphertext and MAC tag, surrounded by random data.

```
    I: reading plaintext, writing cryptoblob
    I: written 100.0%; 1010.8 KiB in 0.1s; avg 14.4 MiB/s
    I: writing completed; total of 1,035,028 B written
```

The location of the padding within the cryptoblob will be displayed:

```
    I: location of padding in output file (may be ignored):
        [16:417] — 401 B
        [1000993:1035012] — 34,019 B (33.2 KiB)
```

Upon successful completion of the action, you will see "action completed":

```
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
A0. Select an option [0-9]: 2
    I: action #2:
        encrypt file contents and comments;
        write cryptoblob to new file
C0. Use custom settings? (Y/N, default=N):
    I: use custom settings: False
D1. File to encrypt: secret.zip
    I: path: 'secret.zip'; size: 1,000,000 B (976.6 KiB)

D2. Comments (optional, up to 512 B): secret files, zip
    I: comments will be shown as ['secret files, zip']

D3. Output (encrypted) file: random2.bin
    I: new empty file 'random2.bin' created
K1. Keyfile path (optional): key
    I: path: 'key'; size: 32 B
    I: reading and hashing contents of 'key'
    I: keyfile accepted
K1. Keyfile path (optional):
K2. Passphrase (optional):
K2. Confirm passphrase:
    I: passphrase accepted
K2. Passphrase (optional):
    I: deriving one-time keys
    I: keys derived in 3.4s
    I: reading plaintext, writing cryptoblob
    I: written 100.0%; 1010.8 KiB in 0.1s; avg 14.4 MiB/s
    I: writing completed; total of 1,035,028 B written
    I: location of padding in output file (may be ignored):
        [16:417] — 401 B
        [1000993:1035012] — 34,019 B (33.2 KiB)
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
A0. Select an option [0-9]: 2
    I: action #2:
        encrypt file contents and comments;
        write cryptoblob to new file
    W: debug mode enabled! Sensitive data will be exposed!
C0. Use custom settings? (Y/N, default=N):
    I: use custom settings: False
    D: time cost: 4
    D: max padding size, %: 20
    D: set fake MAC tag: False
D1. File to encrypt: secret.zip
    D: real path: '/tmpfs/test/secret.zip'
    D: opening file 'secret.zip' in mode 'rb'
    D: opened file object: <_io.BufferedReader name='secret.zip'>
    I: path: 'secret.zip'; size: 1,000,000 B (976.6 KiB)
    D: constant_padded_size:     1,000,863 B (977.4 KiB)
    D: max_randomized_pad_size:  200,172 B (195.5 KiB)
    D: max_total_padded_size:    1,201,035 B (1.1 MiB)
D2. Comments (optional, up to 512 B): secret files, zip
    D: raw_comments: ['secret files, zip'], size: 17 B
    D: processed_comments: [b'secret files, zip\xffi\xc2s\xe5%\xd3\x8fe\xfb \x01P\x8b\x814s\xa1y7\\a\xfd/\xa0\x10\x18/\x8d\xf2\x07\x1a\xe5\xb9G~[\xe1J!\xbc\xf3\x92&\xdc\x94\xe4m\xcf\x8a\xd7`d\xba\xc3X\x85\x95\x1f\xcaI\xe5\x81;\x19\x88\x1a\x87#\xf7\xc4\xaaS,\xbd&Uq\xb0\xba\x1b\xc1\x9d\xc0\xfc\xb4n8\xf9L\xec\xe1\x80\xe7\xafr\xbb\xcb\xe7:\x95>\t\xd6={y\x92P\xb3@"\xec8\x02\xc7 \x98p\xbd\x85\x1ci\xf6\xf8\xe1T\x00\xe1\x10*\xf20\x15\xcd\x83\x01\xb3V\xb9\xc6Fe~\xab\x88s\xedL\xea< \xb0^Q\x807\xc59\xfcN(\xb3\xf7\xd1L\x1d1\xf7\xc9\x95\xde\xb0Y\xdcp(\xf0\xdf\x11\x02<K\xbc%\xf8\xa6%\x9d\xd3\xcb\xe0\xaf|\xde7\xd9\xeaI\x88\xd4\xa4HH\x81\x8fa\xaf\x17\x1d\x1a\xc3Z\xad\x1c\xde\x90\xac\x94\xe1\xe3\xb5J\x0b\xa9\x80V\x8e\xde\x80ye\x10\xc3\xae0\x9e\x91\xf2g\x07\x9dB\xd9\xaa\x8e\xe0\xb9\x17\x02\xeb\x14\xea\xc4G\x035P\x8f7\xda\xda\xae\x98*\xdeE\xe0\xbebF\xe75\x17\x8a7 \xf9\xc9\xea \x0f\xce\xb2zo\x85{\x90\xbb\xd2\xb8\xf8\xeb\xdc\xf3\x19\x8b\x8e\xae(\x12\x0c\xdc\xc1=\x83~\xf9e\x98\xb9\xe1\xc8\x82B\x00\xf9\x0cc\xff\n\xa7\xfd\x8b\xf3\xbb;{R-\xb8!\x13;k\xf7\xed\xd1=\xd2k\x8a\x029N\x0eSL\x89&\x9a\x00\x9e\'\xb6\xf8b\xaf.\xb7\xd9\xf9\xda\x8e\xb08Wb)|\x05.\xdf\xcb\x16\x8b\xc0%\x91\xc2#yN\xcd\x8bu\xee\xdc\xa8\x8f\xc2I,*O\xefV"x!\x90\xe0v\\GT\xf0\xd5\x05sd\xf3\xe6\xe7\xde\xdf\xc3#\xc4\xa5X\x05\xe5FJ\xd4\xffO\x02Q\xe8w\x80H7`\xbc;\x8aPD\xa4\xe1\x8d{\xba\xba\xc6\x03\xe1\x02\xbc\xa0 DN\xeb|\xd1\\m\xe5\\\xb2r\xf9NT7\xc8\xbeG\xdf7\xe0\x8c\xd6\x9ed\xe8`\xa4\x8bb\x8eX\xdd=\xd9\x0bI\xa9D\xc6'], size: 512 B
    I: comments will be shown as ['secret files, zip']
D3. Output (encrypted) file: random.bin
    D: opening file 'random.bin' in mode 'xb'
    D: opened file object: <_io.BufferedWriter name='random.bin'>
    D: real path: '/tmpfs/test/random.bin'
    I: new empty file 'random.bin' created
    D: getting salts
    D: salts:
        argon2_salt:  cbe5234bf06e1c15d15a32e268a48e80
        blake2_salt:  6bbef7fcde3c8b5654919c852222a391
    D: getting salts completed
    D: collecting IKM
K1. Keyfile path (optional): key
    D: real path: '/tmpfs/test/key'
    I: path: 'key'; size: 32 B
    I: reading and hashing contents of 'key'
    D: opening file 'key' in mode 'rb'
    D: opened file object: <_io.BufferedReader name='key'>
    D: read 32 B from <_io.BufferedReader name='key'>; position moved from 0 to 32
    D: closing <_io.BufferedReader name='key'>
    D: <_io.BufferedReader name='key'> closed
    D: digest of 'key' contents:
        62a0a243ec92416b41d8772b3f7bed20496882a98b20f68d06f73f99b2684566e8fc039a56506c2819b6a1275a2c860e0ee7d5e8a752b6f829d30b12ad29b41e
    I: keyfile accepted
K1. Keyfile path (optional):
    W: entered passphrases will be displayed!
K2. Passphrase (optional):
    D: passphrase (raw):
        'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase (normalized):
        'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase (normalized, encoded, truncated):
        b'Correct Horse Battery Staple'
    D: length: 28 B
K2. Confirm passphrase:
    D: passphrase (raw):
        'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase (normalized):
        'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase (normalized, encoded, truncated):
        b'Correct Horse Battery Staple'
    D: length: 28 B
    D: passphrase digest:
        780f1e159b5a60e5f794c45756c932656f2c0e698f68cee2fa3e1830417487ffd9034501fc08d67cd57714e163a82447f4337337d7fd059f78a27f0d79a7ede9
    I: passphrase accepted
K2. Passphrase (optional):
    D: collecting IKM completed
    D: 2 IKM digests collected
    D: sorting IKM digests
    D: sorted IKM digests:
      - 62a0a243ec92416b41d8772b3f7bed20496882a98b20f68d06f73f99b2684566e8fc039a56506c2819b6a1275a2c860e0ee7d5e8a752b6f829d30b12ad29b41e
      - 780f1e159b5a60e5f794c45756c932656f2c0e698f68cee2fa3e1830417487ffd9034501fc08d67cd57714e163a82447f4337337d7fd059f78a27f0d79a7ede9
    D: hashing digest list
    D: list containing 2 digests hashed
    D: argon2_password:
        0979a1b75dd777310c1b12ca287b075b7c839c9ca36ec9558ddba64b9e8b827cd823023cedae3958b034d301ae0e26dfbb8d26592bf3a247bca5245ec02b05f4
    I: deriving one-time keys
    D: argon2_tag:
        c3e3db30326a7c2eb6359255717a48714e3e8d9dbd372f7143842dc9cffd201494a38c02d260d7c9662e59eab5b25280843c9994e1ac7b65d7d93a5d96f1e169fb7fefb17a4a8de3c2a323400520b6a6be6e5911f0e8bf82979e108fab5a40b0a5c64ca35188fbe223683fcd2eb8dba040f860159e2f19d294a467b5a36a1fa1 (128 B)
    D: splitting argon2_tag into separate keys
    D: derived keys:
        pad_key_t:  c3e3db30326a7c2eb635 (10 B)
        pad_key_s:  9255717a48714e3e8d9d (10 B)
        nonce_key:  bd372f7143842dc9cffd2014 (12 B)
        enc_key:    94a38c02d260d7c9662e59eab5b25280843c9994e1ac7b65d7d93a5d96f1e169 (32 B)
        mac_key:    fb7fefb17a4a8de3c2a323400520b6a6be6e5911f0e8bf82979e108fab5a40b0a5c64ca35188fbe223683fcd2eb8dba040f860159e2f19d294a467b5a36a1fa1 (64 B)
    I: keys derived in 3.6s
    D: nonce counter initialized to 6229584414347146986974558141
    D: MAC hash object initialized
    D: getting randomized_pad_size
    D: pad_key_t_int:                253646080682492992152515
    D: pad_key_t_int/PAD_KEY_SPACE:  0.20981112039061922
    D: constant_padded_size:     1,000,863 B (977.4 KiB)
    D: max_randomized_pad_size:  200,172 B (195.5 KiB)
    D: randomized_pad_size:      41,998 B (41.0 KiB), 4.2% of constant_padded_size, 21.0% of max_randomized_pad_size
    D: total_padded_size:        1,042,861 B (1018.4 KiB)
    D: splitting total_pad_size: getting header_pad_size and footer_pad_size
    D: pad_key_s_int:    744017018375361986123154
    D: header_pad_size:  21,204 B (20.7 KiB), 50.2% of total_pad_size
    D: footer_pad_size:  21,049 B (20.6 KiB), 49.8% of total_pad_size
    D: total_padded_size_bytes:  ade90f0000000000
    D: header_pad_size_bytes:    d452000000000000
    D: footer_pad_size_bytes:    3952000000000000
    D: MAC updated with 16 B chunk
    D: MAC updated with 16 B chunk
    D: MAC updated with 8 B chunk
    D: MAC updated with 8 B chunk
    D: MAC updated with 8 B chunk
    D: calculating additional sizes
    D: payload file contents size:  1,000,000 B (976.6 KiB)
    D: output data size:            1,042,861 B (1018.4 KiB)
    I: reading plaintext, writing cryptoblob
    D: writing argon2_salt
    D: written 16 B to <_io.BufferedWriter name='random.bin'>; position moved from 0 to 16
    D: argon2_salt written
    D: handling header padding
    D: written 21,204 B (20.7 KiB) to <_io.BufferedWriter name='random.bin'>; position moved from 16 to 21,220
    D: handling header padding completed
    D: handling comments
    D: nonce counter incremented to 6229584414347146986974558142
    D: data chunk encrypted/decrypted:
        chunk size:  512 B
        nonce used:  be372f7143842dc9cffd2014
    D: MAC updated with 512 B chunk
    D: written 512 B to <_io.BufferedWriter name='random.bin'>; position moved from 21,220 to 21,732
    D: handling comments completed
    D: handling payload file contents
    D: read 1,000,000 B (976.6 KiB) from <_io.BufferedReader name='secret.zip'>; position moved from 0 to 1,000,000
    D: nonce counter incremented to 6229584414347146986974558143
    D: data chunk encrypted/decrypted:
        chunk size:  1,000,000 B (976.6 KiB)
        nonce used:  bf372f7143842dc9cffd2014
    D: written 1,000,000 B (976.6 KiB) to <_io.BufferedWriter name='random.bin'>; position moved from 21,732 to 1,021,732
    D: MAC updated with 1,000,000 B (976.6 KiB) chunk
    D: handling payload file contents completed
    D: encryption completed
    D: total encrypted with ChaCha20: 2 chunks, 1,000,512 B (977.1 KiB)
    D: handling MAC tag
    D: computed MAC tag:
        a891e03d3505085a03a68c1bcc4673a4857091df5f7aee9d44d43f2629071c8fca5ed122c4d618f058f72c0e9436482d5aab373445ea88ebf351c35badb705e4
    D: fake MAC tag:
        23536bbd0a65c05240db486a2354ef7972fccc6a8ecdb11675979bb547bc261f021fdcf2546cd5f2ef6bd85f294a1c61f9eeeb0692837563f3c79275cbac21a3
    D: MAC tag to write:
        a891e03d3505085a03a68c1bcc4673a4857091df5f7aee9d44d43f2629071c8fca5ed122c4d618f058f72c0e9436482d5aab373445ea88ebf351c35badb705e4
    D: written 64 B to <_io.BufferedWriter name='random.bin'>; position moved from 1,021,732 to 1,021,796
    D: MAC tag written
    D: MAC message size handled: 1,000,568 B (977.1 KiB)
    D: handling MAC tag completed
    D: handling footer padding
    D: written 21,049 B (20.6 KiB) to <_io.BufferedWriter name='random.bin'>; position moved from 1,021,796 to 1,042,845
    D: handling footer padding completed
    D: writing blake2_salt
    D: written 16 B to <_io.BufferedWriter name='random.bin'>; position moved from 1,042,845 to 1,042,861
    D: blake2_salt written
    I: written 100.0%; 1018.4 KiB in 0.1s; avg 15.3 MiB/s
    I: writing completed; total of 1,042,861 B written
    I: location of padding in output file (may be ignored):
        [16:21220] — 21,204 B (20.7 KiB)
        [1021796:1042845] — 21,049 B (20.6 KiB)
    D: closing <_io.BufferedReader name='secret.zip'>
    D: <_io.BufferedReader name='secret.zip'> closed
    D: closing <_io.BufferedWriter name='random.bin'>
    D: <_io.BufferedWriter name='random.bin'> closed
    I: action completed
```

</details>

---

## Encrypting a File with Custom Options


