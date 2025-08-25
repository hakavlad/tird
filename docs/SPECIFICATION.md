
<h4 align="left">
  🏠&nbsp;<a href="https://github.com/hakavlad/tird">Homepage</a> &nbsp;
  📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">man&nbsp;page</a> &nbsp;
  📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a> &nbsp;
  📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a> &nbsp;
  📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial</a> &nbsp;
  ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ</a> &nbsp;
  📥&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INSTALLATION.md">Installation</a>
</h4>

---

# \[WIP] Draft Specification

- Conventions used in this document
- Payload
  - Comments
  - File contents
- Encrypted data format
- IKM
  - Keyfiles
  - Passphrases
- Salt
- Key derivation scheme
- Keys utilization
  - Padding
  - Encryption
  - MAC
- Layer cake: embed and extract
  - Just embed and extract (no encryption)
  - Encrypt & embed, Extract & decrypt
- Creating files with random data
- Overwriting file contents with random data
- Test vectors

---

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) \[[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)] \[[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)] when, and only when, they appear in all capitals, as shown here.

- `||` denotes byte string concatenation.
- `=` denotes assignment.
- `,` separates function parameters or list items.
- `0x` prefix denotes a byte value in hexadecimal representation (e.g., `0xFF`).
- `[N:M]` denotes a byte string slice from index N (inclusive) to M (exclusive).
- `++` denotes counter increment (increase by 1).
- `CSPRNG` denotes a Cryptographically Secure Pseudo-Random Number Generator (in `tird`, this is `secrets.token_bytes`).
- `KiB`, `MiB`, `GiB` denote kibibytes, mebibytes, and gibibytes, respectively.
- Byte order (endianness) for converting numbers to bytes and vice-versa is `little-endian`.

---

## Payload

Payload consists of Comments up to 512 bytes and File contents from 0 bytes.

### Comments

- The user MAY provide an optional comment as a UTF-8 string.
- The comment string is encoded into UTF-8 bytes.
- A separator byte `0xFF` is appended to the encoded comments.
- Random data (`CSPRNG`) is appended to the result.
- The final byte string is **truncated** to a fixed size of `PROCESSED_COMMENTS_SIZE = 512` bytes. If the original comment (after UTF-8 encoding) is longer than 512 bytes, it will be truncated.
```
raw_comments_bytes = encode_utf8(user_comment)

processed_comments = (raw_comments_bytes || 0xFF || read(CSPRNG, PROCESSED_COMMENTS_SIZE))[:PROCESSED_COMMENTS_SIZE]
```
- If no comment is provided, `processed_comments` are generated in a special way (see `get_processed_comments` code) to minimize the chance of accidentally matching a valid comment structure, if the "fake MAC" option is *not* used. If "fake MAC" is used, `processed_comments` are simply filled with random bytes `read(CSPRNG, PROCESSED_COMMENTS_SIZE)`.

### Payload file contents

- The main content for encryption/decryption or embedding/extraction.
- Can be the contents of a regular file or a block device.
- The size of the file contents can range from 0 bytes up to 2^64-832 bytes.

---

## Encrypted data format

Cryptoblob structure:

```
+————————————————————————————————————————————————————+
| CSPRNG output:                                     |
|     Salt for key stretching used with Argon2, 16 B |
+————————————————————————————————————————————————————+
| CSPRNG output:                                     |
|     Randomized padding (header padding): 0-20% of  |
|     the (unpadded size + 255 B) by default         |
+————————————————————————————————————————————————————+
| ChaCha20 output:                                   |
|     Ciphertext, 512+ B, consists of:               |
|     - Encrypted constant-padded comments, 512 B    |
|     - Encrypted payload file contents, 0+ B        |
+————————————————————————————————————————————————————+
| BLAKE2 or CSPRNG output:                           |
|     MAC tag or Fake MAC tag, 32 B                  |
+————————————————————————————————————————————————————+
| CSPRNG output:                                     |
|     Randomized padding (footer padding): 0-20% of  |
|     the (unpadded size + 255 B) by default         |
+————————————————————————————————————————————————————+
| CSPRNG output:                                     |
|     Salt for prehashing IKM used with BLAKE2, 16 B |
+————————————————————————————————————————————————————+
```

```
argon2_salt || header_pad || ciphertext || (computed_mac_tag|fake_mac_tag) || footer_pad || blake2_salt
```

- `argon2_salt`: Random salt for the Argon2id key derivation function.
- `header_pad`:
- `ciphertext`:
- `computed_mac_tag`:
- `fake_mac_tag`:
- `footer_pad`:
- `blake2_salt`: Random salt used during IKM hashing and for the final IKM digest list hashing with BLAKE2b.

---

## Input keying material

`tird` can use passhrases and contents of keyfiles to derive one-time keys.

### Keyfiles

User can specify none, one or multiple keyfile paths.

### Passphrases

User can specify none, one or multiple passphrases.

---

## Salt

Two 16-byte salts are used in the process:

1.  `argon2_salt`: Used as the salt for Argon2id.
2.  `blake2_salt`: Used as the salt for hashing IKM (keyfiles, passphrases) and for the final hashing of the IKM digest list with BLAKE2b.

- During encryption (actions 2, 6): Both salts are generated using `CSPRNG`.

```
argon2_salt = read(CSPRNG, 16)

blake2_salt = read(CSPRNG, 16)
```

- During decryption (actions 3, 7): Salts are extracted from the cryptoblob.

```
argon2_salt = cryptoblob[0:16]

blake2_salt = cryptoblob[-16:]
```

---

## Key derivation scheme

There are 5 steps:

1. Collecting and handling keyfiles and passphrases, getting IKM digest list.
2. Sorting IKM digest list, getting sorted IKM digest list.
3. Hashing sorted IKM digest list, getting Argon2 password.
4. Key stretching with Argon2, getting Argon2 tag.
5. Deriving keys for padding, encryption, and authentication from Argon2 tag.


### 1. Collecting and handling keyfiles and passphrases, getting IKM digest list

```
normalized,
encoded,
truncated
passphrase  keyfile1  keyfile2  <-- input keying material (IKM)
    |          |         |
    |          |         |  <------ salted and personalized BLAKE2b-256
    v          v         v
passphrase  keyfile1  keyfile2  <-- IKM digests
digest:32  digest:32  digest:32
        \      |      /
         v     v     v
         [digest list]
```

**How to handle keyfiles:**

1. Read keyfile contents and get its disgest:

```
keyfile_digest = BLAKE2b-256(keyfile_contents, salt = blake2_salt, person = PERSON_KEYFILE)
```

`PERSON_KEYFILE`: the UTF-8 encoding of "KKKKKKKKKKKKKKKK" (`0x4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b`, 16 bytes).

2. Add the digest to `ikm_digest_list`.

**How to handle passphrases:**

1. Get passphrase from user input. It's `raw_passphrase`, an UTF-8 string.

2. Normalize it with NFC. Get `normalized_passphrase`.

3. Encode in bytes and truncate to 2048 bytes. Get `encoded_passphrase`.

4. Confirm passphrase. Compare in constant time.

5. Get passphrase digest:

```
passphrase_digest = BLAKE2b-256(encoded_passphrase, salt = blake2_salt, person = PERSON_PASSPHRASE)
```

`PERSON_PASSPHRASE`: the UTF-8 encoding of "PPPPPPPPPPPPPPPP" (`0x50505050505050505050505050505050`, 16 bytes).

6. Add the digest to `ikm_digest_list`.

### 2. Sorting IKM digest list, getting sorted IKM digest list

Sorts a list of byte sequences (digests) in ascending order based on their byte values.

```
sorted_digest_list = sorted(digest_list)
```

### 3. Hashing sorted IKM digest list, getting Argon2 password

```
argon2_password = BLAKE2b-256(sorted_ikm_digest_list, salt = blake2_salt)
```

### 4. Key stretching with Argon2, getting Argon2 tag

```
argon2_tag = Argon2(password = argon2_password, salt = argon2_salt, params)
```

```
Argon2 params:

Argon2id version number 19 (0x13)
Memory:       1 GiB
Passes:       4 by default
Parallelism:  1 lane
Tag length:   32 bytes
```

Number of passes may be specified by the user.

### 5. Deriving keys for padding, encryption, and authentication from Argon2 tag

```
pad_key_t = HKDF-SHA-256(ikm = argon2_tag, salt = empty, info = "PAD_TOTAL")

pad_key_s = HKDF-SHA-256(ikm = argon2_tag, salt = empty, info = "PAD_SPLIT")

enc_key = HKDF-SHA-256(ikm = argon2_tag, salt = empty, info = "ENCRYPT")

mac_key = HKDF-SHA-256(ikm = argon2_tag, salt = empty, info = "MAC")
```

---

## Keys utilization

### Padding

Relationships between different parts of the padding:

```
+———————————————————+—————————————————————+
| CONSTANT_PAD_SIZE | randomized_pad_size |
+———————————————————+—————————————————————+
|            total_pad_size               |
+———————————————————+—————————————————————+
|  header_pad_size  |  footer_pad_size    |
+———————————————————+—————————————————————+
```

`pad_key_t` ("total") defines `randomized_pad_size`.

`pad_key_s` ("split") defines proportions between `header_pad_size` and `footer_pad_size`.


`randomized_pad_size` in cryptoblob structure:

```
+——————————————————————+—————————————————————+
| constant_padded_size | randomized_pad_size |
+——————————————————————+—————————————————————+
|              total_padded_size             |
+————————————————————————————————————————————+
```

### Encryption

`tird` uses ChaCha20 from \[[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)] with a counter nonce to encrypt payloads:

```
ciphertext chunk = ChaCha20(plaintext chunk, key = enc_key, nonce++)
```

- `enc_key`: A 256-bit encryption key derived with HKDF-SHA-256.
- `nonce`: A 96-bit value, represented as bytes, derived from a counter. Сounter starts at 0, but counter=0 is reserved (first used value is 1).

**Overview of nonce incrementation process:**

|Counter|nonce|Data to encrypt|
|-|-|-|
|0|—|(initial counter value; not used for encryption)|
|1|`0x010000000000000000000000`|Processed comments, size: 512 B|
|2|`0x020000000000000000000000`|File contents chunk 0, size: 16 MiB|
|3|`0x030000000000000000000000`|File contents chunk 1, size: 16 MiB|
|4|`0x040000000000000000000000`|File contents last chunk, size: 1 B to 16 MiB|

### MAC

```
mac_message = argon2_salt || blake2_salt || total_padded_size_bytes || header_pad_size_bytes || footer_pad_size_bytes || ciphertext
```

```
computed_mac_tag = BLAKE2b-256(mac_message, key = mac_key)
```

```
fake_mac_tag = read(CSPRNG, 32)
```

---

## Layer cake: embed and extract

### Embed (no encryption)

Container file format:

```
0    start      end     start      end
|    |          |       |          |
+----+----------+-------+----------+-----+
|    | message1 |       | message2 |     |
+----+----------+-------+----------+-----+
```

Write input file contents over a container file.

### Encrypt and embed

Container file format:

```
0    start         end     start         end
|    |             |       |             |
+----+-------------+-------+-------------+------+
|    | cryptoblob1 |       | cryptoblob2 |      |
+----+-------------+-------+-------------+------+
```

Write a cryptoblob over a container file.

---

## Creating files with random data

Create a new file and write random data with chunks up to 16 MiB.

```
output file contents = read(CSPRNG, size)
```

---

## Overwriting file contents with random data

Overwrite file contents with random data from the start position to the end position.

Use chunks up to 16 MiB.

```
0       start         end
|       |             |
+-------+-------------+-----+
|       | random data |     |
+-------+-------------+-----+
```

---

## Test vectors
