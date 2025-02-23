
<h4 align="left">
  <a href="https://github.com/hakavlad/tird">🏠&nbsp;Homepage</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">📜&nbsp;man&nbsp;page</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">📑&nbsp;Specification</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">📄&nbsp;Input&nbsp;Options</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">📖&nbsp;Tutorial</a> &nbsp;
  <a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">❓&nbsp;FAQ</a>
</h4>

---

# Draft Specification

- Conventions used in this document
- Encrypted file format
- Payload
  - Comments
  - File contents
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

`||` denotes concatenation.
`=` denotes assignment.
`,` denotes separate parameters.
`0x` followed by two hexadecimal characters denotes a byte value in the 0-255 range.
`++` denotes incremented by one in little-endian.

---

## Encrypted file format

Cryptoblob structure:

```
                  512 B        0+ B
              +——————————+———————————————+
              | Comments | File contents |
              +——————————+———————————————+
  16 B   0+ B |        Plaintext         |  64 B     0+ B   16 B
+——————+——————+——————————————————————————+—————————+——————+——————+
| Salt | Pad  |       Ciphertext         | MAC tag | Pad  | Salt |
+——————+——————+——————————————————————————+—————————+——————+——————+
| Random data |     Random-looking data            | Random data |
+—————————————+————————————————————————————————————+—————————————+
```

Alternative scheme:

```
+——————————————————————————————+—————————+
| Header salt: 16 B, 2 parts:  |         |
| BLAKE2b salt[:8] +           |         |
| Argon2 salt[:8]              | Random  |
+——————————————————————————————+ data    |
| Randomized padding: 0-20%    |         |
| of the ciphertext size       |         |
| by default                   |         |
+——————————————————————————————+—————————+
| Ciphertext: 512+ B, consists |         |
| of encrypted padded comments |         |
| (always 512 B) and encrypted | Random- |
| payload file contents (0+ B) | looking |
+——————————————————————————————+ data    |
| MAC tag: 64 B                |         |
+——————————————————————————————+—————————+
| Randomized padding: 0-20%    |         |
| of the ciphertext size       |         |
| by default                   | Random  |
+——————————————————————————————+ data    |
| Footer salt: 16 B, 2 parts:  |         |
| BLAKE2b salt[-8:] +          |         |
| Argon2 salt[-8:]             |         |
+——————————————————————————————+—————————+
```

```
cryptoblob = header_salt || header_pad || ciphertext || MAC tag || footer_pad || footer_salt
```

---

## Payload

Payload consists of Comments up to 512 bytes and File contents from 0 bytes.

### Comments

User can add comments to encrypt it with a cryptoblob.

`0xFF` is used as a marker to separate user-entered comments from random data.

```
comments_bytes = (comments || 0xFF || random data)[:512]
```

### Payload file contents

The payload file could be:

- regular file;
- block device.

---

## Input keying material

`tird` can use passhrases and contents of keyfiles to derive one-time keys.

### Keyfiles

User can specify none, one or multiple keyfile paths.

### Passphrases

User can specify none, one or multiple passphrases.

---

## Salt

Creating `blake2_salt` and `argon2_salt`:

```
blake2_salt = urandom(16)
argon2_salt = urandom(16)
```

Separating salts into `header_salt` and `footer_salt` to write the `header_salt` at the beginning of the cryptoblob, and the `footer_salt` at the end of the cryptoblob:

```
header_salt = blake2_salt[:8] || argon2_salt[:8]
footer_salt = blake2_salt[-8:] || argon2_salt[-8:]
```

When decrypting a cryptoblob, the `header_salt` and the `footer_salt` are read from the beginning and end of the cryptoblob and converted back to `blake2_salt` and `argon2_salt`:

```
header_salt = cryptoblob[:16]
footer_salt = cryptoblob[-16:]

blake2_salt = header_salt[:8] || footer_salt[:8]
argon2_salt = header_salt[-8:] || footer_salt[-8:]
```

---

## Key derivation scheme

How to get one-time keys (encryption key, padding key, MAC key) from input keying material and salt.

```
passphrase  keyfile1  keyfile2  <-- input keying material (IKM)
    |          |         |
    |          |         |  <------ salted and personalized BLAKE2b-512
    v          v         v
passphrase  keyfile1  keyfile2  <-- IKM digests
digest:64  digest:64  digest:64
        \      |      /
         v     v     v
         [digest list]
               |
               |  <------------- sorting digests for entering keys in any order
               v
      [sorted digest list]
               |
               |  <------------- hashing sorted digests with salted BLAKE2b-512
               v
      Argon2 password (64 B)
               |                 +------------------------------------------+
               |  <--------------| salted Argon2id:                         |
               v                 | 1 lane, 512 MiB, 4 iterations by default |
       Argon2 tag (128 B)        +------------------------------------------+
               |
               |  <-- enc_key || pad_key || mac_key = argon2_tag
               v
   +-------------------+---------------------+
   |                   |                     |
   v                   v                     v
encryption key    padding key               MAC key
   |              |         |                |
   v              v         v                v
ChaCha20    pad_key1:16  pad_key2:16   keyed BLAKE2b-512
              /                 \
    defines total       defines proportions between
      pad size           header_pad and footer_pad
```

---

## Keys utilization

### Padding

### Encryption

`tird` uses ChaCha20 from \[[RFC 7539](https://www.rfc-editor.org/rfc/rfc7539)] with a counter nonce to encrypt a payload.

256-bit encryption key is from Argon2 output.

96-bit nonce is bytes in little-endian from a counter.

|Counter|nonce|Data to encrypt|
|-|-|-|
|1|`0x010000000000000000000000`|Comments, 512 B|
|2|`0x020000000000000000000000`|File contents chunk0, 128 KiB|
|3|`0x030000000000000000000000`|File contents chunk1, 128 KiB|
|4|`0x040000000000000000000000`|File contents chunk2, 128 KiB|
|5|`0x050000000000000000000000`|File contents chunk3, 0-128 KiB|

Decryption never fails.

### MAC

```
MAC message = salt_header || salt_footer || ciphertext
```

```
MAC tag = BLAKE2b-512(MAC message, MAC key)
```

```
Fake MAC tag = urandom(64)
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

Create a new file and write random data with chunks up to 128 KiB.

```
output file contents = urandom(size)
```

---

## Overwriting file contents with random data

Owerwrite file contents with random data from the start position to the end position.

Use chunks up to 128 KiB.

```
0       start         end
|       |             |
+-------+-------------+-----+
|       | random data |     |
+-------+-------------+-----+
```

---

## Test vectors
