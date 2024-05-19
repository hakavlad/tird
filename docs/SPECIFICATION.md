
# Draft Specification

### Encrypted file format

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
| Salt header: 16 B, 2 parts:  |         |
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
| Salt footer: 16 B, 2 parts:  |         |
| BLAKE2b salt[-8:] +          |         |
| Argon2 salt[-8:]             |         |
+——————————————————————————————+—————————+
```

### Key derivation scheme

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
               |  <-------------- hashing sorted digests with BLAKE2b-512
               v
      Argon2 password (64 B)
               |                 +------------------------------------------+
               |  <--------------| salted Argon2id:                         |
               v                 | 1 lane, 512 MiB, 4 iterations by default |
       Argon2 tag (128 B)        +------------------------------------------+
               |
               |  <-- enc_key:32 || pad_key:32 || mac_key:64 = argon2_tag:128
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

### Encryption

<table>
  <tr> <td>Counter</td> <td>nonce                     </td> <td>Data                           </td> </tr>
  <tr> <td>0      </td> <td>                          </td> <td>Init value, not used           </td> </tr>
  <tr> <td>1      </td> <td>0x010000000000000000000000</td> <td>Comments, 512 B                </td> </tr>
  <tr> <td>2      </td> <td>0x020000000000000000000000</td> <td>File contents chunk0, 128 KiB  </td> </tr>
  <tr> <td>3      </td> <td>0x030000000000000000000000</td> <td>File contents chunk1, 128 KiB  </td> </tr>
  <tr> <td>4      </td> <td>0x040000000000000000000000</td> <td>File contents chunk2, 128 KiB  </td> </tr>
  <tr> <td>5      </td> <td>0x050000000000000000000000</td> <td>File contents chunk3, 0-128 KiB</td> </tr>
</table>


### Container file format


```
0              start          end
|              |              |
+--------------+--------------+----------+
|              |     msg      |          |
+--------------+--------------+----------+
```
