
# Draft Specification

Key derivation scheme:

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
               |  <-- (enc_key:32 || pad_key:32 || mac_key:64) = argon2_tag:128
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
