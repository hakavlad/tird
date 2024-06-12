
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

Select the action to perform from the MENU list.

#### List of available actions

<table>

<tr>  <td><b>Action</b></td>  <td><b>Description</b></td>  </tr>

<tr>  <td><b>0. Exit</b></td>  <td>Exiting <code>tird</code>.</td>  </tr>

<tr>  <td><b>1. Info & warnings</b></td>  <td>Displaying info and warnings.</td>  </tr>

<tr>  <td><b>2. Encrypt</b></td>  <td>Encrypt file contents and comments; write the cryptoblob to a new file.</td>  </tr>

<tr>  <td><b>3. Decrypt</b></td>  <td>Decrypt a file; display the decrypted comments and write the decrypted contents to a new file.</td>  </tr>

<tr>  <td><b>4. Embed</b></td>  <td>Embed file contents (no encryption): write input file contents over output file contents.</td>  </tr>

<tr>  <td><b>5. Extract</b></td>  <td>Extract file contents (no decryption) to a new file.</td>  </tr>

<tr>  <td><b>6. Encrypt & embed</b></td>  <td>Encrypt file contents and comments; write the cryptoblob over a container.</td>  </tr>

<tr>  <td><b>7. Extract & decrypt</b></td>  <td>Extract and decrypt cryptoblob; display the decrypted comments and write the decrypted contents to a new file.</td>  </tr>

<tr>  <td><b>8. Create w/ random</b></td>  <td>Create a file of the specified size with random data.</td>  </tr>

<tr>  <td><b>9. Overwrite w/ random</b></td>  <td>Overwrite file contents with random data.</td>  </tr>

</table>

#### Example

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

---

## [02] Use custom settings?

---

## [03] Argon2 time cost

---

## [04] Max padding size

---

## [05] Set a fake MAC tag?

---

## [06] Input file path

---

## [07] Output file path

Examples

```
[07] File to overwrite (container): container.bin
I: path: "container.bin"
I: size: 1000000 B, 976.6 KiB
```


---

## [08] Start position

Examples

```
[08] Start position, valid values are [0; 999936]: 1111
I: start position: 1111
I: end position: 1175
```


---

## [09] End position

---

## [10] Comments


Examples

```
[10] Comments (optional, up to 512 B):
I: comments will be shown as: [None]
```

---

## [11] Keyfile path

```
[11] Keyfile path (optional):
[12] Passphrase (optional):
```


---

## [12] Passphrase

Examples


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


Examples

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


```
[14] Output file size in bytes: 1000000
I: size: 1000000 B, 976.6 KiB
```






