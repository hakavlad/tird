
<h4 align="left">
  📜&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/MANPAGE.md">man&nbsp;page</a>&nbsp;&nbsp;&nbsp;
  📑&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/SPECIFICATION.md">Specification</a>&nbsp;&nbsp;&nbsp;
  📄&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INPUT_OPTIONS.md">Input&nbsp;Options</a>&nbsp;&nbsp;&nbsp;
  📖&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/tutorial/README.md">Tutorial</a>&nbsp;&nbsp;&nbsp;
  ❓&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/FAQ.md">FAQ</a>&nbsp;&nbsp;&nbsp;
  📥&nbsp;<a href="https://github.com/hakavlad/tird/blob/main/docs/INSTALLATION.md">Installation</a>
</h4>

---

# Creating a Bootable USB Drive from an ISO Image

> [!WARNING]
> Writing the image to the device will result in data loss on the device to which the image is being written!

You can use `tird` as a more user-friendly alternative to `dd` for creating bootable drives from ISO images. `tird` will display the ISO image and removable device sizes, request confirmation (to prevent accidental overwriting), show the writing progress, and synchronize the written data to the disk.

In our case:

- The image from which we want to create the bootable USB drive: `debian-12.10.0-amd64-netinst.iso`
- The path to the device: `/dev/sdc` **(note that in your case, the path may be different!)**

To write to an external device, `root` privileges are required, so you need to run `tird` with `sudo`.

After launching the application, you will need to answer 5 questions:

```
A0. Select an option [0-9]:
D1. File to embed:
D3. File to overwrite (container):
D5. Start position:
P0. Proceed overwriting? (Y/N):
```

#### 1. Launch the app with `sudo` and select option (action) `4`

```
$ sudo tird

                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. Select an option [0-9]: 4
    I: action #4:
        embed file contents (no encryption):
        write input file contents over output file contents
```

#### 2. Enter the path to the ISO image file

```
D1. File to embed: debian-12.10.0-amd64-netinst.iso
    I: path: 'debian-12.10.0-amd64-netinst.iso'; size: 663,748,608 B (633.0 MiB)
```

The file size will be displayed.

#### 3. Enter the path to the device where you want to write the image

```
D3. File to overwrite (container): /dev/sdc
    I: path: '/dev/sdc'
    I: size: 31,042,043,904 B (28.9 GiB)
```

The device size will be displayed.

#### 4. Choose the start position

`tird` will prompt for the offset from the beginning of the device (container) in bytes. Enter `0` to write the image to the beginning of the removable device.

```
D5. Start position [0; 30378295296]: 0
    I: start position: 0 (offset: 0 B)
    I: end position: 663748608 (offset: 663,748,608 B)
```

#### 5. Confirm that you want to proceed

Overwriting the disk will result in data loss, so `tird` requires confirmation before proceeding. Enter `y` only if you are certain that all previous inputs were correct.

```
    W: output file will be partially overwritten!
P0. Proceed overwriting? (Y/N): y
```

#### After confirmation, the action will be completed

```
    I: reading message from input and writing it over output
    I: written 100.0%; 633.0 MiB in 4.1s; avg 155.5 MiB/s
    I: writing completed; total of 663,748,608 B written
    I: syncing output data to disk
    I: synced in 29.4s
    W: message location is important for its further extraction!
    I: remember message location in container:
        [0:663748608]
    I: message checksum:
        c878ae358a50e387382bdc73de7e3075e206d04b788c22c03c3425161e12f788
    I: action completed
```

<details>
  <summary>&nbsp;<b>Show the full dialog</b></summary>

```
$ sudo tird

                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. Select an option [0-9]: 4
    I: action #4:
        embed file contents (no encryption):
        write input file contents over output file contents
D1. File to embed: debian-12.10.0-amd64-netinst.iso
    I: path: 'debian-12.10.0-amd64-netinst.iso'; size: 663,748,608 B (633.0 MiB)
D3. File to overwrite (container): /dev/sdc
    I: path: '/dev/sdc'
    I: size: 31,042,043,904 B (28.9 GiB)
D5. Start position [0; 30378295296]: 0
    I: start position: 0 (offset: 0 B)
    I: end position: 663748608 (offset: 663,748,608 B)
    W: output file will be partially overwritten!
P0. Proceed overwriting? (Y/N): y
    I: reading message from input and writing it over output
    I: written 100.0%; 633.0 MiB in 4.1s; avg 155.5 MiB/s
    I: writing completed; total of 663,748,608 B written
    I: syncing output data to disk
    I: synced in 29.4s
    W: message location is important for its further extraction!
    I: remember message location in container:
        [0:663748608]
    I: message checksum:
        c878ae358a50e387382bdc73de7e3075e206d04b788c22c03c3425161e12f788
    I: action completed
```

</details>

<details>
  <summary>&nbsp;<b>Show the full dialog with debug mode enabled</b></summary>

```
$ sudo tird --debug
    W: debug mode enabled! Sensitive data will be exposed!

                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. Select an option [0-9]: 4
    I: action #4:
        embed file contents (no encryption):
        write input file contents over output file contents
    W: debug mode enabled! Sensitive data will be exposed!
D1. File to embed: debian-12.10.0-amd64-netinst.iso
    D: real path: '/home/user/Downloads/debian-12.10.0-amd64-netinst.iso'
    D: opening file 'debian-12.10.0-amd64-netinst.iso' in mode 'rb'
    D: opened file object: <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>
    I: path: 'debian-12.10.0-amd64-netinst.iso'; size: 663,748,608 B (633.0 MiB)
D3. File to overwrite (container): /dev/sdc
    D: real path: '/dev/sdc'
    D: opening file '/dev/sdc' in mode 'rb+'
    D: opened file object: <_io.BufferedRandom name='/dev/sdc'>
    I: path: '/dev/sdc'
    I: size: 31,042,043,904 B (28.9 GiB)
D5. Start position [0; 30378295296]: 0
    I: start position: 0 (offset: 0 B)
    I: end position: 663748608 (offset: 663,748,608 B)
    W: output file will be partially overwritten!
P0. Proceed overwriting? (Y/N): 1
    D: moving from position 0 to position 0 in <_io.BufferedRandom name='/dev/sdc'>
    I: reading message from input and writing it over output
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 0 to 16,777,216
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 0 to 16,777,216
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 16,777,216 to 33,554,432
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 16,777,216 to 33,554,432
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 33,554,432 to 50,331,648
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 33,554,432 to 50,331,648
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 50,331,648 to 67,108,864
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 50,331,648 to 67,108,864
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 67,108,864 to 83,886,080
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 67,108,864 to 83,886,080
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 83,886,080 to 100,663,296
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 83,886,080 to 100,663,296
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 100,663,296 to 117,440,512
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 100,663,296 to 117,440,512
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 117,440,512 to 134,217,728
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 117,440,512 to 134,217,728
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 134,217,728 to 150,994,944
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 134,217,728 to 150,994,944
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 150,994,944 to 167,772,160
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 150,994,944 to 167,772,160
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 167,772,160 to 184,549,376
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 167,772,160 to 184,549,376
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 184,549,376 to 201,326,592
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 184,549,376 to 201,326,592
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 201,326,592 to 218,103,808
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 201,326,592 to 218,103,808
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 218,103,808 to 234,881,024
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 218,103,808 to 234,881,024
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 234,881,024 to 251,658,240
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 234,881,024 to 251,658,240
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 251,658,240 to 268,435,456
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 251,658,240 to 268,435,456
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 268,435,456 to 285,212,672
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 268,435,456 to 285,212,672
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 285,212,672 to 301,989,888
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 285,212,672 to 301,989,888
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 301,989,888 to 318,767,104
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 301,989,888 to 318,767,104
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 318,767,104 to 335,544,320
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 318,767,104 to 335,544,320
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 335,544,320 to 352,321,536
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 335,544,320 to 352,321,536
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 352,321,536 to 369,098,752
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 352,321,536 to 369,098,752
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 369,098,752 to 385,875,968
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 369,098,752 to 385,875,968
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 385,875,968 to 402,653,184
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 385,875,968 to 402,653,184
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 402,653,184 to 419,430,400
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 402,653,184 to 419,430,400
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 419,430,400 to 436,207,616
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 419,430,400 to 436,207,616
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 436,207,616 to 452,984,832
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 436,207,616 to 452,984,832
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 452,984,832 to 469,762,048
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 452,984,832 to 469,762,048
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 469,762,048 to 486,539,264
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 469,762,048 to 486,539,264
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 486,539,264 to 503,316,480
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 486,539,264 to 503,316,480
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 503,316,480 to 520,093,696
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 503,316,480 to 520,093,696
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 520,093,696 to 536,870,912
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 520,093,696 to 536,870,912
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 536,870,912 to 553,648,128
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 536,870,912 to 553,648,128
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 553,648,128 to 570,425,344
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 553,648,128 to 570,425,344
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 570,425,344 to 587,202,560
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 570,425,344 to 587,202,560
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 587,202,560 to 603,979,776
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 587,202,560 to 603,979,776
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 603,979,776 to 620,756,992
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 603,979,776 to 620,756,992
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 620,756,992 to 637,534,208
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 620,756,992 to 637,534,208
    D: read 16,777,216 B (16.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 637,534,208 to 654,311,424
    D: written 16,777,216 B (16.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 637,534,208 to 654,311,424
    D: read 9,437,184 B (9.0 MiB) from <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>; position moved from 654,311,424 to 663,748,608
    D: written 9,437,184 B (9.0 MiB) to <_io.BufferedRandom name='/dev/sdc'>; position moved from 654,311,424 to 663,748,608
    I: written 100.0%; 633.0 MiB in 4.4s; avg 144.3 MiB/s
    I: writing completed; total of 663,748,608 B written
    I: syncing output data to disk
    D: fsynced <_io.BufferedRandom name='/dev/sdc'>
    I: synced in 32.5s
    W: message location is important for its further extraction!
    I: remember message location in container:
        [0:663748608]
    I: message checksum:
        c878ae358a50e387382bdc73de7e3075e206d04b788c22c03c3425161e12f788
    D: closing <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'>
    D: <_io.BufferedReader name='debian-12.10.0-amd64-netinst.iso'> closed
    D: closing <_io.BufferedRandom name='/dev/sdc'>
    D: <_io.BufferedRandom name='/dev/sdc'> closed
    I: action completed
```

</details>
