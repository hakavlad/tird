
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

# Time-Lock Encryption

> [!NOTE]
> `Time cost` value MUST be an integer.

Here's how to find the `Time cost` value at which keys are derived with Argon2 within a given time.

First, you need to determine the average time of a single Argon2 pass (iteration) on your hardware.

Try encrypting or decrypting a file.

For example, create an empty file named `0` and encrypt it with `Time cost` = 100.

Open the custom options, set `Time cost:` 100, and encrypt file `0`.

```
$ touch 0
$ tird

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
C0. Use custom settings? (Y/N, default=N): y
    I: use custom settings: True
    W: decryption will require the same [C1] and [C2] values!
C1. Time cost (default=4): 100
    I: time cost: 100
C2. Max padding size, % (default=20):
    I: max padding size, %: 20
C3. Set fake MAC tag? (Y/N, default=N):
    I: set fake MAC tag: False
D1. File to encrypt: 0
    I: path: '0'; size: 0 B
D2. Comments (optional, up to 512 B):
    I: comments will be shown as [None]
D3. Output (encrypted) file: test1
    I: new empty file 'test1' created
K1. Keyfile path (optional):
K2. Passphrase (optional):
    W: no keyfile or passphrase specified!
    I: deriving keys (time-consuming)
    I: keys derived in 87.4s (1m 27.4s)
    I: data size to write: 899 B
    I: reading plaintext, writing cryptoblob
    I: written 100.0%; 899 B in 0.0s; avg 0.2 MiB/s
    I: writing completed; total of 899 B written
    I: pockets (padding) location in output file:
        [16:159] — 143 B
        [703:883] — 180 B
    I: action completed
```

Here we specified the number of Argon2 iterations (`Time cost`):

```
C1. Time cost (default=4): 100
    I: time cost: 100
```

Here we obtained the Argon2 runtime in seconds:

```
    I: deriving keys (time-consuming)
    I: keys derived in 87.4s (1m 27.4s)
```

Find the average time for one pass by dividing total time by the number of iterations:

```
t_avg = 87.4 / 100 = 0.874
```

So, on my hardware the average time for one iteration was **0.874** seconds.

### How to find `Time cost` for a given time interval?

Multiply `t_avg` by the number of seconds in the interval and round to get an integer.

For one hour:

```
t_cost = t_avg * 3600 = 0.874 * 3600 = 3146.4 ≈ 3146
```

Thus, `Time cost` = 3146 will make Argon2 run for about one hour on my hardware.

**Note:** speed can vary depending on CPU and memory load. This is an approximate value.

For two days:

```
t_cost = t_avg * 3600 * 24 * 2 = 0.874 * 3600 * 24 * 2 = 151027.2 ≈ 151027
```

**Note:** Measured times may vary with system load; re-run the short benchmark (e.g., `Time cost`=100) a few times and average the results for better accuracy.

### Approximate `Time cost` for different durations and example `t_avg` values


|Time|`Time cost`<br>(`t_avg=0.5`)|`Time cost`<br>(`t_avg=1`)|`Time cost`<br>(`t_avg=1.5`)|`Time cost`<br>(`t_avg=2`)|`Time cost`<br>(`t_avg=3`)|`Time cost`<br>(`t_avg=4`)|
|-|-|-|-|-|-|-|
|10s|5|10|15|20|30|40|
|1m (60s)|30|60|90|120|180|240|
|10m (600s)|300|600|900|1200|1800|2400|
|1h (3600s)|1800|3600|5400|7200|10800|14400|
|6h (21600s)|10800|21600|32400|43200|64800|86400|
|1d (24h, 86400s)|43200|86400|129600|172800|259200|345600|
|7d (168h, 604800s)|302400|604800|907200|1209600|1814400|2419200|
|30d (720h, 2592000s)|1296000|2592000|3888000|5184000|7776000|10368000|
