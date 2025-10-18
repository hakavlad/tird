#!/usr/bin/env python3
"""
tird /tɪrd/ (an acronym for "this is random data")
A tool for encrypting files and hiding encrypted data.

tird implements a PURB-style (Padded Uniform Random Blob) encryption
scheme designed to leak minimal metadata — only total size is
observable; no headers, file types, or plaintext hints are exposed. The
tool supports embedding cryptoblobs into arbitrary containers for
plausible deniability and offers optional time-lock encryption via
memory-hard Argon2id key derivation.

Key features:
- PURB-format encrypted blobs: randomized size, uniformly random-looking
  ciphertext.
- Padded & encrypted comments: metadata hidden; no plaintext leakage.
- Hidden data embedding: cryptoblobs can be written into existing files.
- Time-lock encryption: configurable Argon2id parameters
  (default: 1 GiB RAM, 4 ops).
- Authenticated encryption: ChaCha20 stream cipher + BLAKE2b-based
  MAC (AEAD).
- Flexible key material: derive keys from passphrases, files, block
  devices, or directories (order-independent).
- Interactive CLI: user-friendly prompts; no command-line flags
  required.
- No persistent metadata: output contains no version strings, magic
  bytes, or identifiable structure.

Planned:
- Stable, documented binary format for long-term storage and
  interoperability.

Security notes:
- Intended for offline, non-compromised environments.
- Does not erase secrets from memory; sensitive data may persist in
  RAM or swap.
- Not a substitute for operational security or legal protection.

Requirements:
- Python >= 3.9.2
- cryptography >= 2.1 (ChaCha20, HKDF-SHA-256)
- PyNaCl >= 1.2.0 (Argon2id, BLAKE2b)
- colorama >= 0.4.6 (Windows console support)

SPDX-License-Identifier: 0BSD

Homepage: https://github.com/hakavlad/tird
"""

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-branches
# pylint: disable=too-many-lines
# pylint: disable=too-many-locals
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-statements

from collections.abc import Callable
from gc import collect
from getpass import getpass
from os import SEEK_END
from os import _exit as os_exit
from os import chmod, fsync, ftruncate, path, remove, walk, write

try:
    from resource import RLIMIT_CORE, setrlimit
    RESOURCE_MODULE_AVAILABLE: bool = True
except ModuleNotFoundError:
    RESOURCE_MODULE_AVAILABLE = False

from io import BytesIO
from secrets import compare_digest, token_bytes
from signal import SIGINT, SIGTERM, signal
from sys import argv
from sys import exit as sys_exit
from sys import platform, stderr, version
from time import monotonic
from types import FrameType
from typing import Any, BinaryIO, Final, Literal, NoReturn, Optional
from unicodedata import normalize

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.hashlib import blake2b
from nacl.pwhash import argon2id

if platform == 'win32':
    from colorama import just_fix_windows_console
else:
    from signal import SIGHUP, SIGQUIT


# Define some classes
# --------------------------------------------------------------------------- #


class KeyfileScanError(Exception):
    """Exception raised by keyfile directory scanning errors."""


# Define a type alias for action identifiers
ActionID = Literal[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]


class ActData:
    """
    Container for per-operation runtime state used during processing.

    Acts as a plain data holder for values tracked while performing a
    single action (encryption, decryption, embed, extract, etc.). Fields
    are simple typed attributes; instances are slot-restricted to the
    annotated names.

    Attributes
    ----------
    action : ActionID
        Identifier of the action being performed.
    err : bool
        Error flag; set True when an unrecoverable error occurs during
        the operation.

    out_file_obj : BinaryIO
        Open file-like object for output (writes). Expected to provide
        write(), flush(), fileno(), tell(), and close() as appropriate.
    in_file_obj : BinaryIO
        Open file-like object for input (reads). Expected to provide
        read(), tell(), seek(), and close().

    start_time : float
        Monotonic timestamp when the operation started.
    last_progress_time : float
        Monotonic timestamp of the last progress log.

    start_pos : int
        File-position (bytes) at operation start in the output file.
    end_pos : Optional[int]
        File-position (bytes) at operation end, if known; otherwise
        None.
    max_start_pos : int
        Maximum allowed start position (used for validation).
    max_end_pos : int
        Maximum allowed end position (used for validation).

    written_sum : int
        Cumulative number of bytes written to the output file so far.
    total_out_data_size : int
        Total number of bytes expected to be written (used for
        progress).
    in_file_size : int
        Size in bytes of the input file.

    processed_comments : Optional[bytes]
        Optional comments or metadata processed for the current action;
        stored as bytes when present.

    unpadded_size : int
        Original data size before padding.
    padded_size : int
        Data size after padding (bytes).

    Notes
    -----
    - Instances use __slots__ to prevent dynamic attribute creation and
      reduce memory usage.
    - This class is a data container only; lifecycle management
      (opening/closing files, wiping secrets) is the caller's
      responsibility.
    - Field semantics (units, required vs optional) follow the
      conventions of the surrounding codebase and helper functions.
    """
    action: ActionID
    err: bool

    out_file_obj: BinaryIO
    in_file_obj: BinaryIO

    start_time: float
    last_progress_time: float

    start_pos: int
    end_pos: Optional[int]
    max_start_pos: int
    max_end_pos: int

    written_sum: int
    total_out_data_size: int
    in_file_size: int

    processed_comments: Optional[bytes]

    unpadded_size: int
    padded_size: int

    __slots__ = tuple(__annotations__.keys())


class Crypto:
    """
    Cryptographic state container used during cryptographic operations.

    Holds derived keys, nonces, salts, counters and incremental
    MAC/encryption state required by encryption, authentication and
    key-derivation routines.

    Attributes
    ----------
    blake2_salt : bytes
        Salt used with BLAKE2 hashing.
    argon2_salt : bytes
        Salt used for Argon2 key derivation.
    argon2_password : bytes
        Password or secret input for Argon2.
    argon2_time_cost : int
        Argon2 time-cost parameter.

    mac_key : bytes
        Key used for message authentication (MAC).
    enc_key : bytes
        Symmetric encryption key.
    enc_key_hash : bytes
        Hash of the encryption key (used for explicit key commitment).

    nonce_counter : int
        Counter used to derive or advance the nonce.
    nonce : bytes
        Current nonce used for encryption/authentication operations.

    mac_hash_obj : Any
        Incremental MAC/hash object (e.g., blake2b);
        implementation-specific.
    mac_chunk_size_sum : int
        Cumulative number of bytes processed by the MAC.
    enc_sum : int
        Cumulative number of bytes encrypted.
    enc_chunk_count : int
        Number of encryption chunks processed.

    pad_ikm : bytes
        Independent key material used for padding or further derivation
        (if used).
    encrypted_pad_ikm : bytes
        Encrypted form of pad_ikm, if stored/transported encrypted.

    padded_size_bytes : bytes
        Padded data size encoded as bytes.
    pad_size_bytes : bytes
        Pad size encoded as bytes.
    contents_size_bytes : bytes
        Original contents size encoded as bytes.

    Notes
    -----
    - Instances use __slots__ (derived from __annotations__) to prevent
      dynamic attribute creation and reduce memory usage.
    - This class is a plain data container; it does not perform
      cryptographic operations itself. All sensitive material (keys,
      salts, passwords) should be zeroed/wiped by the caller when no
      longer needed.
    - Types such as ActionID, BinaryIO, and Any must be
      available/imported in the module namespace where this class is
      defined.
    """
    blake2_salt: bytes
    argon2_salt: bytes
    argon2_password: bytes
    argon2_time_cost: int

    mac_key: bytes
    enc_key: bytes
    enc_key_hash: bytes

    nonce_counter: int
    nonce: bytes

    mac_hash_obj: Any
    mac_chunk_size_sum: int
    enc_sum: int
    enc_chunk_count: int

    pad_ikm: bytes
    encrypted_pad_ikm: bytes

    padded_size_bytes: bytes
    pad_size_bytes: bytes
    contents_size_bytes: bytes

    __slots__ = tuple(__annotations__.keys())


# Formatting output messages and logging
# --------------------------------------------------------------------------- #


def log_e(error_message: str) -> None:
    """
    Log an error-level message.

    Prints the provided message formatted for error severity to stderr.
    The output includes an "E:" prefix and uses the ERROR color/style
    constant `ERR` and the reset constant `RES` if available.

    Parameters
    ----------
    error_message : str
        Message text to log at error level.

    Returns
    -------
    None
    """
    print(f'    {ERR}E: {error_message}{RES}', file=stderr)


def log_w(warning_message: str) -> None:
    """
    Log a warning-level message.

    Prints the provided message formatted for warning severity to
    stderr. The output includes a "W:" prefix and uses the WARNING
    color/style constant `WAR` and the reset constant `RES` if
    available.

    Parameters
    ----------
    warning_message : str
        Message text to log at warning level.

    Returns
    -------
    None
    """
    print(f'    {WAR}W: {warning_message}{RES}', file=stderr)


def log_i(info_message: str) -> None:
    """
    Log an informational message.

    Prints the provided message with an "I:" prefix to stdout.

    Parameters
    ----------
    info_message : str
        Message text to log at info level.

    Returns
    -------
    None
    """
    print(f'    I: {info_message}')


def log_d(debug_message: str) -> None:
    """
    Log a debug-level message.

    Prints the provided message with a "D:" prefix for
    diagnostic/debugging output to stdout.

    Parameters
    ----------
    debug_message : str
        Message text to log at debug level.

    Returns
    -------
    None
    """
    print(f'    D: {debug_message}')


def format_size(size: int) -> str:
    """
    Convert a byte count to a human-readable string showing bytes and
    IEC units.

    Returns the size formatted with a thousands separator in bytes and,
    when applicable, its equivalent in the largest IEC unit (KiB, MiB,
    GiB, TiB, PiB, EiB) rounded to one decimal place. Values smaller
    than 1 KiB are returned as "<bytes> B".

    Parameters
    ----------
    size : int
        Size in bytes.

    Returns
    -------
    str
        Human-readable size, e.g. "1,234 B (1.2 KiB)" or "123 B" for
        small values.

    Notes
    -----
    - Uses IEC constants `KIB`, `MIB`, `GIB`, `TIB`, `PIB`, `EIB`.
    - Rounds unit values to one decimal place.
    """
    formatted_size: str

    if size >= EIB:
        formatted_size = f'{size:,} B ({round(size / EIB, 1)} EiB)'
    elif size >= PIB:
        formatted_size = f'{size:,} B ({round(size / PIB, 1)} PiB)'
    elif size >= TIB:
        formatted_size = f'{size:,} B ({round(size / TIB, 1)} TiB)'
    elif size >= GIB:
        formatted_size = f'{size:,} B ({round(size / GIB, 1)} GiB)'
    elif size >= MIB:
        formatted_size = f'{size:,} B ({round(size / MIB, 1)} MiB)'
    elif size >= KIB:
        formatted_size = f'{size:,} B ({round(size / KIB, 1)} KiB)'
    else:
        formatted_size = f'{size:,} B'

    return formatted_size


def short_format_size(size: int) -> str:
    """
    Convert a byte count to a compact, human-readable string using IEC
    units.

    Chooses the largest IEC unit (EiB, PiB, TiB, GiB, MiB, KiB) for
    which the value is >= 1 and formats the result with one decimal
    place. Values smaller than 1 KiB are returned in bytes with
    thousands separators.

    Parameters
    ----------
    size : int
        Size in bytes.

    Returns
    -------
    str
        Human-readable size string, e.g. "1.2 MiB", "512 KiB", or
        "123 B".

    Notes
    -----
    - Uses IEC constants `EIB`, `PIB`, `TIB`, `GIB`, `MIB`, and `KIB`.
    - Rounds unit values to one decimal place.
    """
    formatted_size: str

    if size >= EIB:
        formatted_size = f'{round(size / EIB, 1)} EiB'
    elif size >= PIB:
        formatted_size = f'{round(size / PIB, 1)} PiB'
    elif size >= TIB:
        formatted_size = f'{round(size / TIB, 1)} TiB'
    elif size >= GIB:
        formatted_size = f'{round(size / GIB, 1)} GiB'
    elif size >= MIB:
        formatted_size = f'{round(size / MIB, 1)} MiB'
    elif size >= KIB:
        formatted_size = f'{round(size / KIB, 1)} KiB'
    else:
        formatted_size = f'{size:,} B'

    return formatted_size


def format_time(total_s: float) -> str:
    """
    Format a duration in seconds into a human-readable string.

    Produces a compact representation in seconds and, when applicable,
    an expanded form with minutes and/or hours.

    Parameters
    ----------
    total_s : float
        Duration in seconds. May be fractional.

    Returns
    -------
    str
        Human-readable time string. Examples:
        - For < 60 s: "Xs" (seconds, rounded to 0.1s)
        - For < 3600 s: "Xs (Ym Zs)" (seconds plus minutes and seconds)
        - For >= 3600 s: "Xs (Ah Bm Cs)" (seconds plus hours, minutes,
          seconds)

    Notes
    -----
    - The primary seconds value is rounded to one decimal place.
    - Minutes and hours are integer values; remaining seconds are
      rounded to one decimal place.
    """
    formatted_time: str

    rounded_s: float = round(total_s, 1)

    if total_s < 60:
        formatted_time = f'{rounded_s}s'

    elif total_s < 3600:
        total_m: int = int(total_s // 60)
        mod_s: float = round(total_s % 60, 1)
        formatted_time = f'{rounded_s:,}s ({total_m}m {mod_s}s)'

    else:
        total_m = int(total_s // 60)
        mod_s = round(total_s % 60, 1)
        total_h: int = int(total_m // 60)
        mod_m: int = int(total_m % 60)
        formatted_time = f'{rounded_s:,}s ({total_h}h {mod_m}m {mod_s}s)'

    return formatted_time


def log_progress(ad: ActData) -> None:
    """
    Log progress of an ongoing data-writing operation.

    Computes and logs percentage complete, amount written, elapsed time,
    and average throughput. Uses values from the provided action data:
    `ad.start_time`, `ad.written_sum`, and `ad.total_out_data_size`.

    Parameters
    ----------
    ad : ActData
        Action data containing:
        - start_time (float): monotonic timestamp when the operation
          started.
        - written_sum (int): total bytes written so far.
        - total_out_data_size (int): total bytes expected to be written.
        The function may also rely on formatting helpers referenced by
        `ad` context (e.g., `short_format_size`, `format_time`) or
        globals (`MIB`).

    Returns
    -------
    None
        Emits log messages via `log_i` and does not return a value.

    Notes
    -----
    - If `ad.total_out_data_size` is zero, logs 'written 0 B' to avoid
      division by zero.
    - If elapsed time is zero, logs percentage and written amount
      without average speed.
    - Average speed is reported in MiB/s using the `MIB` constant.
    - Relies on helpers/globals: `monotonic`, `short_format_size`,
      `format_time`, `MIB`, and `log_i`.
    """

    # Check if the total data size is zero to avoid division by zero
    if not ad.total_out_data_size:
        log_i('written 0 B')
        return

    # Calculate the elapsed time since the start of the operation
    elapsed_time: float = monotonic() - ad.start_time

    # Calculate the percentage of data written
    percentage: float = ad.written_sum / ad.total_out_data_size * 100

    # Format the amount of data written for logging
    formatted_written: str = short_format_size(ad.written_sum)

    if not elapsed_time:
        # Log progress without average speed if elapsed time is zero
        log_i(f'written {round(percentage, 1)}%; '
              f'{formatted_written} in 0.0s')
        return

    # Calculate the average writing speed in MiB/s
    average_speed: int = round(ad.written_sum / MIB / elapsed_time)

    # Log the detailed progress information
    log_i(f'written {round(percentage, 1)}%; '
          f'{formatted_written} in {format_time(elapsed_time)}; '
          f'avg {average_speed} MiB/s')


def log_progress_if_time_elapsed(ad: ActData) -> ActData:
    """
    Emit progress information if the minimum interval has elapsed.

    Checks the elapsed time since the last progress log stored in the
    action data and, if it meets or exceeds MIN_PROGRESS_INTERVAL, calls
    `log_progress(ad)` and updates `ad.last_progress_time`.

    Parameters
    ----------
    ad : ActData
        Action data containing at least:
        - last_progress_time (float): timestamp of the last progress
          log.
        - any fields required by `log_progress`.

    Returns
    -------
    ActData
        The (possibly modified) action data with `last_progress_time`
        updated when progress was logged.

    Notes
    -----
    - Uses `monotonic()` for elapsed-time checks and the global
      `MIN_PROGRESS_INTERVAL` constant.
    - Relies on the helper `log_progress`.
    """

    # Check if the minimum progress interval has passed since the last log
    if monotonic() - ad.last_progress_time >= MIN_PROGRESS_INTERVAL:

        # Log the current progress based on the total data size
        log_progress(ad)

        # Update the last progress log time to the current time
        ad.last_progress_time = monotonic()

    return ad


def log_progress_final(ad: ActData) -> None:
    """
    Log final write progress and total bytes written.

    Calls `log_progress()` to emit any pending progress information,
    then logs an informational message stating that writing has
    completed and reporting the total number of bytes written.

    Parameters
    ----------
    ad : ActData
        Action data containing at least the `written_sum` attribute used
        to report the total bytes written.

    Returns
    -------
    None
        Performs logging side effects and does not return a value.

    Notes
    -----
    - Uses logging helpers `log_progress` and `log_i`.
    - Assumes `ad.written_sum` is an integer representing bytes written.
    """
    log_progress(ad)

    log_i(f'writing completed; total of {ad.written_sum:,} B written')


# Handle files and paths
# --------------------------------------------------------------------------- #


def open_file(
    file_path: str,
    access_mode: Literal['rb', 'rb+', 'xb'],
) -> Optional[BinaryIO]:
    """
    Open a file in the requested mode and return the file object.

    Attempts to open `file_path` using the provided `access_mode`.
    Common modes used are 'rb' (read binary), 'rb+' (read/write binary)
    and 'xb' (exclusive create, binary). Exceptions from the open
    attempt are caught, logged, and the function returns None on
    failure.

    Parameters
    ----------
    file_path : str
        Path to the file to open.
    access_mode : {'rb', 'rb+', 'xb'}
        File access mode. 'xb' will fail if the file already exists.

    Returns
    -------
    Optional[BinaryIO]
        Open binary file object on success, or None if an error
        occurred.

    Notes
    -----
    - The function calls `check_for_signal()` before attempting to open
      the file and logs debug information when `UNSAFE_DEBUG` is true.
    - Errors are logged via `log_e`; no exceptions are propagated.
    - Relies on globals/helpers: `check_for_signal`, `UNSAFE_DEBUG`,
      `log_d`, and `log_e`.
    """
    check_for_signal()  # Check if a termination signal has been received

    if UNSAFE_DEBUG:
        log_d(f'opening file {file_path!r} in mode {access_mode!r}')

    try:
        file_obj: BinaryIO = open(file_path, access_mode)
        if UNSAFE_DEBUG:
            log_d(f'opened file object: {file_obj}')
        return file_obj
    except (
        FileNotFoundError, PermissionError, FileExistsError, OSError
    ) as error:
        log_e(f'{error}')
        return None


def close_file(file_obj: BinaryIO) -> None:
    """
    Close a binary file object, logging progress and errors.

    Checks for termination signals, then attempts to close the provided
    file object if it is not already closed. Debug logging occurs before
    and after closing when `UNSAFE_DEBUG` is true. If closing raises an
    OSError or the object reports `closed` as False after the operation,
    an error is logged.

    Parameters
    ----------
    file_obj : BinaryIO
        File-like object to close. Must implement `.close()` and
        `.closed`.

    Returns
    -------
    None
        This function performs side effects (closing and logging) and
        does not return a value.

    Notes
    -----
    - Calls `check_for_signal()` before attempting I/O-related
      operations.
    - Uses `log_d` for debug messages and `log_e` for errors; these
      globals are expected to be available.
    - Exceptions raised by `.close()` are caught and logged; they are
      not propagated.
    """
    check_for_signal()  # Check if a termination signal has been received

    if not file_obj.closed:
        if UNSAFE_DEBUG:
            log_d(f'closing {file_obj}')

        try:
            file_obj.close()
        except OSError as error:
            log_e(f'{error}')

        if file_obj.closed:
            if UNSAFE_DEBUG:
                log_d(f'{file_obj} closed')
        else:
            log_e(f'file descriptor of {file_obj} NOT closed')
    else:
        if UNSAFE_DEBUG:
            log_d(f'{file_obj} is already closed')


def get_file_size(file_path: str) -> Optional[int]:
    """
    Get the size of a file or block device in bytes.

    Opens the given path in binary read mode and seeks to the end to
    obtain its size. Unlike os.path.getsize(), this method can work with
    block devices on Unix systems by using seek on the device file.

    Parameters
    ----------
    file_path : str
        Path to the file or block device whose size is required.

    Returns
    -------
    Optional[int]
        Size in bytes on success, or None on error (for example if the
        file does not exist, permission is denied, or an I/O error
        occurs).

    Notes
    -----
    - The function logs errors via `log_e` and returns None on failure.
    - Uses a short-lived file descriptor and therefore does not keep the
      file open.
    - Relies on globals/helpers: `SEEK_END` and `log_e`.
    """
    try:
        with open(file_path, 'rb') as file_obj:
            # Move to the end of the file
            file_size: int = file_obj.seek(0, SEEK_END)
            return file_size
    except (FileNotFoundError, PermissionError, OSError) as error:
        log_e(f'{error}')
        return None


def seek_position(file_obj: BinaryIO, offset: int) -> bool:
    """
    Attempts to move the file pointer to the given byte offset using
    file_obj.seek(offset). Returns True on success or False if an
    OSError occurs during seek.

    Parameters
    ----------
    file_obj : BinaryIO
        File-like object supporting seek() and tell().
    offset : int
        Byte offset to seek to. This function does not support a
        `whence` parameter — the offset is passed directly to
        file_obj.seek(offset).

    Returns
    -------
    bool
        True if the seek succeeded, False if an OSError occurred.

    Notes
    -----
    - When the global UNSAFE_DEBUG is truthy the function logs the
      current and target positions via `log_d`. The call to
      file_obj.tell() is made only when UNSAFE_DEBUG is enabled and may
      itself raise an exception; that exception is not caught by this
      function.
    - Errors raised by file_obj.seek() that are instances of OSError
      are logged via `log_e` and cause the function to return False.
    - Other exceptions are not caught and will propagate to the caller.
    - Relies on globals/helpers: `UNSAFE_DEBUG`, `log_d`, and `log_e`.
    """
    if UNSAFE_DEBUG:
        current_pos: int = file_obj.tell()
        log_d(f'moving from position {current_pos:,} '
              f'to position {offset:,} in {file_obj}')
    try:
        file_obj.seek(offset)
        return True
    except OSError as error:
        log_e(f'{error}')
        return False


def read_data(file_obj: BinaryIO, data_size: int) -> Optional[bytes]:
    """
    Read exactly a specified number of bytes from a binary file object.

    Performs a strict read: the function returns the requested number of
    bytes or None on error or if EOF is reached before `data_size` bytes
    are obtained. Useful where partial reads are unacceptable (e.g.,
    cryptographic operations).

    Parameters
    ----------
    file_obj : BinaryIO
        Binary file-like object supporting read(); when UNSAFE_DEBUG is
        enabled it should also support tell() (and optionally seek())
        for position logging.
    data_size : int
        Number of bytes to read. Must be non-negative.

    Returns
    -------
    Optional[bytes]
        The bytes read (exactly `data_size` bytes) on success, or None
        if:
        - EOF was reached before `data_size` bytes were read,
        - an I/O error occurred, or
        - UNSAFE_DEBUG checks detect an unexpected position change.

    Notes
    -----
    - The function calls `check_for_signal()` before performing I/O.
    - Errors are logged via `log_e`; progress/debug information is
      logged via `log_d` when `UNSAFE_DEBUG` is true.
    - Relies on globals/helpers: `check_for_signal`, `UNSAFE_DEBUG`,
      `log_e`, `log_d`, and `format_size`.
    """
    check_for_signal()  # Check if a termination signal has been received

    if UNSAFE_DEBUG:
        start_pos: int = file_obj.tell()

    try:
        data: bytes = file_obj.read(data_size)
    except OSError as error:
        log_e(f'{error}')
        return None

    if len(data) < data_size:
        log_e(f'read data size ({len(data):,} B) is less than '
              f'expected ({data_size:,} B)')
        return None

    if UNSAFE_DEBUG:
        end_pos: int = file_obj.tell()
        log_d(f'read {format_size(end_pos - start_pos)} from {file_obj}; '
              f'position moved from {start_pos:,} to {end_pos:,}')

    return data


def write_data(data: bytes, ad: ActData) -> ActData:
    """
    Write binary data to the active output file and update progress
    state.

    Performs a single write() call on the provided action data's output
    file object, updates cumulative written byte counters, and
    records/logs progress. Any OSError during writing is logged, sets
    the action data's error flag, and causes an early return. Signal
    checks and optional debug position logging are performed.

    Parameters
    ----------
    data : bytes
        Binary data to write to the output file.
    ad : ActData
        Action data structure containing at least:
        - out_file_obj: a binary file-like object opened for writing
          with tell() and write() support.
        - written_sum: integer counter of total bytes written (will be
          incremented by len(data)).
        - err: boolean flag to mark an error condition.
        Other fields used: any fields read/updated by
        `log_progress_if_time_elapsed`.

    Returns
    -------
    ActData
        The (possibly modified) action data object. On error `ad.err`
        will be set True; on success `ad.written_sum` is increased and
        progress may be logged.

    Notes
    -----
    - The function calls `check_for_signal()` before performing IO.
    - It does not fsync; use `fsync_written_data()` for durability
      guarantees.
    - In UNSAFE_DEBUG mode the function logs the file position before
      and after the write using `log_d` and `format_size`.
    - Relies on helpers/globals: `check_for_signal`, `UNSAFE_DEBUG`,
      `log_e`, `log_d`, `format_size`, and
      `log_progress_if_time_elapsed`.
    - The caller should handle recovery (close/remove file) if an error
      is indicated by `ad.err`.
    """
    check_for_signal()  # Check if a termination signal has been received

    if UNSAFE_DEBUG:
        start_pos: int = ad.out_file_obj.tell()

    try:
        ad.out_file_obj.write(data)
    except OSError as error:
        log_e(f'{error}')
        ad.err = True
        return ad

    if UNSAFE_DEBUG:
        end_pos: int = ad.out_file_obj.tell()
        log_d(f'written {format_size(end_pos - start_pos)} to '
              f'{ad.out_file_obj}; position moved '
              f'from {start_pos:,} to {end_pos:,}')

    ad.written_sum += len(data)

    ad = log_progress_if_time_elapsed(ad)

    return ad


def fsync_written_data(ad: ActData) -> bool:
    """
    Flush the output file buffer and synchronize written data to disk.

    Calls flush() on the provided output file object then performs a
    filesystem sync on its file descriptor. A prior call to
    check_for_signal() ensures pending termination requests are observed
    before attempting IO.

    Parameters
    ----------
    ad : ActData
        Action data containing `out_file_obj`, a binary file-like object
        with a valid fileno() method.

    Returns
    -------
    bool
        True if the buffer was flushed and fsync completed successfully;
        False if an OSError occurred during flushing or syncing.

    Notes
    -----
    - The function logs errors via `log_e` and debug information via
      `log_d` when `UNSAFE_DEBUG` is true.
    - Relies on helpers/globals: `check_for_signal`, `fsync`,
      `UNSAFE_DEBUG`, and logging helpers.
    - Exceptions other than OSError are not explicitly handled and will
      propagate.
    """
    check_for_signal()  # Check if a termination signal has been received

    try:
        # Flush the output buffer
        ad.out_file_obj.flush()

        # Synchronize the file to disk
        fsync(ad.out_file_obj.fileno())
    except OSError as error:
        log_e(f'{error}')
        return False

    if UNSAFE_DEBUG:
        log_d(f'fsynced {ad.out_file_obj}')

    return True


def truncate_output_file(ad: ActData) -> None:
    """
    Truncate the current output file to zero bytes and clear the module
    signal flag that references the file object.

    Flushes the provided binary file-like object and truncates its
    underlying file descriptor to length zero. The file object itself is
    not closed; the caller remains responsible for closing it. After the
    attempt to truncate, the function unconditionally clears the module
    flag `file_obj_to_truncate_by_signal`.

    Parameters
    ----------
    ad : ActData
        Action data containing `out_file_obj`, a binary file-like object
        with a working fileno() method.

    Returns
    -------
    None
        Performs side effects (flush, ftruncate, module-level mutation)
        and does not return a value.

    Behavior and error handling
    ---------------------------
    - If `UNSAFE_DEBUG` is true, a debug message is logged before
      truncation.
    - Attempts to flush `ad.out_file_obj` and then truncate its
      underlying file descriptor via `ftruncate(fileno, 0)`.
    - Any exceptions raised during flush or ftruncate are caught and
      logged with `log_e`; exceptions are not propagated.
    - On success, an informational message is logged with `log_i`.
    - The module-level reference `file_obj_to_truncate_by_signal` is
      cleared (set to None) unconditionally at function exit.

    Concurrency and safety
    ----------------------
    - This function performs non-signal-safe operations (flush, file
      I/O). It must not be called directly from a signal handler.
    - It relies on the following module-level names being defined:
      `ftruncate`, `UNSAFE_DEBUG`, `log_d`, `log_i`, and `log_e`.
    """
    if UNSAFE_DEBUG:
        log_d('truncating output file')

    try:
        ad.out_file_obj.flush()
        ftruncate(ad.out_file_obj.fileno(), 0)
        log_i('output file truncated to 0')
    except Exception as truncate_error:
        log_e(f'cannot truncate output file: {truncate_error}')

    global file_obj_to_truncate_by_signal
    file_obj_to_truncate_by_signal = None


def remove_output_path(ad: ActData) -> None:
    """
    Close the current output file and optionally remove its path from
    disk.

    The function always closes the open output file object stored on the
    provided action data, then asks the user for confirmation (via
    `proceed_request`) before attempting to remove the file from the
    file system. Removal errors are logged and do not propagate.

    Parameters
    ----------
    ad : ActData
        Action data structure containing at least the attribute
        `out_file_obj` (a file-like object with a `.name` attribute).

    Returns
    -------
    None
        This function performs side effects (closing and possibly
        removing a file) and does not return a value.

    Notes
    -----
    - The function calls `close_file` on `ad.out_file_obj` before
      prompting.
    - Confirmation is performed by `proceed_request(PROCEED_REMOVE,
      ad)`.
    - If removal is attempted, success and failures are logged with
      `log_i` and `log_e` respectively; debug information may be logged
      when `UNSAFE_DEBUG` is true.
    - Removal exceptions are caught and logged; they are not re-raised.
    - Depends on globals/helpers: `close_file`, `proceed_request`,
      `remove`, `log_i`, `log_e`, `log_d`, and `UNSAFE_DEBUG`.
    """
    out_file_name: str = ad.out_file_obj.name

    close_file(ad.out_file_obj)

    if proceed_request(proceed_type=PROCEED_REMOVE, ad=ad):
        if UNSAFE_DEBUG:
            log_d(f'removing path {out_file_name!r}')

        try:
            remove(out_file_name)
            log_i(f'path {out_file_name!r} removed')
        except Exception as remove_error:
            log_e(f'cannot remove output file path: {remove_error}')
    else:
        log_i('output file path NOT removed')


# Collect and handle user input
# --------------------------------------------------------------------------- #


def no_eof_input(prompt: str) -> str:
    """
    Prompt for user input and retry on EOF.

    Repeatedly calls built-in input() with the given prompt until a
    non-EOF response is received. If an EOFError occurs, a newline is
    printed and an error is logged before retrying.

    Parameters
    ----------
    prompt : str
        The message displayed to the user.

    Returns
    -------
    str
        The line of text entered by the user.

    Notes
    -----
    - On EOFError the function prints a newline and logs an error using
      `log_e`, then continues prompting.
    - Depends on the global `log_e`.
    """
    while True:
        try:
            return input(prompt)
        except EOFError:
            print()
            log_e('EOFError: '
                  'end of input detected while waiting for user input')
            continue


def no_eof_getpass(prompt: str) -> str:
    """
    Prompt for a passphrase and retry on EOF.

    Repeatedly prompts the user using getpass() until a non-EOF response
    is received. If an EOFError occurs, a newline is printed, an error
    is logged, and the prompt is retried.

    Parameters
    ----------
    prompt : str
        Message shown to the user when asking for the passphrase.

    Returns
    -------
    str
        The passphrase entered by the user.

    Notes
    -----
    - On EOFError the function logs an error and continues prompting.
    - Relies on helper functions/loggers: getpass, log_e.
    """
    while True:
        try:
            return getpass(prompt)
        except EOFError:
            print()
            log_e('EOFError: '
                  'end of input detected while waiting for user input')
            log_e('passphrase NOT accepted')
            continue


def select_action() -> ActionID:
    """
    Prompt the user to select an action from the application menu.

    Repeatedly displays the menu (APP_MENU) and reads user input until a
    valid menu key is entered. When a valid selection is made the
    corresponding action description is logged and the ActionID value is
    returned.

    Parameters
    ----------
    None

    Returns
    -------
    ActionID
        The selected action identifier corresponding to a valid entry in
        the global ACTIONS mapping.

    Notes
    -----
    - Expects a global mapping `ACTIONS` where keys are the user-entered
      menu strings and values are tuples of (ActionID, description).
    - Uses helper globals/functions: APP_MENU, no_eof_input, ACTIONS,
      log_i, log_e.
    - Invalid selections cause an error message to be logged and the
      prompt to repeat.
    """
    error_message: str = 'invalid value; please select a valid option [0-9]'

    # Start an infinite loop to get user input
    while True:
        # Prompt the user to input an action number and remove any
        # leading/trailing whitespace
        input_value: str = no_eof_input(APP_MENU).strip()

        # Check if the entered action is valid
        if input_value in ACTIONS:
            # Get the description of the action
            action_description: str = ACTIONS[input_value][1]

            # Log the action description
            log_i(action_description)

            # Retrieve the action number associated with the user input
            action: ActionID = ACTIONS[input_value][0]

            return action  # Return the valid action number

        # If an invalid value is entered, log an error message
        log_e(error_message)


def get_input_file(action: ActionID) -> tuple[str, int, BinaryIO]:
    """
    Prompt for an input file appropriate to the given action and
    validate it.

    Selects a prompt based on the action, asks the user for a file path,
    validates existence and size, and opens the file in binary read
    mode. For optional input actions (ENCRYPT, ENCRYPT_EMBED) an empty
    response returns an empty path, zero size and an in-memory BytesIO
    object.

    Parameters
    ----------
    action : ActionID
        Action determining required input type. Expected values include
        ENCRYPT, DECRYPT, EMBED, EXTRACT, ENCRYPT_EMBED,
        EXTRACT_DECRYPT.

    Returns
    -------
    tuple[str, int, BinaryIO]
        - in_file_path: The validated input file path (empty string for
          optional empty input when allowed).
        - in_file_size: Size of the input file in bytes (0 for empty
          optional input).
        - in_file_obj: Open file object in 'rb' mode, or a BytesIO for
          empty optional input.

    Notes
    -----
    - The function loops until a valid file is provided or an allowable
      empty input is returned.
    - Relies on helper functions and globals: no_eof_input,
      get_file_size, open_file, log_e, log_d, UNSAFE_DEBUG, BOL, RES,
      BytesIO, and path.realpath.
    """

    # Dictionary mapping actions to corresponding prompt messages
    action_prompts: dict[ActionID, str] = {
        ENCRYPT: 'FILE TO ENCRYPT (OPT)',
        DECRYPT: 'FILE TO DECRYPT',
        EMBED: 'FILE TO EMBED',
        EXTRACT: 'CONTAINER',
        ENCRYPT_EMBED: 'FILE TO ENCRYPT AND EMBED (OPT)',
        EXTRACT_DECRYPT: 'CONTAINER',
    }

    # Get the prompt message based on the action provided
    prompt_message: Optional[str] = action_prompts.get(action)

    # Start an infinite loop to get a valid input file path
    while True:
        # Prompt the user for the input file path
        in_file_path: str = no_eof_input(f'{BOL}D1. {prompt_message}:{RES} ')

        # Check if the input file path is empty
        if not in_file_path:

            if action in (ENCRYPT, ENCRYPT_EMBED):
                return '', 0, BytesIO()

            log_e('input file path not specified')
            continue  # Prompt the user again

        # Log the real path if in UNSAFE_DEBUG mode
        if UNSAFE_DEBUG:
            log_d(f'real path: {path.realpath(in_file_path)!r}')

        # Get the size of the input file
        in_file_size: Optional[int] = get_file_size(in_file_path)

        # Check if the file size could not be determined
        if in_file_size is None:
            continue  # Prompt the user again

        # Attempt to open the input file in binary read mode
        in_file_obj: Optional[BinaryIO] = open_file(in_file_path, 'rb')

        # Check if the file object could be opened
        if in_file_obj is not None:
            # Return the valid file details
            return in_file_path, in_file_size, in_file_obj


def get_raw_comments(basename: str) -> str:
    """
    Prompt the user for comments and return the entered string.

    Prompts the user with a default hint showing the provided basename
    and returns whatever the user enters (may be an empty string).

    Parameters
    ----------
    basename : str
        Basename shown in the prompt as the default comment hint.

    Returns
    -------
    str
        The comments entered by the user (possibly empty).

    Notes
    -----
    - Uses the helper `no_eof_input` and global formatting variables
      `BOL` and `RES` to build the prompt.
    """
    return no_eof_input(
        f"{BOL}D2. COMMENTS (DEFAULT='{basename}'):{RES} ")


def get_output_file_new(action: ActionID) -> tuple[str, BinaryIO]:
    """
    Prompt for a new output file path, create the file, and (optionally)
    set permissions.

    Prompt wording is chosen based on the provided action. The function
    repeatedly asks the user for a path, attempts to create the file
    using exclusive-creation mode ('xb') to avoid overwriting existing
    files, logs the real path in debug mode, and for certain actions
    attempts to set restrictive permissions (0o600). Failure to set
    permissions is logged as a warning and does not cause failure.

    Parameters
    ----------
    action : ActionID
        Action being performed which influences prompt wording and
        permission handling. Examples include ENCRYPT, DECRYPT, EXTRACT,
        EXTRACT_DECRYPT, CREATE_W_RANDOM.

    Returns
    -------
    tuple[str, BinaryIO]
        - out_file_path: The created output file path (as entered).
        - out_file_obj: Open file object created with mode 'xb'.

    Notes
    -----
    - The function loops until a new file is successfully created or the
      process is interrupted.
    - For actions ENCRYPT and CREATE_W_RANDOM, the function attempts to
      set restrictive file permissions (owner read/write only).
      Permission-setting errors are logged but do not raise.
    - Relies on helper functions and globals such as no_eof_input,
      open_file, log_e, log_w, log_d, UNSAFE_DEBUG, BOL, RES, chmod.
    """

    # Determine the prompt message based on the action provided
    if action == ENCRYPT:
        prompt_message: str = 'OUTPUT (ENCRYPTED) FILE'
    elif action in (DECRYPT, EXTRACT_DECRYPT):
        prompt_message = 'OUTPUT (DECRYPTED) FILE'
    else:  # For actions EXTRACT and CREATE_W_RANDOM
        prompt_message = 'OUTPUT FILE'

    # Start an infinite loop to get a valid output file path
    while True:
        # Prompt the user for the output file path
        out_file_path: str = no_eof_input(f'{BOL}D3. {prompt_message}:{RES} ')

        # Check if the input file path is empty
        if not out_file_path:
            log_e('output file path not specified')
            continue  # Prompt the user again

        # Attempt to open the output file in exclusive creation mode
        out_file_obj: Optional[BinaryIO] = open_file(out_file_path, 'xb')

        # Check if the file object was created successfully
        if out_file_obj is not None:

            # Log the real path if in UNSAFE_DEBUG mode
            if UNSAFE_DEBUG:
                log_d(f'real path: {path.realpath(out_file_path)!r}')

            # Set restrictive permissions for new random-looking files:
            # keyfiles, containers, and cryptoblobs
            if action in (ENCRYPT, CREATE_W_RANDOM):
                try:
                    chmod(out_file_path, 0o600)
                except OSError as e:
                    log_w(f'could not set restrictive permissions '
                          f'on {out_file_path!r}: {e}')

            # Return the valid file path and object
            return out_file_path, out_file_obj


def get_output_file_exist(
    in_file_path: str,
    min_out_size: int,
    action: ActionID,
) -> tuple[str, int, BinaryIO]:
    """
    Prompt for an existing output file path and validate it.

    Prompts the user for an output file path (to overwrite), validates
    that the path is not empty, is not the same real path as the input
    file, exists, meets a minimum size, and can be opened for binary
    read/write. The prompt wording changes slightly depending on the
    provided action.

    Parameters
    ----------
    in_file_path : str
        Path to the input file; used to prevent selecting the same real
        path for input and output.
    min_out_size : int
        Minimum required output file size in bytes.
    action : ActionID
        Action type that determines prompt wording (for example EMBED,
        ENCRYPT_EMBED, or OVERWRITE_W_RANDOM).

    Returns
    -------
    tuple[str, int, BinaryIO]
        A tuple containing:
        - out_file_path (str): The validated output file path (as
            entered).
        - out_file_size (int): Size of the output file in bytes.
        - out_file_obj (BinaryIO): Open file object opened in 'rb+'
            mode.

    Notes
    -----
    - The function loops until a valid output file is provided or the
      program is otherwise interrupted.
    - If the real path of the provided output file equals the real path
      of in_file_path, the selection is rejected.
    - The function relies on helper functions and globals such as
      no_eof_input, get_file_size, open_file, log_e, log_d,
      UNSAFE_DEBUG, BOL, RES, EMBED, ENCRYPT_EMBED.
    """

    # Determine the prompt message based on the action provided
    if action in (EMBED, ENCRYPT_EMBED):
        prompt_message: str = 'FILE TO OVERWRITE (CONTAINER)'
    else:  # For action OVERWRITE_W_RANDOM
        prompt_message = 'FILE TO OVERWRITE'

    # Start an infinite loop to get a valid output file path
    while True:
        # Prompt the user for the output file path
        out_file_path: str = no_eof_input(f'{BOL}D3. {prompt_message}:{RES} ')

        # Check if the user input is empty
        if not out_file_path:
            log_e('output file path not specified')
            continue

        # Check if the real output file path is the same as the real
        # input file path
        if path.realpath(out_file_path) == path.realpath(in_file_path):
            log_e('input and output files must not be at the same real path')
            continue

        # Log the real path if in UNSAFE_DEBUG mode
        if UNSAFE_DEBUG:
            log_d(f'real path: {path.realpath(out_file_path)!r}')

        # Get the size of the output file
        out_file_size: Optional[int] = get_file_size(out_file_path)

        # Check if the file size could not be determined
        if out_file_size is None:
            continue

        # Check if the output file size meets the minimum requirement
        if out_file_size < min_out_size:
            # Log an error message
            log_e(f'specified output file is too small ({out_file_size:,} B); '
                  f'size must be >= {min_out_size:,} B')
            continue

        # Attempt to open the output file in binary read/write mode
        out_file_obj: Optional[BinaryIO] = open_file(out_file_path, 'rb+')

        # Check if the file object was created successfully
        if out_file_obj is not None:
            # Return the valid file details
            return out_file_path, out_file_size, out_file_obj


def get_output_file_size() -> int:
    """
    Prompt the user for a desired output file size (bytes) and return
    it.

    Returns
    -------
    int
        Desired output file size in bytes
        (0 <= value <= RAND_OUT_FILE_SIZE_LIMIT).

    Notes
    -----
    - Prompts the user with: `D4. OUTPUT FILE SIZE IN BYTES:`.
    - Re-prompts until a non-empty integer within the inclusive range
      [0, RAND_OUT_FILE_SIZE_LIMIT] is entered.
    - Logs an error via `log_e()` for empty, non-integer, negative, or
      out-of-range input.
    - Uses `no_eof_input()` for interactive input and may block waiting
      for user input.
    - Requires the constant `RAND_OUT_FILE_SIZE_LIMIT` and the logging
      helper `log_e`.
    """
    prompt_message: str = f'{BOL}D4. OUTPUT FILE SIZE IN BYTES:{RES} '

    error_message: str = f'invalid value; must be an integer from ' \
        f'the range [0; {RAND_OUT_FILE_SIZE_LIMIT}]'

    while True:
        # Get user input and remove any leading/trailing whitespace
        input_value: str = no_eof_input(prompt_message).strip()

        # Check if the user input is empty
        if not input_value:
            # Log error for empty input
            log_e(error_message)
            continue

        try:
            # Attempt to convert the user input to an integer
            out_size = int(input_value)

            # Check if the value is within the valid range
            if out_size < 0 or out_size > RAND_OUT_FILE_SIZE_LIMIT:
                log_e(error_message)
                continue

            return out_size  # Return the valid output size
        except ValueError:
            # Log an error if the input cannot be converted to an integer
            log_e(error_message)
            continue


def get_start_position(max_start_pos: int, no_default: bool) -> int:
    """
    Prompt the user for a start position within [0, max_start_pos].

    Parameters
    ----------
    max_start_pos : int
        Maximum allowed start position (inclusive).
    no_default : bool
        If True, the user must enter a value. If False, an empty input
        selects the default value 0.

    Returns
    -------
    int
        Validated start position (0 <= start_pos <= max_start_pos).

    Notes
    -----
    - Prompts:
      - When `no_default` is True:
        `D5. START POSITION [0; {max_start_pos}]:`
      - When `no_default` is False:
        `D5. START POSITION [0; {max_start_pos}], default=0:`
    - Re-prompts on non-integer input or values outside the inclusive
      range.
    - Uses `no_eof_input()` for interactive input and logs errors via
      `log_e`.
    - Function blocks waiting for user input.
    """
    prompt_message_no_default: str = \
        f'{BOL}D5. START POSITION [0; {max_start_pos}]:{RES} '

    prompt_message_default: str = \
        f'{BOL}D5. START POSITION [0; {max_start_pos}], DEFAULT=0:{RES} '

    error_message: str = f'invalid value; must be an integer ' \
        f'from the range [0; {max_start_pos}]'

    while True:
        if no_default:
            input_value: str = \
                no_eof_input(prompt_message_no_default).strip()

            if not input_value:
                log_e(error_message)
                continue
        else:
            input_value = no_eof_input(prompt_message_default).strip()

            # If input is empty, set default value to 0
            if not input_value:
                input_value = '0'

        # Try to convert the input to an integer
        try:
            start_pos: int = int(input_value)
        except ValueError:
            log_e(error_message)
            continue

        # Check if the start position is within the valid range
        if start_pos < 0 or start_pos > max_start_pos:
            log_e(error_message)
            continue

        # Return the valid start position
        return start_pos


def get_end_position(min_pos: int, max_pos: int, no_default: bool) -> int:
    """
    Prompt the user for an end position within a specified inclusive
    range.

    Parameters
    ----------
    min_pos : int
        Minimum valid end position.
    max_pos : int
        Maximum valid end position.
    no_default : bool
        If True, the user must provide a value. If False, an empty input
        selects the default value `max_pos`.

    Returns
    -------
    int
        A valid end position within the range [min_pos, max_pos].

    Notes
    -----
    - Prompts with either:
      - `D6. END POSITION [min_pos; max_pos]:` when `no_default` is
        True, or
      - `D6. END POSITION [min_pos; max_pos], default=max_pos:` when
        False.
    - Re-prompts on non-integer input or values outside the inclusive
      range.
    - Uses `no_eof_input()` for interactive input and logs errors via
      `log_e`.
    - Function blocks waiting for user input.
    """
    prompt_message_no_default: str = f'{BOL}D6. END POSITION [{min_pos}; ' \
        f'{max_pos}]:{RES} '

    prompt_message_default: str = f'{BOL}D6. END POSITION [{min_pos}; ' \
        f'{max_pos}], DEFAULT={max_pos}:{RES} '

    error_message: str = f'invalid value; must be an integer from ' \
        f'the range [{min_pos}; {max_pos}]'

    input_value: str

    while True:
        if no_default:
            input_value = no_eof_input(prompt_message_no_default).strip()
        else:
            input_value = no_eof_input(prompt_message_default).strip()

            if not input_value:
                input_value = str(max_pos)

        # Try to convert the input to an integer
        try:
            end_pos: int = int(input_value)
        except ValueError:
            log_e(error_message)
            continue

        # Check if the end position is within the valid range
        if end_pos < min_pos or end_pos > max_pos:
            log_e(error_message)
            continue

        # Return the valid end position
        return end_pos


def collect_and_handle_ikm(
    action: ActionID,
    blake2_salt: bytes,
) -> list[bytes]:
    """
    Collect input keying material (keyfiles and passphrases) and return
    their digests.

    Parameters
    ----------
    action : ActionID
        Action identifier that determines context (e.g., ENCRYPT,
        DECRYPT).
    blake2_salt : bytes
        Salt value passed to BLAKE2b when hashing keyfiles and
        passphrases.

    Returns
    -------
    list[bytes]
        List of digests (bytes) corresponding to accepted keyfiles
        and/or
        passphrases. May be empty. The function never raises; it logs
        errors and skips invalid inputs.

    Notes
    -----
    - Prompts the user for zero or more keyfile paths (interactive). For
      each:
      - If the path is a file, computes its digest via
        `get_keyfile_digest`.
      - If the path is a directory, recursively scans and hashes files
        via `get_keyfile_digest_list`; if that helper fails the
        directory is rejected.
      - On success, appends resulting digest(s) to the returned list and
        logs acceptance.
    - Prompts the user for an optional passphrase (interactive). If
      provided:
      - Asks for confirmation and normalizes/encodes both entries using
        `handle_raw_passphrase`.
      - Compares encoded values with `compare_digest` to avoid timing
        leaks.
      - If they match, computes the passphrase digest via
        `get_passphrase_digest` and appends it to the returned list.
    - Logs verbose debug information when `UNSAFE_DEBUG` is enabled.
    - If no keying material is collected and `action` is an encryption
      action (`ENCRYPT` or `ENCRYPT_EMBED`), a warning is logged.
    - Requires helpers/constants: `no_eof_input`, `no_eof_getpass`,
      `path.exists`, `path.isdir`, `get_keyfile_digest`,
      `get_keyfile_digest_list`, `handle_raw_passphrase`,
      `get_passphrase_digest`, `compare_digest`, and logging functions
      `log_i`, `log_w`, `log_d`, `log_e`, plus `UNSAFE_DEBUG`.
    """
    if UNSAFE_DEBUG:
        log_d('collecting IKM')

    # List to store the digests of keying material
    ikm_digest_list: list[bytes] = []

    # Handle keyfile paths
    # ----------------------------------------------------------------------- #

    while True:
        # Prompt for the keyfile path
        keyfile_path: str = \
            no_eof_input(f'{BOL}K1. KEYFILE PATH (OPT):{RES} ')

        if not keyfile_path:
            break  # Exit the loop if the user does not enter a path

        if not path.exists(keyfile_path):
            # Log error if the keyfile path does not exist
            log_e(f'file {keyfile_path!r} not found')
            log_e('keyfile NOT accepted')
            continue

        if UNSAFE_DEBUG:
            log_d(f'real path: {path.realpath(keyfile_path)!r}')

        # Handle existing path (directory or individual file)
        # ------------------------------------------------------------------- #

        if path.isdir(keyfile_path):
            # If the path is a directory, get the digests of all keyfiles
            # within it
            digest_list: Optional[list[bytes]] = get_keyfile_digest_list(
                directory_path=keyfile_path,
                blake2_salt=blake2_salt,
            )

            if digest_list is None:
                log_e('keyfiles NOT accepted')
                continue

            if digest_list:
                ikm_digest_list.extend(digest_list)

                log_i(f'{len(digest_list)} keyfiles accepted')
            else:
                log_w('directory is empty; no keyfiles to accept!')
        else:
            # If the path is a file, get its digest
            file_digest: Optional[bytes] = get_keyfile_digest(
                file_path=keyfile_path,
                blake2_salt=blake2_salt,
            )

            if file_digest is None:
                log_e('keyfile NOT accepted')
            else:
                # Add the file digest to the list
                ikm_digest_list.append(file_digest)
                log_i('keyfile accepted')
            continue

    # Handle passphrases
    # ----------------------------------------------------------------------- #

    if UNSAFE_DEBUG:
        log_w('entered passphrases will be displayed!')

    while True:
        raw_passphrase_1: str = \
            no_eof_getpass(f'{BOL}K2. PASSPHRASE (OPT):{RES} ')

        if not raw_passphrase_1:
            break  # Exit the loop if the user does not enter a passphrase

        # Normalize, encode, truncate
        encoded_passphrase_1: bytes = handle_raw_passphrase(raw_passphrase_1)

        # Prompt for confirming the passphrase
        raw_passphrase_2: str = \
            no_eof_getpass(f'{BOL}K2. CONFIRM PASSPHRASE:{RES} ')

        encoded_passphrase_2: bytes = handle_raw_passphrase(raw_passphrase_2)

        if compare_digest(encoded_passphrase_1, encoded_passphrase_2):
            passphrase_digest: bytes = get_passphrase_digest(
                passphrase=encoded_passphrase_1,
                blake2_salt=blake2_salt,
            )
            ikm_digest_list.append(passphrase_digest)
            log_i('passphrase accepted')
            break

        log_e('passphrase NOT accepted: confirmation failed')

    # Log results
    # ----------------------------------------------------------------------- #

    if UNSAFE_DEBUG:
        log_d('collecting IKM completed')

    if UNSAFE_DEBUG:
        log_d(f'{len(ikm_digest_list)} IKM digests collected')

    if not ikm_digest_list and action in (ENCRYPT, ENCRYPT_EMBED):
        log_w('no keyfile or passphrase specified!')

    return ikm_digest_list


def get_argon2_time_cost(action: ActionID) -> int:
    """
    Prompt for and validate the Argon2 time-cost parameter and return
    it.

    Parameters
    ----------
    action : ActionID
        Current action identifier. Used to determine whether to warn
        when a non-default value is chosen for an encryption action.

    Returns
    -------
    int
        Accepted Argon2 time-cost value.

    Notes
    -----
    - Prompts the user with:
      `K3. TIME COST (DEFAULT={DEFAULT_ARGON2_TIME_COST}):`
      and accepts an empty input or the textual default as the
      predefined `DEFAULT_ARGON2_TIME_COST`.
    - Validates that the entered value is an integer in the inclusive
      range [MIN_ARGON2_TIME_COST, argon2id.OPSLIMIT_MAX]. On invalid
      input the function logs an error and re-prompts.
    - Logs the chosen `time_cost` using `log_i()`. If `action` is an
      encryption action (`ENCRYPT` or `ENCRYPT_EMBED`) and a non-default
      value is chosen, logs a warning via `log_w()` that decryption will
      require the same value.
    - Uses `no_eof_input()` for interactive input and logging helpers
      `log_i`, `log_w`, and `log_e`.
    - The function is interactive and may block waiting for user input.
    """
    prompt_message: str = \
        f'{BOL}K3. TIME COST (DEFAULT={DEFAULT_ARGON2_TIME_COST}):{RES} '

    error_message: str = \
        f'invalid value; must be an integer from the ' \
        f'range [{MIN_ARGON2_TIME_COST}; {argon2id.OPSLIMIT_MAX}]'

    # Start an infinite loop to get user input
    while True:
        # Get user input and remove any leading/trailing whitespace
        input_value: str = no_eof_input(prompt_message).strip()

        # Return default value if input is empty or matches the default
        if input_value in ('', str(DEFAULT_ARGON2_TIME_COST)):
            time_cost: int = DEFAULT_ARGON2_TIME_COST
            break

        try:
            # Convert input to integer
            time_cost = int(input_value)
        except ValueError:
            log_e(error_message)
            continue

        # Check if the value is within the valid range
        if (time_cost < MIN_ARGON2_TIME_COST or
                time_cost > argon2id.OPSLIMIT_MAX):
            log_e(error_message)
            continue

        break

    log_i(f'time cost: {time_cost}')

    if action in (ENCRYPT, ENCRYPT_EMBED) and \
            time_cost != DEFAULT_ARGON2_TIME_COST:
        log_w('decryption will require the same "TIME COST" value!')

    return time_cost


def proceed_request(proceed_type: bool, ad: ActData) -> bool:
    """
    Prompt the user to confirm whether to proceed with an operation.

    Parameters
    ----------
    proceed_type : bool
        Indicator of the confirmation type. Expected values:
        - `PROCEED_OVERWRITE`: warn user that an existing output file
          will be partially overwritten (default answer: no).
        - `PROCEED_REMOVE`: inform user that an output file path will be
          removed (default answer: yes when Enter pressed).
    ad : ActData
        Action/state container used for contextual logging (provides
        `ad.action`, `ad.start_pos`, `ad.max_end_pos`, etc.).

    Returns
    -------
    bool
        True if the user confirms to proceed, False otherwise.

    Notes
    -----
    - Prompts differ by `proceed_type`. For `PROCEED_OVERWRITE` a
      warning is logged (more specific message for `ENCRYPT_EMBED`) and
      the prompt default is not to proceed. For `PROCEED_REMOVE` an
      informational message is logged and the prompt accepts Enter as a
      default yes.
    - Accepts affirmative answers in `TRUE_ANSWERS` and negative answers
      in `FALSE_ANSWERS`. If no input is provided and `proceed_type` is
      `PROCEED_REMOVE`, the function returns True.
    - Invalid responses produce an error log and re-prompt.
    - Requires helpers/constants: `no_eof_input`, `TRUE_ANSWERS`,
      `FALSE_ANSWERS`, `VALID_BOOL_ANSWERS`, `PROCEED_OVERWRITE`,
      `PROCEED_REMOVE`, `ENCRYPT_EMBED`, and logging functions `log_i`,
      `log_w`, `log_e`. The function blocks on user input.
    """

    # Check the action type to determine the appropriate prompt message
    if proceed_type is PROCEED_OVERWRITE:
        if ad.action == ENCRYPT_EMBED:
            log_w(f'output file will be overwritten from '
                  f'{ad.start_pos} to {ad.max_end_pos}!')
        else:
            log_w('output file will be partially overwritten!')

        prompt_message: str = f'{BOL}P0. PROCEED OVERWRITING? (Y/N):{RES} '
    else:
        log_i('removing output file path')

        prompt_message = f'{BOL}P0. PROCEED REMOVING? (Y/N, DEFAULT=Y):{RES} '

    while True:
        # Get user input and remove any leading/trailing whitespace
        input_value: str = no_eof_input(prompt_message).strip()

        # Check if the user wants to proceed (affirmative response)
        if input_value in TRUE_ANSWERS:
            return True

        # If no input is given and proceed_type is PROCEED_REMOVE,
        # default to proceeding
        if not input_value and proceed_type is PROCEED_REMOVE:
            return True

        # Check if the user wants to cancel (negative response)
        if input_value in FALSE_ANSWERS:
            return False

        # Log an error message for invalid input
        if proceed_type is PROCEED_OVERWRITE:
            log_e(f'invalid value; valid values are: {VALID_BOOL_ANSWERS}')
        else:
            log_e(f'invalid value; valid values are: {VALID_BOOL_ANSWERS}, '
                  f'or press Enter for default (Y)')


# Handle key derivation - from salts and IKM to working keys
# --------------------------------------------------------------------------- #


def get_salts(
    input_size: int,
    end_pos: Optional[int],
    ad: ActData,
    crypt: Crypto,
) -> tuple[ActData, Crypto]:
    """
    Retrieve or generate salts used for Argon2 and BLAKE2 operations.

    Parameters
    ----------
    input_size : int
        Total size of the input data; used to compute the position from
        which to read the trailing BLAKE2 salt when decrypting.
    end_pos : Optional[int]
        End position within the cryptoblob; required for EXTRACT_DECRYPT
        to compute the BLAKE2 salt position. May be None for encrypting
        actions.
    ad : ActData
        Action/state container providing `ad.action` and
        `ad.in_file_obj`. On error `ad.err` will be set to True.
    crypt : Crypto
        Mutable container where retrieved/generated salts will be
        stored:
        - `crypt.argon2_salt` (bytes)
        - `crypt.blake2_salt` (bytes)

    Returns
    -------
    tuple[ActData, Crypto]
        Tuple `(ad, crypt)` where `crypt` contains `argon2_salt` and
        `blake2_salt` on success. On failure `ad.err` is set to True and
        the returned `crypt` may be unchanged.

    Notes
    -----
    - For actions ENCRYPT and ENCRYPT_EMBED the function generates new
      random salts (`SALT_SIZE` bytes each) using `token_bytes`.
    - For actions DECRYPT and EXTRACT_DECRYPT the function reads:
      - `argon2_salt` from the start of the cryptoblob (current
        `ad.in_file_obj` position),
      - `blake2_salt` from a trailing position:
        - DECRYPT: `input_size - SALT_SIZE`
        - EXTRACT_DECRYPT: `end_pos - SALT_SIZE` (requires `end_pos`
          not None).
    - The function seeks the input file object as needed and restores
      the position after reading the salts. If any read or seek fails,
      `ad.err` is set to True and `(ad, crypt)` is returned early.
    - Emits debug logs when `UNSAFE_DEBUG` is enabled and requires helpers:
      `seek_position`, `read_data`, and `token_bytes`, plus constants
      `SALT_SIZE`, `ENCRYPT`, `ENCRYPT_EMBED`, `DECRYPT`,
      `EXTRACT_DECRYPT`.
    """

    # Log the start of getting salts if debugging is enabled
    if UNSAFE_DEBUG:
        log_d('getting salts')

    # Check if the action requires generating new salts
    if ad.action in (ENCRYPT, ENCRYPT_EMBED):
        # Generate random salts for Argon2 and BLAKE2 functions
        argon2_salt: bytes = token_bytes(SALT_SIZE)
        blake2_salt: bytes = token_bytes(SALT_SIZE)
    else:
        # Read the salts from the cryptoblob for actions DECRYPT and
        # EXTRACT_DECRYPT
        opt_argon2_salt: Optional[bytes]
        opt_blake2_salt: Optional[bytes]

        if UNSAFE_DEBUG:
            log_d('reading argon2_salt from start of cryptoblob')

        # Try to read argon2_salt from the cryptoblob
        opt_argon2_salt = read_data(ad.in_file_obj, SALT_SIZE)

        # On failure, sets ad.err = True and returns early
        if opt_argon2_salt is None:
            ad.err = True
            return ad, crypt

        # Store argon2_salt
        argon2_salt = opt_argon2_salt

        # Log that the argon2_salt has been read if debugging is enabled
        if UNSAFE_DEBUG:
            log_d('argon2_salt read')

        # Save the current position in the cryptoblob
        pos_after_argon2_salt: int = ad.in_file_obj.tell()

        # Determine the new position based on the action
        if ad.action == DECRYPT:
            pos_before_blake2_salt: int = input_size - SALT_SIZE
        else:  # action == EXTRACT_DECRYPT
            if end_pos is None:
                raise TypeError

            pos_before_blake2_salt = end_pos - SALT_SIZE

        # Move to the position for reading blake2_salt
        if not seek_position(ad.in_file_obj, offset=pos_before_blake2_salt):
            ad.err = True
            return ad, crypt

        if UNSAFE_DEBUG:
            log_d('reading blake2_salt from end of cryptoblob')

        # Try to read blake2_salt from the cryptoblob
        opt_blake2_salt = read_data(ad.in_file_obj, SALT_SIZE)

        # Return False if reading blake2_salt fails
        if opt_blake2_salt is None:
            ad.err = True
            return ad, crypt

        # Store blake2_salt
        blake2_salt = opt_blake2_salt

        # Log that blake2_salt has been read if debugging is enabled
        if UNSAFE_DEBUG:
            log_d('blake2_salt read')

        # Move back to the previously saved position
        if not seek_position(ad.in_file_obj, offset=pos_after_argon2_salt):
            ad.err = True
            return ad, crypt

    # Log the salts if debugging is enabled
    if UNSAFE_DEBUG:
        log_d(f'salts:\n'
              f'        argon2_salt: {argon2_salt.hex()}\n'
              f'        blake2_salt: {blake2_salt.hex()}')
        log_d('getting salts completed')

    crypt.argon2_salt = argon2_salt
    crypt.blake2_salt = blake2_salt

    return ad, crypt


def hash_keyfile_contents(
    file_obj: BinaryIO,
    file_size: int,
    blake2_salt: bytes,
) -> Optional[bytes]:
    """
    Compute the BLAKE2b digest of a keyfile's contents, reading in
    chunks.

    Parameters
    ----------
    file_obj : BinaryIO
        File object opened in binary mode to read the keyfile contents
        from.
    file_size : int
        Total size of the file in bytes.
    blake2_salt : bytes
        Salt value passed to BLAKE2b.

    Returns
    -------
    Optional[bytes]
        The BLAKE2b digest of the file contents with length
        `IKM_DIGEST_SIZE`, or `None` if an error occurs while reading
        from `file_obj`.

    Notes
    -----
    - Initializes BLAKE2b with `digest_size=IKM_DIGEST_SIZE`,
      `person=PERSON_KEYFILE`, and `salt=blake2_salt`.
    - Reads the file in chunks of `MAX_PT_CHUNK_SIZE` (last chunk may be
      smaller), updating the hash with each chunk via
      `hash_obj.update(...)`.
    - Uses helper `read_data(file_obj, size)` to read chunks; if it
      returns `None` the function returns `None`.
    - Returns the final digest from `hash_obj.digest()`.
    - Requires constants/functions: `IKM_DIGEST_SIZE`, `PERSON_KEYFILE`,
      `MAX_PT_CHUNK_SIZE`, and `read_data`.
    """

    # Create a BLAKE2 hash object with the specified digest size,
    # personalization, and salt
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        person=PERSON_KEYFILE,
        salt=blake2_salt,
    )

    # Calculate the number of complete chunks and remaining bytes to read
    full_chunks: int = file_size // MAX_PT_CHUNK_SIZE
    remain_size: int = file_size % MAX_PT_CHUNK_SIZE

    # Read and process each complete chunk of the file
    for _ in range(full_chunks):
        # Read a chunk of data from the file
        chunk_data: Optional[bytes] = read_data(file_obj, MAX_PT_CHUNK_SIZE)

        # If reading the chunk fails, return None
        if chunk_data is None:
            return None

        # Update the hash object with the data from the chunk
        hash_obj.update(chunk_data)

    # If there are remaining bytes, read and process them
    if remain_size:
        # Read the remaining bytes from the file
        chunk_data = read_data(file_obj, remain_size)

        # If reading the remaining bytes fails, return None
        if chunk_data is None:
            return None

        # Update the hash object with the remaining data
        hash_obj.update(chunk_data)

    # Compute the final BLAKE2 digest
    keyfile_digest: bytes = hash_obj.digest()

    # Return the computed digest
    return keyfile_digest


def get_keyfile_digest(file_path: str, blake2_salt: bytes) -> Optional[bytes]:
    """
    Compute and return the BLAKE2-based digest of a keyfile's contents.

    Parameters
    ----------
    file_path : str
        Path to the keyfile to read and hash.
    blake2_salt : bytes
        Salt value passed to the file-hashing helper
        (`hash_keyfile_contents`).

    Returns
    -------
    Optional[bytes]
        The computed digest bytes on success, or `None` if any step
        fails (file missing/unreadable, size unavailable, or hashing
        error).

    Notes
    -----
    - Steps performed:
      1. Obtain file size via `get_file_size(file_path)`.
      2. Open file with `open_file(file_path, 'rb')`.
      3. Compute digest using `hash_keyfile_contents(file_obj,
         file_size, blake2_salt)`.
      4. Close the file with `close_file(file_obj)` and return the
         digest.
    - Logs file path and size via `log_i`, and the hex digest via
      `log_d` when `UNSAFE_DEBUG` is enabled.
    - Any failure from the helper functions causes an immediate return
      of `None`.
    - The exact hash algorithm and digest length are determined by
      `hash_keyfile_contents`.
    """

    # Get the size of the file at the specified path
    file_size: Optional[int] = get_file_size(file_path)

    # If the file size could not be determined, return None
    if file_size is None:
        return None

    # Log the file path and its size for informational purposes
    log_i(f'path: {file_path!r}; size: {format_size(file_size)}')
    log_i(f'reading and hashing contents of {file_path!r}')

    # Open the file in binary read mode
    file_obj: Optional[BinaryIO] = open_file(file_path, 'rb')

    # If the file could not be opened, return None
    if file_obj is None:
        return None

    # Compute the digest of the keyfile
    file_digest: Optional[bytes] = hash_keyfile_contents(
        file_obj=file_obj,
        file_size=file_size,
        blake2_salt=blake2_salt,
    )

    # Close the file after reading
    close_file(file_obj)

    # If the digest could not be computed, return None
    if file_digest is None:
        return None

    if UNSAFE_DEBUG:
        log_d(f'digest of {file_path!r} contents:'
              f'\n        {file_digest.hex()}')

    return file_digest


def get_keyfile_digest_list(
    directory_path: str,
    blake2_salt: bytes,
) -> Optional[list[bytes]]:
    """
    Scan a directory for keyfiles, compute and return a list of their
    digests.

    Parameters
    ----------
    directory_path : str
        Path to the directory to scan (recursive). Symbolic links are
        followed according to os.walk behavior.
    blake2_salt : bytes
        Salt passed to the file-hashing helper (used by
        hash_keyfile_contents).

    Returns
    -------
    Optional[list[bytes]]
        List of digest bytes for each successfully processed regular
        file found under `directory_path` (order is arbitrary). Returns
        an empty list if no files are found. Returns `None` if any error
        occurs during traversal, file opening, sizing, or hashing (the
        function aborts on first failure).

    Notes
    -----
    - Traverses `directory_path` with `walk(directory_path,
      onerror=walk_error_handler)`. `walk_error_handler` logs the error
      and raises `KeyfileScanError`, which causes the function to return
      `None`.
    - Uses helpers: `get_file_size`, `open_file`, `close_file`, and
      `hash_keyfile_contents(file_obj, size, blake2_salt)`; any failure
      from these helpers results in returning `None`.
    - Logs progress and file sizes via `log_i` and verbose details via
      `log_d` when `UNSAFE_DEBUG` is enabled.
    - Performs blocking I/O; do not call from signal handlers.
    - The digest algorithm and length are determined by
      `hash_keyfile_contents`.
    """
    def walk_error_handler(error: Any) -> None:
        """
        Handle walk error by logging the error and raising an exception.
        """
        log_e(f'{error}')
        raise KeyfileScanError

    # Collect file paths
    # ----------------------------------------------------------------------- #

    log_i(f'scanning directory {directory_path!r}')

    # Initialize a list to store the paths of found keyfiles
    file_path_list: list[str] = []

    try:
        # Traverse the directory and collect file paths
        for root, _, files in walk(directory_path, onerror=walk_error_handler):
            for file_name in files:
                # Construct the full file path and add it to the list
                full_file_path: str = path.join(root, file_name)
                file_path_list.append(full_file_path)
    except KeyfileScanError:
        # Return None if an exception is raised during directory traversal
        return None

    # Get the number of files found
    file_count: int = len(file_path_list)

    log_i(f'found {file_count} files')

    # If no files are found, return an empty list
    if not file_count:
        return []

    # Get file sizes
    # ----------------------------------------------------------------------- #

    # Initialize a list to store file information (path and size)
    file_info_list: list[tuple[str, int]] = []

    # Initialize a variable to keep track of the total size of files
    total_size: int = 0

    # Iterate over the collected file paths to get their sizes
    for full_file_path in file_path_list:
        if UNSAFE_DEBUG:
            log_d(f'getting size of {full_file_path!r} '
                  f'(real path: {path.realpath(full_file_path)!r})')

        # Get the size of the current file
        optional_file_size: Optional[int] = get_file_size(full_file_path)

        # If the file size cannot be determined, return None
        if optional_file_size is None:
            return None

        # Store the file size
        file_size: int = optional_file_size

        if UNSAFE_DEBUG:
            log_d(f'size: {format_size(file_size)}')

        # Add the file size to the total size
        total_size += file_size

        # Create a tuple of the file path and size, and add it to the list
        file_info: tuple[str, int] = (full_file_path, file_size)

        # Add a tuple to the list
        file_info_list.append(file_info)

    log_i('list of these files:')

    # Log the details of each found file
    for file_info in file_info_list:
        full_file_path, file_size = file_info
        log_i(f'\r      '
              f'- path: {full_file_path!r}; size: {format_size(file_size)}')

    log_i(f'total size: {format_size(total_size)}')

    # Get digest list
    # ----------------------------------------------------------------------- #

    log_i(f'hashing files in directory {directory_path!r}')

    # Initialize a list to store the computed digests
    digest_list: list[bytes] = []

    # Iterate over the file information to compute digests
    for file_info in file_info_list:
        full_file_path, file_size = file_info

        if UNSAFE_DEBUG:
            log_d(f'reading and hashing contents of {full_file_path!r}')

        # Open the file for reading in binary mode
        file_obj: Optional[BinaryIO] = open_file(full_file_path, 'rb')

        # If the file cannot be opened, return None
        if file_obj is None:
            return None

        # Compute the digest of the keyfile
        file_digest: Optional[bytes] = hash_keyfile_contents(
            file_obj=file_obj,
            file_size=file_size,
            blake2_salt=blake2_salt,
        )

        # Close the file after reading
        close_file(file_obj)

        # If the digest could not be computed, return None
        if file_digest is None:
            return None

        if UNSAFE_DEBUG:
            log_d(f'digest of {full_file_path!r} contents:\n'
                  f'        {file_digest.hex()}')

        # Add the computed digest to the list
        digest_list.append(file_digest)

    # Return the list of computed digests
    return digest_list


def handle_raw_passphrase(raw_passphrase: str) -> bytes:
    """
    Normalize, encode, and truncate a raw passphrase for cryptographic
    use.

    Parameters
    ----------
    raw_passphrase : str
        Input passphrase string. May contain any Unicode characters and
        is not stripped of whitespace.

    Returns
    -------
    bytes
        UTF-8 encoded, Unicode-normalized passphrase truncated to at
        most `PASSPHRASE_SIZE_LIMIT` bytes.

    Notes
    -----
    - Normalization uses `normalize(UNICODE_NF, raw_passphrase)` to
      ensure canonical equivalence.
    - The function encodes the normalized string with UTF-8 and then
      truncates the resulting bytes to `PASSPHRASE_SIZE_LIMIT`.
    - An empty input string returns `b''`.
    - When `UNSAFE_DEBUG` is enabled, raw, normalized, and truncated forms and
      their byte lengths are logged.
    - Requires `normalize`, `UNICODE_NF`, `PASSPHRASE_SIZE_LIMIT`, and
      `UNSAFE_DEBUG`.
    """

    # Normalize the raw passphrase using Unicode Normalization Form
    normalized_passphrase: str = normalize(UNICODE_NF, raw_passphrase)

    # Encode the normalized passphrase to bytes and truncate to the size limit
    encoded_passphrase: bytes = \
        normalized_passphrase.encode('utf-8')[:PASSPHRASE_SIZE_LIMIT]

    # Log details if debugging is enabled
    if UNSAFE_DEBUG:
        log_d(f'passphrase (raw):\n'
              f'        {raw_passphrase!r}')
        raw_pp_len: int = len(raw_passphrase.encode('utf-8'))
        log_d(f'length: {raw_pp_len:,} B')

        log_d(f'passphrase (normalized):\n'
              f'        {normalized_passphrase!r}')
        normalized_pp_len: int = len(normalized_passphrase.encode('utf-8'))
        log_d(f'length: {normalized_pp_len:,} B')

        log_d(f'passphrase (normalized, encoded, truncated):\n'
              f'        {encoded_passphrase!r}')
        log_d(f'length: {len(encoded_passphrase):,} B')

    return encoded_passphrase


def get_passphrase_digest(passphrase: bytes, blake2_salt: bytes) -> bytes:
    """
    Compute the BLAKE2b digest of a passphrase using a specified salt
    and personalization.

    Parameters
    ----------
    passphrase : bytes
        Passphrase to hash.
    blake2_salt : bytes
        Salt value passed to BLAKE2b.

    Returns
    -------
    bytes
        BLAKE2b digest of the passphrase with length `IKM_DIGEST_SIZE`.

    Notes
    -----
    - Initializes BLAKE2b with `digest_size=IKM_DIGEST_SIZE`,
      `person=PERSON_PASSPHRASE`, and `salt=blake2_salt`, then updates
      it with `passphrase` and returns `.digest()`.
    - Logs the hex digest when `UNSAFE_DEBUG` is enabled.
    - Requires `blake2b`, `IKM_DIGEST_SIZE`, and `PERSON_PASSPHRASE` to
      be available.
    """

    # Create a BLAKE2 hash object with the specified
    # digest size, personalization, and salt
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        person=PERSON_PASSPHRASE,
        salt=blake2_salt,
    )

    # Update the hash object with the provided passphrase
    hash_obj.update(passphrase)

    # Compute the final digest of the passphrase
    digest: bytes = hash_obj.digest()

    if UNSAFE_DEBUG:
        log_d(f'passphrase digest:\n        {digest.hex()}')

    return digest


def sort_digest_list(digest_list: list[bytes]) -> list[bytes]:
    """
    Sort a list of byte-sequence digests in ascending byte order.

    Parameters
    ----------
    digest_list : list[bytes]
        List of byte sequences (digests) to sort in-place. May be empty.

    Returns
    -------
    list[bytes]
        The same list object sorted in ascending byte order.

    Notes
    -----
    - Sorting is performed in-place using list.sort(), preserving the
      original list object reference.
    - An empty list is returned immediately.
    - When `UNSAFE_DEBUG` is enabled the function logs the sorting steps
      and each sorted digest in hexadecimal.
    """
    if not digest_list:
        if UNSAFE_DEBUG:
            log_d('digest list is empty, nothing to sort')

        return digest_list

    if UNSAFE_DEBUG:
        log_d('sorting IKM digests')

    # Sort the digest list in place in ascending order
    digest_list.sort(key=None, reverse=False)

    # Log sorted digests if debugging is enabled
    if UNSAFE_DEBUG:
        log_d('sorted IKM digests:')
        for digest in digest_list:
            log_d(f'\r      - {digest.hex()}')

    return digest_list


def hash_digest_list(digest_list: list[bytes], blake2_salt: bytes) -> bytes:
    """
    Compute a BLAKE2b hash over a list of digests using the provided salt.

    Parameters
    ----------
    digest_list : list[bytes]
        Ordered list of binary digests to include in the hash.
    blake2_salt : bytes
        Salt value passed to BLAKE2b.

    Returns
    -------
    bytes
        BLAKE2b digest with length `IKM_DIGEST_SIZE`.

    Notes
    -----
    - The hash is computed without additional personalization string.
    - Preserves input order; callers should sort the list beforehand if
      a stable, order-independent result is required.
    """
    if UNSAFE_DEBUG:
        log_d('hashing digest list')

    # Create a new BLAKE2 hash object with specified digest size and salt
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        salt=blake2_salt,
    )

    # Update the hash object with each byte sequence in the digest list
    for digest in digest_list:
        hash_obj.update(digest)

    # Finalize the hash and obtain the digest
    digest_list_hash: bytes = hash_obj.digest()

    if UNSAFE_DEBUG:
        log_d(f'list containing {len(digest_list)} digests hashed')

    return digest_list_hash


def get_argon2_password(action: ActionID, blake2_salt: bytes) -> bytes:
    """
    Compute the Argon2 password (IKM) from collected keying-material
    digests.

    Parameters
    ----------
    action : ActionID
        Identifier of the action whose keying material should be
        collected.
    blake2_salt : bytes
        Salt used when hashing the collected digests (passed to
        BLAKE2-based helper).

    Returns
    -------
    bytes
        The Argon2 password bytes produced by hashing the sorted list of
        collected digests with the provided `blake2_salt`.

    Notes
    -----
    - Calls `collect_and_handle_ikm(action, blake2_salt)` to obtain a
      list of digests, then `sort_digest_list(...)` to produce a stable
      ordering.
    - Computes the final password with
      `hash_digest_list(sorted_digest_list, blake2_salt)`.
    - Logs the hex-encoded argon2_password when UNSAFE_DEBUG is enabled.
    - Requires helper functions `collect_and_handle_ikm`,
      `sort_digest_list`, and `hash_digest_list` to be available in
      scope.
    """
    digest_list: list[bytes] = collect_and_handle_ikm(
        action=action,
        blake2_salt=blake2_salt,
    )

    sorted_digest_list: list[bytes] = sort_digest_list(digest_list)

    argon2_password: bytes = hash_digest_list(
        digest_list=sorted_digest_list,
        blake2_salt=blake2_salt,
    )

    if UNSAFE_DEBUG:
        log_d(f'argon2_password:\n        {argon2_password.hex()}')

    return argon2_password


def derive_keys(ad: ActData, crypt: Crypto) -> tuple[ActData, Crypto]:
    """
    Derive symmetric keys from Argon2 input and store them in the Crypto
    state.

    Parameters
    ----------
    ad : ActData
        Mutable action/state container used by the caller. On error
        `ad.err` will be set to True.
    crypt : Crypto
        Mutable container providing Argon2 inputs and receiving derived
        keys. Must provide:
        - argon2_password : bytes
            Password/input for Argon2 KDF.
        - argon2_salt : bytes
            Salt for Argon2 KDF.
        - argon2_time_cost : int
            Ops/time cost parameter for Argon2 (used as `opslimit`).
        After successful return, `crypt` will have keys set by
        `derive_working_keys(argon2_tag, crypt)`:
        - mac_key, enc_key, enc_key_hash : bytes

    Returns
    -------
    tuple[ActData, Crypto]
        (ad, crypt). On success `ad.err` remains unchanged. On Argon2
        failure `ad.err` is set to True and the original `crypt` is
        returned.

    Notes
    -----
    - Performs an Argon2id KDF using `argon2id.kdf`.
    - Logs the operation start/finish and elapsed time.
    - On success calls `derive_working_keys(argon2_tag, crypt)` to
      populate working keys.
    - On Argon2 runtime errors sets `ad.err = True`, logs the error, and
      returns early.
    - Requires constants/functions `ARGON2_TAG_SIZE`,
      `ARGON2_MEMORY_COST`, `monotonic`, `format_time`, and
      `derive_working_keys`, and that `UNSAFE_DEBUG`/logging functions
      are available.
    """
    log_i('deriving keys (time-consuming)')

    start_time: float = monotonic()

    try:
        argon2_tag: bytes = argon2id.kdf(
            size=ARGON2_TAG_SIZE,
            password=crypt.argon2_password,
            salt=crypt.argon2_salt,
            opslimit=crypt.argon2_time_cost,
            memlimit=ARGON2_MEMORY_COST,
        )
    except RuntimeError as error:
        ad.err = True
        log_e(f'{error}')
        return ad, crypt

    crypt = derive_working_keys(argon2_tag=argon2_tag, crypt=crypt)

    end_time: float = monotonic()

    log_i(f'keys derived in {format_time(end_time - start_time)}')

    return ad, crypt


def hkdf_sha256(input_key: bytes, info: bytes, length: int) -> bytes:
    """
    Derive bytes using HKDF with SHA-256 (empty salt).

    Parameters
    ----------
    input_key : bytes
        Input keying material (IKM) for HKDF.
    info : bytes
        Contextual information (HKDF info). May be empty or any length.
    length : int
        Number of bytes to derive. Must be > 0.

    Returns
    -------
    bytes
        Derived key of exactly `length` bytes.

    Notes
    -----
    - Uses an empty salt (salt=None) when constructing the HKDF.
    - Requires cryptography.hazmat.primitives.kdf.hkdf.HKDF and
      cryptography.hazmat.primitives.hashes.SHA256, plus a backend.
    - Raises whatever exceptions HKDF.derive raises for invalid inputs.
    """
    hkdf: HKDF = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    derived_key: bytes = hkdf.derive(input_key)

    return derived_key


def derive_working_keys(argon2_tag: bytes, crypt: Crypto) -> Crypto:
    """
    Derive encryption and MAC keys from an Argon2 tag using
    HKDF-SHA-256.

    Parameters
    ----------
    argon2_tag : bytes
        Raw output bytes from Argon2; used as HKDF input keying
        material (IKM).
    crypt : Crypto
        Mutable container where derived keys will be stored. After the
        call it must contain:
        - mac_key : bytes
            HKDF-derived MAC key of length `MAC_KEY_SIZE`.
        - enc_key : bytes
            HKDF-derived encryption key of length `ENC_KEY_SIZE`.
        - enc_key_hash : bytes
            BLAKE2b digest (digest_size=`ENC_KEY_SIZE`) of `enc_key`.

    Returns
    -------
    Crypto
        The updated `crypt` object with `mac_key`, `enc_key`, and
        `enc_key_hash` populated.

    Notes
    -----
    - Derives `mac_key` and `enc_key` using `hkdf_sha256` with
      per-purpose `HKDF_INFO_MAC` and `HKDF_INFO_ENCRYPT`.
    - Computes `enc_key_hash` as a key-commitment for the encryption
      key.
    - Emits hex-formatted debug logs for `argon2_tag`, `mac_key`,
      `enc_key`, and `enc_key_hash` when `UNSAFE_DEBUG` is enabled.
    - Requires functions/constants `hkdf_sha256`, `blake2b`,
      `MAC_KEY_SIZE`, `ENC_KEY_SIZE`, `HKDF_INFO_MAC`,
      `HKDF_INFO_ENCRYPT`, and `UNSAFE_DEBUG` to be available.
    """
    crypt.mac_key = hkdf_sha256(
        input_key=argon2_tag,
        info=HKDF_INFO_MAC,
        length=MAC_KEY_SIZE,
    )

    crypt.enc_key = hkdf_sha256(
        input_key=argon2_tag,
        info=HKDF_INFO_ENCRYPT,
        length=ENC_KEY_SIZE,
    )

    crypt.enc_key_hash = blake2b(
        crypt.enc_key,
        digest_size=ENC_KEY_SIZE,
    ).digest()

    if UNSAFE_DEBUG:
        log_d(f'argon2_tag:\n        {argon2_tag.hex()}')
        log_d(f'mac_key:\n        {crypt.mac_key.hex()}')
        log_d(f'enc_key:\n        {crypt.enc_key.hex()}')
        log_d(f'enc_key_hash:\n        {crypt.enc_key_hash.hex()}')

    return crypt


# Perform encryption/decryption and authentication
# --------------------------------------------------------------------------- #


def init_nonce_counter(crypt: Crypto) -> Crypto:
    """
    Initialize the nonce counter to zero.

    Parameters
    ----------
    crypt : Crypto
        Mutable container where `nonce_counter` will be set to 0.

    Returns
    -------
    Crypto
        The updated `crypt` object with `nonce_counter == 0`.

    Notes
    -----
    - Resets `crypt.nonce_counter` to 0; safe to call multiple times.
    - Emits a debug log when `UNSAFE_DEBUG` is enabled.
    """
    crypt.nonce_counter = 0

    if UNSAFE_DEBUG:
        log_d(f'nonce counter initialized to {crypt.nonce_counter}')

    return crypt


def increment_nonce(crypt: Crypto) -> Crypto:
    """
    Increment the nonce counter and store the derived nonce bytes.

    Parameters
    ----------
    crypt : Crypto
        Mutable container holding nonce state. Must provide:
        - nonce_counter : int
            Counter to be incremented.
        - (after call) nonce : bytes
            Derived nonce bytes of length `NONCE_SIZE`.

    Returns
    -------
    Crypto
        The updated `crypt` object with `nonce_counter` incremented and
        `nonce` set to `nonce_counter.to_bytes(NONCE_SIZE, BYTEORDER)`.

    Notes
    -----
    - Increments `crypt.nonce_counter` and derives `crypt.nonce` using
      `NONCE_SIZE` and `BYTEORDER`.
    - The nonce must be unique for every encryption operation under the
      same key.
    - Requires that `NONCE_SIZE` and `BYTEORDER` are defined and that
      `crypt.nonce_counter` is initialized.
    - Emits debug logs when `UNSAFE_DEBUG` is enabled.
    """
    crypt.nonce_counter += 1

    crypt.nonce = crypt.nonce_counter.to_bytes(NONCE_SIZE, BYTEORDER)

    if UNSAFE_DEBUG:
        log_d(f'nonce counter incremented to {crypt.nonce_counter}; '
              f'new nonce: {crypt.nonce.hex()}')

    return crypt


def init_new_mac_chunk(crypt: Crypto) -> Crypto:
    """
    Initialize a new MAC chunk: increment nonce, create MAC object,
    reset counter.

    Parameters
    ----------
    crypt : Crypto
        Mutable container holding MAC and protocol state. Must provide:
        - mac_key : bytes
            Key used to initialize the MAC (passed to blake2b or
            equivalent).
        - nonce : bytes
            Current nonce; will be incremented by increment_nonce().
        - (after call) mac_hash_obj : object
            Newly created MAC/hash object exposing .update() and
            .digest().
        - (after call) mac_chunk_size_sum : int
            Running total of processed bytes, reset to 0.

    Returns
    -------
    Crypto
        The updated `crypt` object with a new nonce, a new
        `mac_hash_obj`, and `mac_chunk_size_sum` set to 0.

    Notes
    -----
    - Calls `increment_nonce(crypt)` to advance the nonce used for
      MAC/encryption.
    - Initializes `mac_hash_obj` using `blake2b`.
    - Resets `mac_chunk_size_sum` to 0.
    - Emits debug logs when `UNSAFE_DEBUG` is enabled.
    - Relies on globally available `increment_nonce` and `blake2b`
      functions and constants `MAC_TAG_SIZE` and `UNSAFE_DEBUG`.
    """
    if UNSAFE_DEBUG:
        log_d('init new MAC chunk with new nonce')

    crypt = increment_nonce(crypt)

    crypt.mac_hash_obj = blake2b(
        digest_size=MAC_TAG_SIZE,
        key=crypt.mac_key,
    )

    if UNSAFE_DEBUG:
        log_d('MAC hash object initialized')

    crypt.mac_chunk_size_sum = 0

    return crypt


def update_mac(chunk: bytes, comment: str, crypt: Crypto) -> Crypto:
    """
    Update the MAC object with a data chunk and increment the
    accumulated size.

    Parameters
    ----------
    chunk : bytes
        Data to feed into the MAC.
    comment : str
        Human-readable description of the chunk (used only for debug
        logging).
    crypt : Crypto
        Mutable container holding MAC state. Must provide:
        - mac_hash_obj : object
            A MAC/hash object exposing an .update(bytes) method.
        - mac_chunk_size_sum : int
            Running total of processed bytes; will be incremented by
            len(chunk).

    Returns
    -------
    Crypto
        The updated `crypt` object with `mac_hash_obj` updated and
        `mac_chunk_size_sum` incremented.

    Notes
    -----
    - Uses the provided `mac_hash_obj.update(chunk)` to feed data into
      the MAC.
    - Increments `mac_chunk_size_sum` by the number of bytes in `chunk`.
    - If `UNSAFE_DEBUG` is enabled, logs the chunk description and
      formatted size.
    """
    crypt.mac_hash_obj.update(chunk)

    chunk_size: int = len(chunk)

    if UNSAFE_DEBUG:
        log_d(f'MAC updated with: {comment}, {format_size(chunk_size)}')

    crypt.mac_chunk_size_sum += chunk_size

    return crypt


def update_mac_with_aad(crypt: Crypto) -> Crypto:
    """
    Update the incremental MAC with the assembled additional
    authenticated data (AAD) fields from the provided Crypto context.

    Parameters
    ----------
    crypt : Crypto
        Cryptographic context whose AAD fields will be fed into the
        incremental MAC. Expected fields used by this function:
        - enc_key_hash : bytes
        - argon2_salt : bytes
        - blake2_salt : bytes
        - encrypted_pad_ikm : bytes
        - padded_size_bytes : bytes
        - pad_size_bytes : bytes
        - contents_size_bytes : bytes

    Returns
    -------
    Crypto
        The same `crypt` object passed in. The function mutates `crypt`
        by updating its incremental MAC/hash state via repeated calls to
        `update_mac(...)` and then returns the mutated object.

    Notes
    -----
    - The function feeds AAD fields into the MAC in a fixed order;
      callers must use the same order when verifying MACs.
    - This function assumes `update_mac` is available and that `crypt`
      contains non-None byte values for the listed fields; missing or
      None fields may cause `update_mac` to set error state or raise.
    - No exceptions are caught here; error handling (if any) is the
      responsibility of `update_mac` and the caller.
    - All AAD fields in the crypt object must be non-None and properly
      initialized before calling this function.
    """
    update_mac(
        chunk=crypt.enc_key_hash,
        comment='enc_key_hash',
        crypt=crypt,
    )
    update_mac(
        chunk=crypt.argon2_salt,
        comment='argon2_salt',
        crypt=crypt,
    )
    update_mac(
        chunk=crypt.blake2_salt,
        comment='blake2_salt',
        crypt=crypt,
    )
    update_mac(
        chunk=crypt.encrypted_pad_ikm,
        comment='encrypted_pad_ikm',
        crypt=crypt,
    )
    update_mac(
        chunk=crypt.padded_size_bytes,
        comment='padded_size_bytes',
        crypt=crypt,
    )
    update_mac(
        chunk=crypt.pad_size_bytes,
        comment='pad_size_bytes',
        crypt=crypt,
    )
    update_mac(
        chunk=crypt.contents_size_bytes,
        comment='contents_size_bytes',
        crypt=crypt,
    )
    return crypt


def get_computed_mac_tag(crypt: Crypto) -> tuple[bytes, Crypto]:
    """
    Compute and return the finalized MAC tag and update the Crypto
    state.

    Parameters
    ----------
    crypt : Crypto
        Mutable container holding MAC state and protocol fields. Must
        provide:
        - mac_hash_obj : object
            A pre-initialized keyed MAC/hash object with prior updates
            (e.g., HMAC or keyed BLAKE2b) exposing a .digest() method.
        - mac_chunk_size_sum : int
            Accumulated total processed size to serialize and feed to
            the MAC.
        - nonce : bytes
            Current nonce to include in the MAC.

    Returns
    -------
    tuple[bytes, Crypto]
        Tuple (tag, crypt) where `tag` is the finalized MAC tag bytes
        and `crypt` is the updated Crypto object with consumed fields
        removed.

    Notes
    -----
    - Serializes `mac_chunk_size_sum` to a fixed-length byte sequence of
      length `SIZE_BYTES_SIZE` using `BYTEORDER`, then updates the MAC
      with that value, followed by the current `nonce`, and finally all
      AAD fields via `update_mac_with_aad`.
    - Finalizes the MAC with `mac_hash_obj.digest()` and deletes
      `mac_hash_obj` and `mac_chunk_size_sum` from `crypt`.
    - Does not perform constant-time tag comparison; the caller must
      verify the tag using a constant-time comparison function.
    - Requires constants `SIZE_BYTES_SIZE` and `BYTEORDER` to be defined
      and consistent with the protocol.
    """
    mac_chunk_size: int = crypt.mac_chunk_size_sum

    mac_chunk_size_bytes: bytes = \
        mac_chunk_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)

    if UNSAFE_DEBUG:
        log_d(f'mac_chunk_size: {format_size(mac_chunk_size)}, '
              f'mac_chunk_size_bytes: {mac_chunk_size_bytes.hex()}')

    crypt = update_mac(
        chunk=mac_chunk_size_bytes,
        comment='mac_chunk_size_bytes',
        crypt=crypt,
    )
    crypt = update_mac(
        chunk=crypt.nonce,
        comment='nonce',
        crypt=crypt,
    )
    crypt = update_mac_with_aad(crypt)

    computed_mac_tag: bytes = crypt.mac_hash_obj.digest()

    del crypt.mac_hash_obj, crypt.mac_chunk_size_sum

    if UNSAFE_DEBUG:
        log_d(f'computed MAC tag:\n        {computed_mac_tag.hex()}')

    return computed_mac_tag, crypt


def write_mac_tag(ad: ActData, crypt: Crypto) -> tuple[ActData, Crypto]:
    """
    Write the computed MAC tag to the output.

    Parameters
    ----------
    ad : ActData
        Action/context object providing output helpers and an error flag
       `err`.
    crypt : Crypto
        Crypto state used to compute the MAC tag; may be updated by
        `get_computed_mac_tag`.

    Returns
    -------
    tuple[ActData, Crypto]
        Tuple of (ad, crypt). On success `ad.err` remains False. If
        writing fails `ad.err` is set to True and the returned `crypt`
        reflects the state at failure.

    Notes
    -----
    - Obtains the tag via `get_computed_mac_tag(crypt)` and writes it
      using `write_data(computed_mac_tag, ad)`.
    - Emits debug logs when `UNSAFE_DEBUG` is True.
    - Relies on helpers/globals: `get_computed_mac_tag`, `write_data`,
      `log_d`.
    """
    computed_mac_tag: bytes

    computed_mac_tag, crypt = get_computed_mac_tag(crypt)

    if UNSAFE_DEBUG:
        log_d('writing computed MAC tag')

    ad = write_data(data=computed_mac_tag, ad=ad)
    if ad.err:
        return ad, crypt

    if UNSAFE_DEBUG:
        log_d('computed MAC tag written')

    return ad, crypt


def read_and_verify_mac_tag(
    ad: ActData,
    crypt: Crypto,
) -> tuple[ActData, Crypto]:
    """
    Read and verify a MAC tag from the input and compare it to the
    computed tag.

    Parameters
    ----------
    ad : ActData
        Action/context object providing the input file object
        `in_file_obj` and an error flag `err`. On verification failure
        `ad.err` will be set.
    crypt : Crypto
        Crypto state used to compute the expected MAC tag; may be
        updated by `get_computed_mac_tag`.

    Returns
    -------
    tuple[ActData, Crypto]
        Tuple of (ad, crypt). On success `ad.err` remains
        unchanged/False. On failure (I/O error or tag mismatch) `ad.err`
        is set to True and `crypt` reflects the state at failure.

    Notes
    -----
    - Reads `MAC_TAG_SIZE` bytes from `ad.in_file_obj` using
      `read_data`. If the read returns `None`, sets `ad.err = True`,
      logs the failure, and returns immediately.
    - Obtains the expected tag via `get_computed_mac_tag(crypt)`.
    - Compares tags using a time-constant comparison (`compare_digest`).
      On mismatch, sets `ad.err = True` and logs the failure.
    - Debug logging (when `UNSAFE_DEBUG` is true) outputs the retrieved
      tag and a success message on match.
    - Relies on globals/helpers: `MAC_TAG_SIZE`, `get_computed_mac_tag`,
      `read_data`, `compare_digest`, `log_e`, `log_d`, and
      `MAC_FAIL_MESSAGE`.
    """
    computed_mac_tag: bytes
    computed_mac_tag, crypt = get_computed_mac_tag(crypt)

    retrieved_mac_tag: Optional[bytes] = \
        read_data(ad.in_file_obj, MAC_TAG_SIZE)

    if retrieved_mac_tag is None:
        ad.err = True
        log_e(MAC_FAIL_MESSAGE)
        return ad, crypt

    if UNSAFE_DEBUG:
        log_d(f'retrieved MAC tag:\n        {retrieved_mac_tag.hex()}')

    if compare_digest(computed_mac_tag, retrieved_mac_tag):
        if UNSAFE_DEBUG:
            log_d('computed MAC tag is equal to retrieved MAC tag')
        return ad, crypt

    if UNSAFE_DEBUG:
        log_d('computed MAC tag is NOT equal to retrieved MAC tag')

    if UNSAFE_DECRYPT:
        log_w('authentication failed; '
              'possibly invalid plaintext will be released!')
        return ad, crypt

    ad.err = True
    log_e(MAC_FAIL_MESSAGE)
    return ad, crypt


def feed_stream_cipher(
    input_data: bytes,
    comment: str,
    crypt: Crypto,
) -> tuple[bytes, Crypto]:
    """
    Perform ChaCha20 stream-cipher processing on a single chunk using
    the current nonce.

    Parameters
    ----------
    input_data : bytes
        Data to process. May be empty; output will be the same length as
        input.
    comment : str
        Short description used for debug logging.
    crypt : Crypto
        Crypto state carrying `enc_key` (256-bit key) and `nonce`
        (counter bytes). Returned updated `crypt` may have debug
        counters modified.

    Returns
    -------
    tuple[bytes, Crypto]
        (output_data, crypt) where `output_data` is the
        ciphertext/plaintext (same length as `input_data`) and `crypt`
        is the possibly updated crypto state.

    Notes
    -----
    - A 128-bit nonce is formed by prepending 4 zero bytes
      (BLOCK_COUNTER_INIT_BYTES = b'\x00\x00\x00\x00') to the 96-bit
      crypt.nonce.
    - Uses ChaCha20 with a 256-bit key from `crypt.enc_key`. Caller must
      ensure `crypt.nonce` is a fresh counter value before calling;
      nonce reuse with the same key is catastrophic.
    - This function provides confidentiality only (no authenticity).
      Integrity must be provided separately (e.g., MAC over ciphertext
      and associated data).
    - When `UNSAFE_DEBUG` is true, `crypt.enc_sum` and
      `crypt.enc_chunk_count` are updated and a debug log is emitted.
    - Relies on globals/constants: `BLOCK_COUNTER_INIT_BYTES`,
      `UNSAFE_DEBUG`, and helper `format_size`, and on a ChaCha20/Cipher
      implementation compatible with a 128-bit nonce.
    """

    # This ChaCha20 implementation uses a 128-bit full nonce
    full_nonce: bytes = BLOCK_COUNTER_INIT_BYTES + crypt.nonce

    # Create the ChaCha20 algorithm object
    algorithm: ChaCha20 = ChaCha20(
        key=crypt.enc_key,  # 256-bit encryption key
        nonce=full_nonce,  # 128-bit full nonce
    )

    # Create the cipher object
    cipher: Cipher[None] = Cipher(algorithm, mode=None)

    # Feed input data to the encryptor object and get the output
    output_data: bytes = cipher.encryptor().update(input_data)

    # Log the chunk size and nonce value if debugging is enabled
    if UNSAFE_DEBUG:
        chunk_size: int = len(output_data)
        crypt.enc_sum += chunk_size
        crypt.enc_chunk_count += 1
        log_d(f'ChaCha20 input: {comment}, '
              f'size: {format_size(chunk_size)}, '
              f'with nonce {crypt.nonce.hex()}')

    return output_data, crypt


# Handle padding
# --------------------------------------------------------------------------- #


def get_pad_size_from_unpadded(unpadded_size: int, pad_key: bytes) -> int:
    """
    Calculate padding size from unpadded size and a padding key.

    Parameters
    ----------
    unpadded_size : int
        Size of the unpadded data in bytes. Must be > 0 when used in
        percentage calculations in debug logging.
    pad_key : bytes
        Byte string used to influence the padding size; converted to an
        integer with byte order `BYTEORDER`.

    Returns
    -------
    int
        Calculated padding size in bytes.

    Notes
    -----
    - The padding size is computed as:
      pad_size = (unpadded_size * pad_key_int * MAX_PAD_SIZE_PERCENT) //
                 (PAD_KEY_SPACE * 100)
      where `pad_key_int = int.from_bytes(pad_key, BYTEORDER)`.
    - The maximum possible padding (for logging) is:
      max_pad_size = (unpadded_size * MAX_PAD_SIZE_PERCENT) // 100
    - Debug logging (when `UNSAFE_DEBUG` is true) reports intermediate values:
      `pad_key_int`, `pad_key_int / PAD_KEY_SPACE`, `unpadded_size`,
      `max_pad_size`, `pad_size`, percent of `unpadded_size`, percent of
      `max_pad_size` (if `max_pad_size` > 0), and `padded_size =
      unpadded_size + pad_size`.
    - Relies on globals/constants: `BYTEORDER`, `MAX_PAD_SIZE_PERCENT`,
      `PAD_KEY_SPACE`, and `UNSAFE_DEBUG`, plus helpers used only for
      logging such as `format_size`, `log_d`.
    """

    # Convert the padding key from bytes to an integer
    pad_key_int: int = int.from_bytes(pad_key, BYTEORDER)

    # Calculate the padding size based on the unpadded size,
    # pad_key, and max padding percentage
    pad_size: int = (
        unpadded_size * pad_key_int * MAX_PAD_SIZE_PERCENT //
        (PAD_KEY_SPACE * 100)
    )

    # If debugging is enabled, log detailed information
    # about the padding calculation
    if UNSAFE_DEBUG:
        max_pad_size: int = (unpadded_size * MAX_PAD_SIZE_PERCENT) // 100

        if max_pad_size:
            percent_of_max_total: float = \
                (pad_size * 100) / max_pad_size

        percent_of_unpadded: float = (pad_size * 100) / unpadded_size
        padded_size: int = unpadded_size + pad_size

        log_d('getting pad_size')

        log_d(f'pad_key_int:               {pad_key_int}')
        log_d(f'pad_key_int/PAD_KEY_SPACE: {pad_key_int / PAD_KEY_SPACE}')

        log_d(f'unpadded_size: {format_size(unpadded_size)}')
        log_d(f'max_pad_size:  {format_size(max_pad_size)}')

        if max_pad_size:
            log_d(f'pad_size:      {format_size(pad_size)}, '
                  f'{round(percent_of_unpadded, 1)}% of unpadded_size, '
                  f'{round(percent_of_max_total, 1)}% of max_pad_size')
        else:
            log_d(f'pad_size:      {format_size(pad_size)}, '
                  f'{round(percent_of_unpadded, 1)}% of unpadded_size')

        log_d(f'padded_size:   {format_size(padded_size)}')

    return pad_size


def get_pad_size_from_padded(padded_size: int, pad_key: bytes) -> int:
    """
    Calculate the padding size from the total padded size and padding
    key.

    Parameters
    ----------
    padded_size : int
        The total size of the cryptoblob including padding (bytes).
    pad_key : bytes
        Byte string used to influence the padding size calculation.

    Returns
    -------
    int
        Calculated padding size in bytes.

    Notes
    -----
    - The padding size is derived using the formula:
      pad_size = (padded_size * pad_key_int * MAX_PAD_SIZE_PERCENT) //
                 (pad_key_int * MAX_PAD_SIZE_PERCENT +
                  PAD_KEY_SPACE * 100)
      where `pad_key_int = int.from_bytes(pad_key, BYTEORDER)`.
    - This function is used during decryption to determine the original
      padding size that was applied during encryption, ensuring
      consistency with the `get_pad_size_from_unpadded` calculation.
    """

    # Convert the padding key from bytes to an integer
    pad_key_int: int = int.from_bytes(pad_key, BYTEORDER)

    # Calculate the padding size based on the padded size, padding key,
    # and maximum padding percentage
    pad_size: int = (
        padded_size * pad_key_int * MAX_PAD_SIZE_PERCENT //
        (pad_key_int * MAX_PAD_SIZE_PERCENT + PAD_KEY_SPACE * 100)
    )

    # If debugging is enabled, log detailed information about
    # the padding calculation
    if UNSAFE_DEBUG:
        unpadded_size: int = padded_size - pad_size
        percent_of_unpadded: float = (pad_size * 100) / unpadded_size

        log_d('getting pad_size')

        log_d(f'pad_key_int:               {pad_key_int}')
        log_d(f'pad_key_int/PAD_KEY_SPACE: {pad_key_int / PAD_KEY_SPACE}')

        log_d(f'padded_size:   {format_size(padded_size)}')
        log_d(f'pad_size:      {format_size(pad_size)}, '
              f'{round(percent_of_unpadded, 1)}% of unpadded_size')
        log_d(f'unpadded_size: {format_size(unpadded_size)}')

    return pad_size


def handle_padding(
    pad_size: int,
    ad: ActData,
    crypt: Crypto,
) -> tuple[ActData, Crypto]:
    """
    Handle padding bytes: read/write and authenticate.

    Parameters
    ----------
    pad_size : int
        Total number of padding bytes to process. Must be >= 0.
    ad : ActData
        Action/context object providing `action`, input file object
        `in_file_obj`, and error flag `err`.
    crypt : Crypto
        Crypto state object used for MAC updates and tag operations.

    Returns
    -------
    tuple[ActData, Crypto]
        Tuple of updated (ad, crypt). On failure `ad.err` is set to True
        and the returned `crypt` reflects state at failure.

    Notes
    -----
    - If `ad.action` is `ENCRYPT` or `ENCRYPT_EMBED`:
      - Write `pad_size` bytes of random padding in chunks of size
        `MAX_PT_CHUNK_SIZE` (full chunks first, then a final partial
        chunk).
      - Each written chunk is passed to `update_mac(chunk,
        'padding contents chunk', crypt)`.
      - After all padding is written, call `write_mac_tag(ad, crypt)`
        and return its result.
      - Even when pad_size is zero, the function still finalizes and
        writes (or verifies) the MAC tag for the padding phase.
    - Otherwise (decryption/verification mode):
      - Read `pad_size` bytes from `ad.in_file_obj` in identical chunk
        sizes.
      - If any read returns `None`, set `ad.err = True` and return
        immediately.
      - Each read chunk is passed to `update_mac(chunk,
        'padding contents chunk', crypt)`.
      - After all padding is read, call `read_and_verify_mac_tag(ad,
        crypt)` and return its result.

    - Side effects:
      - Reads from or writes to I/O via `write_data` / `read_data` and
        may call `write_mac_tag` / `read_and_verify_mac_tag`.
      - Updates MAC state via `update_mac`.
      - Relies on globals/constants: `MAX_PT_CHUNK_SIZE`, `ENCRYPT`,
        `ENCRYPT_EMBED`, and helper functions such as `token_bytes`,
        `write_data`, `read_data`.
    """
    action: ActionID = ad.action

    chunk: Optional[bytes]

    # Calculate the number of complete chunks and remaining bytes to write
    full_chunks: int = pad_size // MAX_PT_CHUNK_SIZE
    remain_size: int = pad_size % MAX_PT_CHUNK_SIZE

    # Write the full chunks of random data
    for _ in range(full_chunks):

        if action in (ENCRYPT, ENCRYPT_EMBED):

            # Generate a random data chunk of size MAX_PT_CHUNK_SIZE
            chunk = token_bytes(MAX_PT_CHUNK_SIZE)

            ad = write_data(data=chunk, ad=ad)
            if ad.err:
                return ad, crypt

        else:
            chunk = read_data(ad.in_file_obj, MAX_PT_CHUNK_SIZE)
            if chunk is None:
                ad.err = True
                return ad, crypt

        crypt = update_mac(
            chunk=chunk,
            comment='padding contents chunk',
            crypt=crypt,
        )

    # If there is remaining data to write, handle it
    if remain_size:
        if action in (ENCRYPT, ENCRYPT_EMBED):

            # Generate a random data chunk of size MAX_PT_CHUNK_SIZE
            chunk = token_bytes(remain_size)

            ad = write_data(data=chunk, ad=ad)
            if ad.err:
                return ad, crypt

        else:
            chunk = read_data(ad.in_file_obj, remain_size)
            if chunk is None:
                ad.err = True
                return ad, crypt

        crypt = update_mac(
            chunk=chunk,
            comment='padding contents chunk',
            crypt=crypt,
        )

    if action in (ENCRYPT, ENCRYPT_EMBED):
        ad, crypt = write_mac_tag(ad=ad, crypt=crypt)
    else:
        ad, crypt = read_and_verify_mac_tag(ad=ad, crypt=crypt)

    return ad, crypt


# Handle payload file contents
# --------------------------------------------------------------------------- #


def get_enc_contents_size_from_contents(contents_size: int) -> int:
    """
    Calculate the size of the encrypted payload (including per-chunk MAC
    tags) produced from a plaintext of the given length.

    Parameters
    ----------
    contents_size : int
        Plaintext size in bytes. Must be >= 0.

    Returns
    -------
    int
        Encrypted payload size in bytes (ciphertext + per-chunk MAC tags).

    Notes
    -----
    - The plaintext is split into chunks of size `MAX_PT_CHUNK_SIZE`.
    - Each full plaintext chunk produces `MAX_CT_CHUNK_SIZE` bytes of
      ciphertext (this already includes any per-chunk overhead for full
      chunks).
    - Each chunk is encrypted and a MAC tag of size `MAC_TAG_SIZE` is
      appended. Therefore `MAX_CT_CHUNK_SIZE` equals
      `MAX_PT_CHUNK_SIZE + MAC_TAG_SIZE`.
    - A final partial plaintext chunk, if present, produces
      `remain_size` bytes of ciphertext plus a MAC tag of size
      `MAC_TAG_SIZE`.
    """
    full_chunks = contents_size // MAX_PT_CHUNK_SIZE
    remain_size = contents_size % MAX_PT_CHUNK_SIZE

    # Encrypted payload file contents (with MAC tags) from full
    # plaintext chunks
    enc_contents_size = full_chunks * MAX_CT_CHUNK_SIZE

    # If there's a remaining partial plaintext chunk, it becomes rem
    # bytes of ciphertext plus a MAC tag
    if remain_size:
        enc_contents_size += remain_size + MAC_TAG_SIZE

    return enc_contents_size


def get_contents_size_from_enc_contents(
    enc_contents_size: int,
) -> Optional[int]:
    """
    Compute plaintext size from an encrypted payload length (including
    MACs).

    Parameters
    ----------
    enc_contents_size : int
        Encrypted payload size in bytes, including per-chunk MAC tags.
        Must be >= 0.

    Returns
    -------
    Optional[int]
        Corresponding plaintext size in bytes if `enc_contents_size` is
        a valid length produced by the chunking scheme; otherwise `None`
        when the encrypted length is invalid or cannot correspond to any
        valid plaintext length.

    Notes
    -----
    - The protocol splits plaintext into chunks of size
      `MAX_PT_CHUNK_SIZE`. Each full plaintext chunk maps to a full
      ciphertext chunk of size `MAX_CT_CHUNK_SIZE` (ciphertext + MAC
      tag).
    - For `enc_contents_size` that is an exact multiple of
      `MAX_CT_CHUNK_SIZE`, the plaintext size is `full_chunks *
      MAX_PT_CHUNK_SIZE`.
    - If there is a final partial ciphertext chunk, it must be at least
      `1 + MAC_TAG_SIZE` bytes (minimum 1 byte of ciphertext plus MAC
      tag); the plaintext bytes contributed by that partial chunk equal
      `(partial_ct_size - MAC_TAG_SIZE)`.
    - Returns `None` when the final partial ciphertext chunk is too
      small to hold a MAC plus at least one ciphertext byte (i.e., when
      `remain_size < 1 + MAC_TAG_SIZE`).
    """
    full_chunks = enc_contents_size // MAX_CT_CHUNK_SIZE
    remain_size = enc_contents_size % MAX_CT_CHUNK_SIZE

    # plaintext bytes from complete chunks
    base_plain = full_chunks * MAX_PT_CHUNK_SIZE

    # exact multiple of full ciphertext chunks -> plaintext exactly base_plain
    if remain_size == 0:
        return base_plain

    # any partial ciphertext chunk must be at least 1 + MAC_TAG_SIZE bytes
    if remain_size < 1 + MAC_TAG_SIZE:
        return None

    # remaining plaintext bytes = remainder minus MAC tag
    return base_plain + (remain_size - MAC_TAG_SIZE)


def handle_payload_file_contents(
    contents_size: int,
    ad: ActData,
    crypt: Crypto,
) -> tuple[ActData, Crypto]:
    """
    Process a payload by splitting it into protocol-sized chunks and
    delegating each chunk to `file_chunk_handler`.

    Parameters
    ----------
    contents_size : int
        Total plaintext-sized payload length in bytes (must be >= 0).
    ad : ActData
        Action/context object mutated in-place. Uses `ad.action`,
        `ad.in_file_obj`, and updates error/progress fields.
    crypt : Crypto
        Cryptographic context mutated in-place. Chunk-level MAC and
        stream-cipher state are advanced by `file_chunk_handler`.

    Returns
    -------
    tuple[ActData, Crypto]
        The updated `(ad, crypt)` pair. On error `ad.err` is set to
        True.

    Notes
    -----
    - The payload is split into `full_chunks` of `MAX_PT_CHUNK_SIZE`
      and an optional final `remain_size` partial chunk.
    - Each chunk is processed sequentially by `file_chunk_handler`.
    - Processing stops early on any error (when `ad.err` becomes True).
    - Side effects: reads from `ad.in_file_obj`, writes output via
      helpers, and updates MAC/state via `crypt`.
    """

    # Calculate the number of complete chunks and remaining bytes
    full_chunks: int = contents_size // MAX_PT_CHUNK_SIZE
    remain_size: int = contents_size % MAX_PT_CHUNK_SIZE

    # Process complete chunks
    for _ in range(full_chunks):
        ad, crypt = file_chunk_handler(
            chunk_size=MAX_PT_CHUNK_SIZE,
            ad=ad,
            crypt=crypt,
        )
        if ad.err:
            return ad, crypt

    # Process any remaining bytes
    if remain_size:
        ad, crypt = file_chunk_handler(
            chunk_size=remain_size,
            ad=ad,
            crypt=crypt,
        )

    return ad, crypt


def file_chunk_handler(
    chunk_size: int,
    ad: ActData,
    crypt: Crypto,
) -> tuple[ActData, Crypto]:
    """
    Process a single file chunk: read, encrypt/decrypt, MAC and write.

    Parameters
    ----------
    chunk_size : int
        Number of bytes to read from the input stream for this chunk.
        For encryption this is plaintext length; for decryption this is
        the expected plaintext length after decryption.
    ad : ActData
        Action/context object mutated in-place. Required fields used by
        this function include `action`, `in_file_obj`, and `err`. On
        success the function updates output-related fields (for example:
        written_sum).
    crypt : Crypto
        Cryptographic context mutated in-place. This function
        initializes a new per-chunk MAC, updates MAC state, and advances
        stream-cipher state.

    Returns
    -------
    tuple[ActData, Crypto]
        The updated `(ad, crypt)` pair. On error `ad.err` is set to
        True.

    Notes
    -----
    Behavior
    - The function begins a new MAC chunk with `init_new_mac_chunk()`.
    - It reads `chunk_size` bytes from `ad.in_file_obj` via `read_data`.
    - For encrypting actions (ENCRYPT, ENCRYPT_EMBED):
      - Encrypts the read plaintext with `feed_stream_cipher`.
      - Writes ciphertext via `write_data`.
      - Updates the running MAC with the ciphertext (`update_mac`).
      - Writes the per-chunk MAC tag (`write_mac_tag`).
    - For decrypting actions (DECRYPT, EXTRACT_DECRYPT):
      - Updates the running MAC with the read ciphertext.
      - Reads and verifies the per-chunk MAC tag
        (`read_and_verify_mac_tag`).
      - Decrypts the ciphertext with `feed_stream_cipher`.
      - Writes the resulting plaintext via `write_data`.
    - On any I/O, MAC verification, or crypto failure the function sets
      `ad.err = True` and returns early.

    Side effects
    ------------
    - Reads from `ad.in_file_obj` and writes to the output via helper
      functions (e.g., `write_data`).
    - Mutates `ad` and `crypt`.
    - Calls helpers: `init_new_mac_chunk`, `read_data`,
      `feed_stream_cipher`, `write_data`, `update_mac`, `write_mac_tag`,
      `read_and_verify_mac_tag`.

    Error handling
    --------------
    - If `read_data` returns `None` or any helper indicates failure,
      `ad.err` is set and the function returns immediately with the
      mutated `(ad, crypt)`.
    """
    out_chunk: bytes

    crypt = init_new_mac_chunk(crypt)

    in_chunk: Optional[bytes] = read_data(ad.in_file_obj, chunk_size)
    if in_chunk is None:
        ad.err = True
        return ad, crypt

    if ad.action in (ENCRYPT, ENCRYPT_EMBED):
        out_chunk, crypt = feed_stream_cipher(
            input_data=in_chunk,
            comment='file contents chunk',
            crypt=crypt,
        )

        ad = write_data(data=out_chunk, ad=ad)
        if ad.err:
            return ad, crypt

        crypt = update_mac(
            chunk=out_chunk,
            comment='encrypted file contents chunk',
            crypt=crypt,
        )

        ad, crypt = write_mac_tag(ad=ad, crypt=crypt)

    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)

        crypt = update_mac(
            chunk=in_chunk,
            comment='encrypted file contents chunk',
            crypt=crypt,
        )

        ad, crypt = read_and_verify_mac_tag(ad=ad, crypt=crypt)
        if ad.err:
            return ad, crypt

        out_chunk, crypt = feed_stream_cipher(
            input_data=in_chunk,
            comment='encrypted file contents chunk',
            crypt=crypt,
        )

        ad = write_data(data=out_chunk, ad=ad)

    return ad, crypt


# Handle Comments
# --------------------------------------------------------------------------- #


def get_processed_comments(basename: str) -> bytes:
    """
    Produce a fixed-size, UTF-8-safe processed comments block.

    Parameters
    ----------
    basename : str
        Base name of the input file; used as a fallback comment when the
        user-provided raw comment is empty.

    Returns
    -------
    bytes
        A byte string exactly `PROCESSED_COMMENTS_SIZE` bytes long
        (unless `PROCESSED_COMMENTS_SIZE` is non-positive). The returned
        block contains a sanitized UTF-8 comment (bytes before
        `COMMENTS_SEPARATOR`), followed by `COMMENTS_SEPARATOR` and
        random padding bytes. The sanitized portion is guaranteed to
        decode as valid UTF-8; padding may be arbitrary binary data.

    Notes
    -----
    Processing steps
    - Read a raw comment via `get_raw_comments(basename)`. If empty, use
      `basename` as the comment.
    - Encode the comment to UTF-8 bytes. If the encoded bytes exceed
      `PROCESSED_COMMENTS_SIZE`, they are truncated (a warning is
      logged).
    - To avoid partial-codepoint issues after truncation, the truncated
      bytes are decoded with `errors='ignore'` and re-encoded to UTF-8,
      producing a sanitized, valid-UTF-8 byte sequence.
    - Append `COMMENTS_SEPARATOR` and random bytes from
      `token_bytes(PROCESSED_COMMENTS_SIZE)`, then slice to the final
      `PROCESSED_COMMENTS_SIZE` length.
    - Debug/logging: sizes and the decoded comment are logged when
      `UNSAFE_DEBUG` is set.

    Guarantees and side effects
    - The sanitized comment portion decodes as UTF-8; partial codepoints
      removed during sanitization are dropped.
    - The function logs a warning when truncation occurs and logs the
      decoded comment via `decode_processed_comments`.
    - Uses helper functions: `get_raw_comments`, `token_bytes`,
      `decode_processed_comments`, and logging helpers `log_w`, `log_d`,
      `log_i`.
    """
    raw_comments: str = get_raw_comments(basename)

    if not raw_comments:
        raw_comments = basename

    raw_comments_bytes: bytes = raw_comments.encode('utf-8')

    raw_comments_size: int = len(raw_comments_bytes)

    if raw_comments_size > PROCESSED_COMMENTS_SIZE:
        log_w(f'comments size: {raw_comments_size:,} B; '
              f'it will be truncated!')

    truncated_comments: bytes = \
        raw_comments_bytes[:PROCESSED_COMMENTS_SIZE]

    # Sanitize comments to prevent potential UnicodeDecodeError
    # This ensures that any invalid bytes are ignored during decoding
    sanitized_comments: bytes = truncated_comments.decode(
        'utf-8', errors='ignore').encode('utf-8')

    # Construct processed_comments by appending a separator and random
    # bytes. The total size must not exceed PROCESSED_COMMENTS_SIZE.
    processed_comments: bytes = b''.join([
        sanitized_comments,
        COMMENTS_SEPARATOR,
        token_bytes(PROCESSED_COMMENTS_SIZE),
    ])[:PROCESSED_COMMENTS_SIZE]

    if UNSAFE_DEBUG:
        log_d(f'raw_comments: {[raw_comments]}, size: {raw_comments_size:,} B')
        log_d(f'processed_comments: {[processed_comments]}, '
              f'size: {len(processed_comments)} B')

    # Log decoded comments
    comments_decoded: Optional[str] = \
        decode_processed_comments(processed_comments)
    log_i(f'comments will be shown as {[comments_decoded]}')

    return processed_comments


def decode_processed_comments(processed_comments: bytes) -> Optional[str]:
    """
    Decode a processed comments byte block to a UTF-8 string.

    Parameters
    ----------
    processed_comments : bytes
        Fixed-size processed comments block. The block contains the
        actual comment bytes followed by a separator byte
        `COMMENTS_SEPARATOR` and optional trailing padding; only the
        bytes before the separator are considered.

    Returns
    -------
    Optional[str]
        Decoded UTF-8 string if the bytes before `COMMENTS_SEPARATOR`
        form valid UTF-8; otherwise `None` when decoding fails.

    Notes
    -----
    - The function uses `bytes.partition(COMMENTS_SEPARATOR)` and keeps
      the left segment (bytes before the first separator) for decoding.
    - Any bytes after the separator are ignored.
    - A `UnicodeDecodeError` is caught and results in a `None` return.
    """

    # Split the input byte string at the first occurrence of
    # COMMENTS_SEPARATOR and keep only the part before it
    processed_comments_part: bytes = \
        processed_comments.partition(COMMENTS_SEPARATOR)[0]

    try:
        # Attempt to decode the byte string into a UTF-8 string
        decoded_comments: Optional[str] = \
            processed_comments_part.decode('utf-8')
    except UnicodeDecodeError:
        decoded_comments = None

    # Return the decoded comments or None if decoding failed
    return decoded_comments


def handle_comments(
    processed_comments: Optional[bytes],
    ad: ActData,
    crypt: Crypto,
) -> tuple[ActData, Crypto]:
    """
    Process the fixed-size processed comments block: encrypt/decrypt,
    authenticate with MAC, and (on decryption) decode and log the
    comment.

    Parameters
    ----------
    processed_comments : Optional[bytes]
        Fixed-size comment bytes to encrypt when `ad.action` is an
        encrypting mode (ENCRYPT, ENCRYPT_EMBED). Must be provided for
        encryption; ignored for decryption.
    ad : ActData
        Action/context object mutated in-place. Required fields used by
        this function include `action`, `in_file_obj`, and `err`. The
        function updates `ad` (writes ciphertext, advances written_sum,
        sets `ad.err` on failure, etc.) and returns it.
    crypt : Crypto
        Cryptographic context mutated in-place. This function
        initializes a new MAC chunk, updates MAC state, and may update
        stream-cipher state and session AAD-related fields.

    Returns
    -------
    tuple[ActData, Crypto]
        The updated `(ad, crypt)` pair. On error `ad.err` is set to
        True.

    Notes
    -----
    - Behavior is driven by `ad.action`:
      - Encrypting modes (ENCRYPT, ENCRYPT_EMBED):
        - Calls `init_new_mac_chunk()` to reset MAC/nonce state.
        - In normal operation processed_comments is always provided for
          encryption actions; a TypeError would only occur due to a
          programming error.
        - Encrypts `processed_comments` with `feed_stream_cipher`.
        - Updates the running MAC with the encrypted bytes via
          `update_mac`.
        - Writes encrypted comments with `write_data` and writes the MAC
          tag with `write_mac_tag`.
      - Decrypting modes (DECRYPT, EXTRACT_DECRYPT):
        - Calls `init_new_mac_chunk()` to reset MAC/nonce state.
        - Reads `PROCESSED_COMMENTS_SIZE` bytes from `ad.in_file_obj`
          using `read_data`; sets `ad.err` and returns on failure.
        - Updates the running MAC with the encrypted bytes and verifies
          the MAC tag via `read_and_verify_mac_tag`; sets `ad.err` and
          returns on verification failure.
        - Decrypts the ciphertext with `feed_stream_cipher`, decodes the
          processed comments with `decode_processed_comments`, and logs
          them.
    - Side effects:
      - Mutates `ad` and `crypt`.
      - Calls helpers: `init_new_mac_chunk`, `feed_stream_cipher`,
        `update_mac`, `write_data`, `write_mac_tag`, `read_data`,
        `read_and_verify_mac_tag`,
        and `decode_processed_comments`.
    - Errors:
      - Missing `processed_comments` when encrypting raises `TypeError`.
      - I/O, MAC verification, or cryptographic failures set
        `ad.err = True` and cause early return.
    """
    crypt = init_new_mac_chunk(crypt)

    enc_processed_comments: Optional[bytes]

    if ad.action in (ENCRYPT, ENCRYPT_EMBED):

        if processed_comments is None:
            raise TypeError

        enc_processed_comments, crypt = \
            feed_stream_cipher(
                input_data=processed_comments,
                comment='processed_comments',
                crypt=crypt,
            )

        crypt = update_mac(
            chunk=enc_processed_comments,
            comment='enc_processed_comments',
            crypt=crypt,
        )

        ad = write_data(data=enc_processed_comments, ad=ad)
        if ad.err:
            return ad, crypt

        ad, crypt = write_mac_tag(ad=ad, crypt=crypt)

    else:  # DECRYPT, EXTRACT_DECRYPT
        enc_processed_comments = \
            read_data(ad.in_file_obj, PROCESSED_COMMENTS_SIZE)
        if enc_processed_comments is None:
            ad.err = True
            return ad, crypt

        crypt = update_mac(
            chunk=enc_processed_comments,
            comment='enc_processed_comments',
            crypt=crypt,
        )

        ad, crypt = read_and_verify_mac_tag(ad=ad, crypt=crypt)
        if ad.err:
            return ad, crypt

        # Get decrypted processed_comments
        processed_comments, crypt = feed_stream_cipher(
            input_data=enc_processed_comments,
            comment='enc_processed_comments',
            crypt=crypt,
        )

        decoded_comments: Optional[str] = \
            decode_processed_comments(processed_comments)

        log_i(f'comments:\n        {[decoded_comments]}')

    return ad, crypt


# Perform action INFO
# --------------------------------------------------------------------------- #


def info_and_warnings() -> None:
    """
    Log application info, warnings, and optional debug details.

    Notes
    -----
    - Emits an informational message (`APP_INFO`) via log_i.
    - Iterates `APP_WARNINGS` and logs each warning with log_w.
    - When `UNSAFE_DEBUG` is truthy, logs additional debug information
      (`APP_UNSAFE_DEBUG_INFO`) via log_d.

    Returns
    -------
    None
        This function only logs messages; it has no return value or side
        effects beyond logging.
    """

    # Log general information
    log_i(APP_INFO)

    # Log any warnings
    for warning in APP_WARNINGS:
        log_w(warning)

    # Log debug information if debug mode is enabled
    if UNSAFE_DEBUG:
        log_d(APP_UNSAFE_DEBUG_INFO)


# Perform actions ENCRYPT, DECRYPT, ENCRYPT_EMBED, EXTRACT_DECRYPT
# --------------------------------------------------------------------------- #


def encrypt_and_embed(ad: ActData) -> ActData:
    """
    Orchestrate a complete encrypt/decrypt operation with optional
    embed/extract behavior.

    Parameters
    ----------
    ad : ActData
        Action/context object containing at minimum the `action` field.
        The object is mutated in-place: input/output file handles,
        sizes, positions, error flags, and timing/progress fields are
        updated. Input/output streams are expected on `ad.in_file_obj`
        and `ad.out_file_obj` as required by the workflow.

    Returns
    -------
    ActData
        The same `ad` object passed in, updated after running the
        workflow. On failure `ad.err` will be True; otherwise the
        operation completed successfully and relevant fields (for
        example: written_sum, start_pos, end_pos, total_out_data_size)
        are set.

    Notes
    -----
    - This function calls `encrypt_and_embed_input` to collect and
      validate inputs and populate a `Crypto` context, runs a garbage
      collection pass via `collect()`, then delegates the main work to
      `encrypt_and_embed_handler`.
    - Side effects include opening/setting `ad.in_file_obj` and
      `ad.out_file_obj`, prompting the user through helper functions,
      and writing to disk.
    - Error conditions are reported by setting `ad.err` and returning
      the mutated `ad` object.
    """
    crypt: Crypto

    # Retrieve input parameters for the encryption and embedding process
    ad, crypt = encrypt_and_embed_input(ad)

    # If input retrieval fails, return False
    if ad.err:
        return ad

    # Perform garbage collection before proceeding
    collect()

    # Call the handler function to perform the action
    ad = encrypt_and_embed_handler(ad=ad, crypt=crypt)

    return ad


def encrypt_and_embed_input(ad: ActData) -> tuple[ActData, Crypto]:
    """
    Collect and validate inputs for encrypt/embed/decrypt workflows and
    populate a Crypto context.

    Parameters
    ----------
    ad : ActData
        Action/context object that will be read and mutated. Expected
        fields include (but are not limited to): action, in_file_obj,
        in_file_size, out_file_obj, padded_size, unpadded_size, pad_ikm
        (for encryption), processed_comments, start_pos, end_pos,
        max_start_pos, max_end_pos, err. The function updates `ad` and
        returns it alongside a populated `Crypto` instance.

    Returns
    -------
    tuple[ActData, Crypto]
        Tuple containing the updated `ad` and a populated `Crypto`
        instance. On failure the function sets `ad.err = True` and
        returns (ad, crypt). The function never returns None.

    Overview
    --------
    - Opens and logs the input file and its size.
    - For encryption actions: generates pad IKM (crypt.pad_ikm), derives
      the pad key, computes enc_contents_size, unpadded_size, pad_size,
      and padded_size, and collects processed comments.
    - For decryption/extraction actions: validates input size and uses
      it to determine padded_size (or prompts the user for start and end
      positions to compute it).
    - Prepares the output file (new file creation or selecting an embed
      location), logs paths and sizes, and determines start/end
      positions for embed/extract flows.
    - Reads salts required later, prompts for Argon2 password and time
      cost, and requests overwrite confirmation when embedding.
    - Validates that padded_size does not exceed allowed maximums and
      seeks file handles to the selected positions.

    Side effects
    ------------
    - Opens input/output files and assigns them to fields on `ad`.
    - May set integer and size-related fields on `ad` (for example
      start_pos, max_end_pos, padded_size) and mutates `ad` accordingly.
    - Logs progress via log_i/log_d/log_w/log_e and calls helpers that
      may prompt the user.

    Failure modes
    -------------
    - Sets `ad.err = True` and returns early on:
    - I/O errors from helper file functions;
    - invalid sizes (too small or exceeding MAX_VALID_PADDED_SIZE);
    - user cancellation of overwrite confirmation;
    - helper function failures (get_salts, get_argon2_password, etc.).
    - May raise TypeError elsewhere if required values are missing after
      helper calls.

    Notes
    -----
    - The function populates crypt.pad_ikm only for encryption actions;
      for other actions pad_ikm is not set.
    - This function assumes helper functions perform detailed validation
      and user interaction; it reacts to their return values rather than
      re-checking the same conditions.
    """
    action: ActionID = ad.action

    if UNSAFE_DECRYPT and action in (DECRYPT, EXTRACT_DECRYPT):
        for warning in UNSAFE_DECRYPT_WARNINGS:
            log_w(warning)

    ad.end_pos = None
    ad.processed_comments = None

    crypt: Crypto = Crypto()

    # 1. Get input file path and size
    # ----------------------------------------------------------------------- #

    in_file_path: str

    # Retrieve the input file path, size, and file object
    in_file_path, ad.in_file_size, ad.in_file_obj = get_input_file(action)

    # Log the input file path and size
    log_i(f'path: {in_file_path!r}; size: {format_size(ad.in_file_size)}')

    # 2. Get pad_key
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):

        crypt.pad_ikm = token_bytes(PAD_KEY_SIZE)

        pad_key: bytes = hkdf_sha256(
            input_key=crypt.pad_ikm,
            info=HKDF_INFO_PAD,
            length=PAD_KEY_SIZE
        )

        if UNSAFE_DEBUG:
            log_d(f'pad_ikm: {crypt.pad_ikm.hex()}')
            log_d(f'pad_key: {pad_key.hex()}')

    # 3. Retrieve and verify additional sizes
    # ----------------------------------------------------------------------- #

    # Handle encryption actions (ENCRYPT, ENCRYPT_EMBED)
    if action in (ENCRYPT, ENCRYPT_EMBED):

        # Get size of encrypted payload file contents (with MAC tags)
        enc_contents_size: int = \
            get_enc_contents_size_from_contents(ad.in_file_size)

        # Get the size of unpadded cryptoblob
        ad.unpadded_size = enc_contents_size + MIN_VALID_UNPADDED_SIZE

        pad_size = get_pad_size_from_unpadded(
            unpadded_size=ad.unpadded_size,
            pad_key=pad_key,
        )

        ad.padded_size = ad.unpadded_size + pad_size

    # Handle decryption actions (DECRYPT, EXTRACT_DECRYPT) and validate
    # input file size
    else:
        if ad.in_file_size < MIN_VALID_UNPADDED_SIZE:
            ad.err = True
            log_e(f'input file is too small; size must be '
                  f'>= {format_size(MIN_VALID_UNPADDED_SIZE)}')
            return ad, crypt

    if action == DECRYPT:
        ad.padded_size = ad.in_file_size

    # 4. Get processed comments for their further encryption
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):

        try:
            basename: str = path.basename(in_file_path)
        except TypeError:
            basename = ''

        ad.processed_comments = get_processed_comments(basename)

    # 5. Retrieve the output file path, size, and file object
    # ----------------------------------------------------------------------- #

    out_file_path: str
    out_file_size: int

    # Set up output file based on the action
    if action in (ENCRYPT, DECRYPT):  # New file creation
        out_file_path, ad.out_file_obj = get_output_file_new(action)
        log_i(f'new empty file {out_file_path!r} created')

    elif action == ENCRYPT_EMBED:  # Existing file handling for encryption
        out_file_path, out_file_size, ad.out_file_obj = \
            get_output_file_exist(
                in_file_path=in_file_path,
                min_out_size=ad.padded_size,
                action=action,
            )
        ad.max_start_pos = out_file_size - ad.padded_size
        log_i(f'path: {out_file_path!r}')

    else:  # action == EXTRACT_DECRYPT, new file creation for decryption
        out_file_path, ad.out_file_obj = get_output_file_new(action)
        ad.max_start_pos = ad.in_file_size - MIN_VALID_UNPADDED_SIZE
        log_i(f'new empty file {out_file_path!r} created')

    # Log the size of the output file if applicable
    if action == ENCRYPT_EMBED:
        log_i(f'size: {format_size(out_file_size)}')

    # 6. Get positions for embedding/extraction
    # ----------------------------------------------------------------------- #

    # Get the starting position for the operation
    if action in (ENCRYPT_EMBED, EXTRACT_DECRYPT):
        ad.start_pos = get_start_position(
            max_start_pos=ad.max_start_pos,
            no_default=True,
        )
        log_i(f'start position: {ad.start_pos} (offset: {ad.start_pos:,} B)')

        if action == ENCRYPT_EMBED:
            ad.max_end_pos = ad.start_pos + ad.padded_size

    # Get the ending position for extraction
    if action == EXTRACT_DECRYPT:

        ad.end_pos = get_end_position(
            min_pos=ad.start_pos + MIN_VALID_UNPADDED_SIZE,
            max_pos=ad.in_file_size,
            no_default=True,
        )
        log_i(f'end position: {ad.end_pos} (offset: {ad.end_pos:,} B)')

        ad.padded_size = ad.end_pos - ad.start_pos

        if UNSAFE_DEBUG:
            log_d(f'cryptoblob size: {format_size(ad.padded_size)}')

    # 7. Check if the size of the cryptoblob exceeds the maximum valid size
    # ----------------------------------------------------------------------- #

    if ad.padded_size > MAX_VALID_PADDED_SIZE:
        ad.err = True
        log_e(f'cryptoblob size is too big: {format_size(ad.padded_size)}')
        return ad, crypt

    # 8. Set file pointers to the specified positions
    # ----------------------------------------------------------------------- #

    # Seek to the start position in the container
    if action in (ENCRYPT_EMBED, EXTRACT_DECRYPT):
        if action == ENCRYPT_EMBED:
            if not seek_position(ad.out_file_obj, offset=ad.start_pos):
                ad.err = True
                return ad, crypt
        else:
            if not seek_position(ad.in_file_obj, offset=ad.start_pos):
                ad.err = True
                return ad, crypt

    # 9. Get salts: need for handling IKM and for performing Argon2
    # ----------------------------------------------------------------------- #

    ad, crypt = get_salts(
        input_size=ad.in_file_size,
        end_pos=ad.end_pos,
        ad=ad,
        crypt=crypt,
    )
    if ad.err:
        return ad, crypt

    # 10. Collect and handle IKM, and get the Argon2 password for
    # further key derivation
    # ----------------------------------------------------------------------- #

    crypt.argon2_password = get_argon2_password(
        action=action,
        blake2_salt=crypt.blake2_salt,
    )

    # 11. Get time cost value
    # ----------------------------------------------------------------------- #

    crypt.argon2_time_cost = get_argon2_time_cost(action)

    # 12. Ask user confirmation for proceeding
    # ----------------------------------------------------------------------- #

    if action == ENCRYPT_EMBED:
        if not proceed_request(proceed_type=PROCEED_OVERWRITE, ad=ad):
            ad.err = True
            log_i('stopped by user request')

    return ad, crypt


def encrypt_and_embed_handler(ad: ActData, crypt: Crypto) -> ActData:
    """
    Perform the core cryptographic workflow for encrypt/decrypt and
    optional embed/extract operations.

    This function implements the end-to-end cryptographic workflow for
    the supported file actions: key derivation, pad handling, payload
    processing, comment handling, and finalization (including optional
    salts and fsync). It mutates and returns the provided ActData (`ad`)
    and Crypto (`crypt`) objects; on error it sets `ad.err = True` and
    returns the same `ad`.

    Parameters
    ----------
    ad : ActData
        Action/context object that is read and mutated. Expected fields
        used by this function include (but are not limited to):
        - action: ActionID enum indicating the requested operation.
        - in_file_obj, out_file_obj: file-like objects for input/output.
        - in_file_size: size of the input file in bytes.
        - padded_size, unpadded_size: sizes used for the cryptoblob
          (bytes).
        - pad_ikm: initial key material for pad derivation (bytes;
          provided for encryption flows or recovered during decryption
          flows).
        - processed_comments: comment data to be encrypted/decrypted.
        - written_sum: cumulative number of bytes written to output.
        - start_pos, end_pos, max_start_pos: embedding/extraction
          positions.
        - total_out_data_size: expected total output size for progress
          reporting.
        - start_time, last_progress_time: timestamps for progress
          reporting.
        - err: boolean error flag (set to True on failure).
        The function updates these fields (e.g., start_time,
        last_progress_time, written_sum, end_pos) and returns the same
        `ad` instance.

    crypt : Crypto
        Cryptographic context used and updated by the workflow. Fields
        read and/or written include (examples):
        - argon2_password, argon2_salt, blake2_salt, enc_key_hash:
          salts/hashes and password material used for AAD and key
          derivation.
        - enc_key, mac_key: derived keys for encryption and
          authentication.
        - pad_ikm: pad initial key material (may be derived or
          decrypted).
        - nonce and nonce_counter: streaming-cipher state.
        - enc_sum, enc_chunk_count: optional debug counters when
          UNSAFE_DEBUG.
        The function mutates this object (deriving keys, updating
        counters, storing salts and encrypted pad IKM, etc.).

    Returns
    -------
    ActData
        The same `ad` object passed in, updated with results and
        diagnostic fields. On failure the returned object will have
        `ad.err is True`.

    High-level behavior
    -------------------
    - Derives working keys and initializes nonce/counter state.
    - Clears sensitive password material as soon as practical.
    - For encryption actions, writes argon2_salt to output.
    - Encrypts the pad IKM (when encrypting) or reads and decrypts the
      encrypted_pad_ikm (when decrypting), deriving the pad key.
    - Computes pad and payload sizes and validates them.
    - Builds session AAD from relevant salts/hashes/encrypted fields and
      size bytes.
    - Processes padding, payload contents, and comments (encrypting or
      decrypting as appropriate), updating progress counters and
      timestamps.
    - Optionally writes blake2_salt and calls fsync when embedding.
    - Validates final written size against the expected output size.
    - For embed actions, records and logs the cryptoblob location in the
      container.

    Error handling and side effects
    -------------------------------
    - On any I/O, MAC, or helper failure the function sets
      `ad.err = True` and returns `ad`. Helper functions used throughout
      are expected to set `ad.err` on failure where appropriate.
    - Sensitive material (passwords, IKM, derived keys) is cleared as
      early as possible; callers should avoid retaining those values
      after this function.
    - Emits logs via log_i/log_d/log_w/log_e; additional interactive
      prompts or errors may be produced by helper functions called here.
    - May set module-global state used by a termination handler (e.g.,
      `file_obj_to_truncate_by_signal`) while writing output files.

    Dependencies
    ------------
    Relies on the presence of these helpers and module-level names:
    derive_keys, init_nonce_counter, init_new_mac_chunk,
    feed_stream_cipher, hkdf_sha256, get_pad_size_from_padded,
    get_contents_size_from_enc_contents,
    get_enc_contents_size_from_contents, handle_padding,
    handle_payload_file_contents, handle_comments, log_i, log_d, log_w,
    log_e, log_progress_final, write_data, read_data,
    fsync_written_data, format_size, collect, monotonic, UNSAFE_DEBUG,
    NEW_OUT_FILE_ACTIONS, ENCRYPT, ENCRYPT_EMBED, DECRYPT,
    EXTRACT_DECRYPT, MIN_VALID_UNPADDED_SIZE, PAD_KEY_SIZE,
    HKDF_INFO_PAD, SIZE_BYTES_SIZE, BYTEORDER.

    Failure modes
    -------------
    Typical failure conditions that set `ad.err = True` include:
    - I/O errors from read/write helpers.
    - Authentication/MAC failures or corrupted inputs (e.g., invalid
      MAC, missing or malformed encrypted_pad_ikm).
    - Helper functions returning failure states.
    - Final written size mismatch vs expected output size.

    Notes
    -----
    - This function assumes callers have performed necessary input
      validation and populated required `ad` fields before invocation.
    - Debug counters and verbose logging are controlled by
      `UNSAFE_DEBUG`.
    - The function mutates and returns the provided `ActData` instance
      rather than producing a new object.
    """

    # 1. Derive keys needed for encryption/authentication
    # ----------------------------------------------------------------------- #

    ad, crypt = derive_keys(ad=ad, crypt=crypt)
    if ad.err:
        return ad

    # 2. Clean up sensitive data from memory and trigger garbage collection
    # ----------------------------------------------------------------------- #

    del crypt.argon2_password
    collect()

    # 3. Initialize values
    # ----------------------------------------------------------------------- #

    # Initialize nonce counter for the current action
    crypt = init_nonce_counter(crypt)

    ad.start_time = monotonic()
    ad.last_progress_time = monotonic()

    if UNSAFE_DEBUG:
        crypt.enc_sum = 0
        crypt.enc_chunk_count = 0

    action: ActionID = ad.action

    if action in NEW_OUT_FILE_ACTIONS:
        global file_obj_to_truncate_by_signal
        file_obj_to_truncate_by_signal = ad.out_file_obj

    # 4. Write argon2_salt if encrypting
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):
        log_i('writing cryptoblob')

        if UNSAFE_DEBUG:
            log_d('writing argon2_salt')

        ad = write_data(data=crypt.argon2_salt, ad=ad)
        if ad.err:
            return ad

        if UNSAFE_DEBUG:
            log_d('argon2_salt written')

    else:
        log_i('trying to decrypt data')

    # 5. Handle pad_ikm
    # ----------------------------------------------------------------------- #

    crypt = init_new_mac_chunk(crypt)

    encrypted_pad_ikm: Optional[bytes]

    # encrypt pad_ikm, wrie encrypted_pad_ikm
    if action in (ENCRYPT, ENCRYPT_EMBED):
        encrypted_pad_ikm, crypt = feed_stream_cipher(
            input_data=crypt.pad_ikm,
            comment='pad_ikm',
            crypt=crypt,
        )

        if UNSAFE_DEBUG:
            log_d(f'encrypted_pad_ikm: {encrypted_pad_ikm.hex()}')
            log_d('writing encrypted_pad_ikm')

        ad = write_data(data=encrypted_pad_ikm, ad=ad)
        if ad.err:
            return ad

        if UNSAFE_DEBUG:
            log_d(f'encrypted_pad_ikm: {encrypted_pad_ikm.hex()}')
            log_d('writing encrypted_pad_ikm completed')

    # get pad_ikm and pad_key
    else:
        if UNSAFE_DEBUG:
            log_d('reading encrypted_pad_ikm')

        encrypted_pad_ikm = read_data(ad.in_file_obj, PAD_KEY_SIZE)

        if encrypted_pad_ikm is None:
            ad.err = True
            return ad

        if UNSAFE_DEBUG:
            log_d('reading encrypted_pad_ikm completed')

        crypt.pad_ikm, crypt = feed_stream_cipher(
            input_data=encrypted_pad_ikm,
            comment='encrypted_pad_ikm',
            crypt=crypt,
        )

        pad_key = hkdf_sha256(
            input_key=crypt.pad_ikm,
            info=HKDF_INFO_PAD,
            length=PAD_KEY_SIZE,
        )

        if UNSAFE_DEBUG:
            log_d(f'encrypted_pad_ikm: {encrypted_pad_ikm.hex()}')
            log_d(f'pad_ikm:           {crypt.pad_ikm.hex()}')
            log_d(f'pad_key:           {pad_key.hex()}')

    crypt.encrypted_pad_ikm = encrypted_pad_ikm

    # 6. Get pad_size
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):

        pad_size: int = ad.padded_size - ad.unpadded_size

    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
        pad_size = get_pad_size_from_padded(
            padded_size=ad.padded_size,
            pad_key=pad_key,
        )

        ad.unpadded_size = ad.padded_size - pad_size

    # 7. Calculate, log, and validate sizes
    # ----------------------------------------------------------------------- #

    if UNSAFE_DEBUG:
        log_d('calculating additional sizes')

    # Determine the size of the payload file contents to be processed
    if action in (ENCRYPT, ENCRYPT_EMBED):

        contents_size: Optional[int] = ad.in_file_size

    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)

        enc_contents_size: int = ad.unpadded_size - MIN_VALID_UNPADDED_SIZE

        contents_size = get_contents_size_from_enc_contents(enc_contents_size)

        if UNSAFE_DEBUG:
            log_d(f'unpadded_size:     {ad.unpadded_size}')
            log_d(f'enc_contents_size: {enc_contents_size}')
            log_d(f'contents_size:     {contents_size}')

        if contents_size is None:
            ad.err = True
            log_e(MAC_FAIL_MESSAGE)
            return ad

    if contents_size is None:
        raise TypeError

    # Calculate the output data size based on the action
    if action in (ENCRYPT, ENCRYPT_EMBED):
        enc_contents_size = get_enc_contents_size_from_contents(contents_size)
        out_data_size: int = \
            MIN_VALID_UNPADDED_SIZE + enc_contents_size + pad_size

    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
        out_data_size = contents_size

    # For logging writing progress
    ad.total_out_data_size = out_data_size

    # Debug logging for sizes
    if UNSAFE_DEBUG:
        log_d(f'payload file contents size: {format_size(contents_size)}')
        log_d(f'output data size:           {format_size(out_data_size)}')

    # Validate contents size (for decryption actions)
    if contents_size < 0:
        ad.err = True
        log_e(MAC_FAIL_MESSAGE)
        return ad

    if action in (ENCRYPT, ENCRYPT_EMBED):
        log_i(f'data size to write: {format_size(out_data_size)}')

    # 8. Convert sizes to bytes for further authentication
    # ----------------------------------------------------------------------- #

    crypt.padded_size_bytes = \
        ad.padded_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)

    crypt.pad_size_bytes = \
        pad_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)

    crypt.contents_size_bytes = \
        contents_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)

    if UNSAFE_DEBUG:
        log_d(f'padded_size_bytes:   {crypt.padded_size_bytes.hex()}')
        log_d(f'pad_size_bytes:      {crypt.pad_size_bytes.hex()}')
        log_d(f'contents_size_bytes: {crypt.contents_size_bytes.hex()}')

    # 9. Handle padding
    # ----------------------------------------------------------------------- #

    if UNSAFE_DEBUG:
        log_d('handling padding')

    ad, crypt = handle_padding(pad_size=pad_size, ad=ad, crypt=crypt)
    if ad.err:
        return ad

    if UNSAFE_DEBUG:
        log_d('handling padding completed')

    # 10. Handle contents of the payload file based on the action type
    # ----------------------------------------------------------------------- #

    if action in (DECRYPT, EXTRACT_DECRYPT):
        log_i(f'data size to write: {format_size(out_data_size)}')

    if UNSAFE_DEBUG:
        log_d('handling payload file contents')

    ad, crypt = handle_payload_file_contents(
        contents_size=contents_size,
        ad=ad,
        crypt=crypt,
    )
    if ad.err:
        return ad

    if UNSAFE_DEBUG:
        log_d('handling payload file contents completed')

    # 11. Handle comments based on the action type
    # ----------------------------------------------------------------------- #

    if UNSAFE_DEBUG:
        log_d('handling comments')

    ad, crypt = handle_comments(
        processed_comments=ad.processed_comments,
        ad=ad,
        crypt=crypt,
    )
    if ad.err:
        return ad

    if UNSAFE_DEBUG:
        log_d('handling comments completed')

    # 12. Summary
    # ----------------------------------------------------------------------- #

    if UNSAFE_DEBUG:
        if action in (ENCRYPT, ENCRYPT_EMBED):
            log_d(f'encryption completed; total encrypted with ChaCha20: '
                  f'{crypt.enc_chunk_count} chunks, '
                  f'{format_size(crypt.enc_sum)}')
        else:
            log_d(f'decryption completed; total decrypted with ChaCha20: '
                  f'{crypt.enc_chunk_count} chunks, '
                  f'{format_size(crypt.enc_sum)}')

    # Log progress for decryption actions
    if action in (DECRYPT, EXTRACT_DECRYPT):
        log_progress_final(ad)

    # 13. Write blake2_salt if encrypting
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):
        if UNSAFE_DEBUG:
            log_d('writing blake2_salt')

        ad = write_data(data=crypt.blake2_salt, ad=ad)
        if ad.err:
            return ad

        if UNSAFE_DEBUG:
            log_d('blake2_salt written')

        log_progress_final(ad)

    # 14. Validate the total written size against the expected output size
    # -----------------------------------------------------------------------

    if ad.written_sum != out_data_size:
        ad.err = True
        log_e(f'written data size ({ad.written_sum:,} B) does not '
              f'equal expected size ({out_data_size:,} B)')
        return ad

    # 15. Synchronize data to disk if necessary
    # ----------------------------------------------------------------------- #

    if action == ENCRYPT_EMBED:
        log_i('syncing output data to disk')
        fsync_start_time: float = monotonic()

        if not fsync_written_data(ad):
            ad.err = True
            return ad

        fsync_end_time: float = monotonic()
        log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    # 16. Log progress and locations
    # ----------------------------------------------------------------------- #

    # Log the location of the cryptoblob in the container if encrypting
    if action == ENCRYPT_EMBED:
        ad.end_pos = ad.out_file_obj.tell()
        log_w('cryptoblob location is important for its further extraction!')
        log_i(f'remember cryptoblob location in container:\n'
              f'        [{ad.start_pos}:{ad.end_pos}]')

    return ad


# Perform actions EMBED, EXTRACT
# --------------------------------------------------------------------------- #


def embed(ad: ActData) -> ActData:
    """
    Orchestrate embed or extract: prepare inputs then perform the
    operation.

    Calls embed_input(ad) to open files and determine start position and
    message size. If preparation succeeds (ad.err is False), calls
    embed_handler(ad) to perform the read/write and checksum work.

    Parameters
    ----------
    ad : ActData
        ActData instance with .action set to EMBED or EXTRACT. On return
        the function will have updated fields from the called helpers
        (e.g., .in_file_obj, .out_file_obj, .start_pos,
        .total_out_data_size, .written_sum, and .err).

    Returns
    -------
    ActData
        The same ActData instance. On failure ad.err is set True.
    """
    ad = embed_input(ad)
    if ad.err:
        return ad

    ad = embed_handler(ad)
    return ad


def embed_input(ad: ActData) -> ActData:
    """
    Prepare input/output files and determine start position and message
    size.

    Locates and opens the input file, prepares the output file (existing
    for EMBED, new for EXTRACT), determines the allowed range for the
    operation, prompts the user if needed, and stores start_pos and
    total_out_data_size on the provided ActData instance.

    Parameters
    ----------
    ad : ActData
        ActData instance with .action set to EMBED or EXTRACT. On return
        the function sets:
        - ad.in_file_obj: opened input file object
        - ad.out_file_obj: opened output file object
        - ad.start_pos (int): chosen start offset
        - ad.total_out_data_size (int): number of bytes to transfer
        The function sets ad.err = True if the user cancels or an error
        occurs.

    Returns
    -------
    ActData
        The same ActData instance. If the operation was cancelled or
        failed, ad.err will be True.

    Notes
    -----
    - For EMBED: verifies output file exists (get_output_file_exist) and
      computes max_start_pos = out_file_size - in_file_size;
      message_size = in_file_size. Prompts the user for confirmation via
      proceed_request(PROCEED_OVERWRITE, ad).
    - For EXTRACT: creates a new output file (get_output_file_new) and
      uses max_start_pos = in_file_size; message_size is derived from
      start/end positions.
    - Uses get_start_position() and get_end_position() to obtain
      user-selected offsets; logs path, sizes, start/end positions, and
      message size.
    - On user cancellation the function sets ad.err = True and logs the
      stop.
    """
    in_file_path: str
    out_file_path: str
    in_file_size: int
    out_file_size: int
    start_pos: int
    end_pos: int
    max_start_pos: int
    message_size: int

    action: ActionID = ad.action

    if action == EMBED:
        log_w('this action does not provide encryption and authentication!')
    else:
        log_w('this action does not provide authentication!')

    # Retrieve the input file path and size based on the action
    in_file_path, in_file_size, ad.in_file_obj = get_input_file(action)

    # Log the path and size of the input file
    log_i(f'path: {in_file_path!r}; size: {format_size(in_file_size)}')

    if action == EMBED:
        # For embedding, retrieve the existing output file and its size
        out_file_path, out_file_size, ad.out_file_obj = get_output_file_exist(
            in_file_path=in_file_path,
            min_out_size=in_file_size,
            action=action,
        )

        max_start_pos = out_file_size - in_file_size
        log_i(f'path: {out_file_path!r}')

    else:  # action EXTRACT
        # For extraction, create a new output file
        out_file_path, ad.out_file_obj = get_output_file_new(action)

        max_start_pos = in_file_size
        log_i(f'new empty file {out_file_path!r} created')

    if action == EMBED:
        # Log the size of the output file for embedding
        log_i(f'size: {format_size(out_file_size)}')

    # Get the starting position for embedding or extraction
    start_pos = get_start_position(
        max_start_pos=max_start_pos,
        no_default=True,
    )
    log_i(f'start position: {start_pos} (offset: {start_pos:,} B)')

    if action == EMBED:
        # For embedding, set message size to input file size
        message_size = in_file_size
        end_pos = start_pos + message_size
        log_i(f'end position: {end_pos} (offset: {end_pos:,} B)')

        # Prompt user for confirmation before proceeding
        if not proceed_request(proceed_type=PROCEED_OVERWRITE, ad=ad):
            ad.err = True
            log_i('stopped by user request\n')
    else:
        # For extraction, calculate end position and message size
        end_pos = get_end_position(
            min_pos=start_pos,
            max_pos=in_file_size,
            no_default=True,
        )
        log_i(f'end position: {end_pos} (offset: {end_pos:,} B)')

        message_size = end_pos - start_pos
        log_i(f'message size to retrieve: {format_size(message_size)}')

    ad.start_pos = start_pos
    ad.total_out_data_size = message_size

    return ad


def embed_handler(ad: ActData) -> ActData:
    """
    Embed or extract a message from a container, writing data and
    computing a checksum.

    This handler transfers `message_size` bytes between input and output
    in chunked reads/writes, updates a running BLAKE2b checksum, reports
    progress, and verifies the total written size. For embed operations
    into a new output file, the output object is registered so a
    termination handler can truncate an incomplete file; the output is
    also fsynced after writing.

    Parameters
    ----------
    ad : ActData
        Action/context object used and mutated. Required fields include:
        - action (ActionID): EMBED or EXTRACT.
        - start_pos (int): start offset in the relevant file.
        - total_out_data_size (int): number of bytes to transfer
          (message size).
        - in_file_obj / out_file_obj: file-like objects for
          reading/writing.
        The function sets/updates:
        - ad.start_time, ad.last_progress_time: monotonic timestamps for
          progress.
        - ad.written_sum: cumulative bytes written.
        - ad.err: set to True on failure.
        - ad.end_pos: (on EMBED) final position after writing.

    Returns
    -------
    ActData
        The same `ad` instance, updated. On failure `ad.err` is set True.

    Behavior and error handling
    ---------------------------
    - If `action` is in `NEW_OUT_FILE_ACTIONS`, registers
      `ad.out_file_obj` in module-global state so a termination handler
      can truncate it if needed.
    - Seeks to `start_pos` on the appropriate file object (output for
      EMBED, input for EXTRACT); on seek failure sets `ad.err` and
      returns.
    - Transfers data in full chunks of `MAX_PT_CHUNK_SIZE` and a final
      remainder chunk, using `read_data` and `write_data`. If any helper
      signals failure (None or `ad.err`), returns with `ad.err = True`.
    - Maintains a BLAKE2b digest (`CHECKSUM_SIZE` bytes) updated for
      every transferred chunk; the hex digest is logged on success.
    - Calls `log_progress_final(ad)` after transfer completes.
    - Validates `ad.written_sum == message_size`; on mismatch sets
      `ad.err`, logs an error, and returns.
    - For EMBED, calls `fsync_written_data(ad)` and logs the duration;
      on failure sets `ad.err` and returns.
    - Logs the message checksum and, for EMBED, the message location
      `[start_pos:end_pos]` (and a warning about remembering the
      location).

    Globals and dependencies
    ------------------------
    Relies on module-level names and helpers:
    `NEW_OUT_FILE_ACTIONS`, `MAX_PT_CHUNK_SIZE`, `CHECKSUM_SIZE`,
    `read_data`, `write_data`, `seek_position`, `log_i`, `log_w`,
    `log_e`, `log_progress_final`, `fsync_written_data`, `format_size`,
    and `monotonic`.

    Notes
    -----
    - Progress logging and I/O error handling are delegated to helper
      functions (`read_data`, `write_data`, etc.), which are expected to
      set `ad.err` on failure where appropriate.
    - The function mutates and returns the provided `ActData` instance.
    - Must be called from the main thread at appropriate safe points if
      used alongside signal-handling truncation logic.
    """
    action: ActionID = ad.action
    start_pos: int = ad.start_pos
    message_size: int = ad.total_out_data_size

    if action in NEW_OUT_FILE_ACTIONS:
        global file_obj_to_truncate_by_signal
        file_obj_to_truncate_by_signal = ad.out_file_obj

    # Seek to the start position in the appropriate container
    if action == EMBED:
        if not seek_position(ad.out_file_obj, offset=start_pos):
            ad.err = True
            return ad

        log_i('reading message from input and writing it over output')

    else:  # action == EXTRACT
        if not seek_position(ad.in_file_obj, offset=start_pos):
            ad.err = True
            return ad

        log_i('reading message from input and writing it to output')

    # Initialize the BLAKE2 hash object for checksum calculation
    hash_obj: Any = blake2b(digest_size=CHECKSUM_SIZE)

    ad.start_time = monotonic()
    ad.last_progress_time = monotonic()

    ad.total_out_data_size = message_size

    full_chunks: int = message_size // MAX_PT_CHUNK_SIZE
    remain_size: int = message_size % MAX_PT_CHUNK_SIZE

    # Read and write complete chunks of data
    for _ in range(full_chunks):

        message_chunk: Optional[bytes] = \
            read_data(ad.in_file_obj, MAX_PT_CHUNK_SIZE)
        if message_chunk is None:
            ad.err = True
            return ad

        ad = write_data(data=message_chunk, ad=ad)
        if ad.err:
            return ad

        hash_obj.update(message_chunk)

    # Write any remaining bytes that do not fit into a full chunk
    if remain_size:

        message_chunk = read_data(ad.in_file_obj, remain_size)
        if message_chunk is None:
            ad.err = True
            return ad

        ad = write_data(data=message_chunk, ad=ad)
        if ad.err:
            return ad

        hash_obj.update(message_chunk)

    log_progress_final(ad)

    # Validate the total written size against the expected output size
    if ad.written_sum != message_size:
        ad.err = True
        log_e(f'written data size ({ad.written_sum:,} B) does not '
              f'equal expected size ({message_size:,} B)')
        return ad

    if action == EMBED:
        log_i('syncing output data to disk')
        fsync_start_time: float = monotonic()

        # Synchronize the output data to ensure all changes are flushed
        if not fsync_written_data(ad):
            ad.err = True
            return ad

        fsync_end_time: float = monotonic()
        log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    # Compute the checksum of the written data
    message_checksum: str = hash_obj.hexdigest()

    # Get the current position in the output container
    end_pos: int = ad.out_file_obj.tell()

    if action == EMBED:
        log_w('message location is important for its further extraction!')

        # Log the location of the embedded message in the container
        log_i(f'remember message location in container:\n'
              f'        [{start_pos}:{end_pos}]')

    log_i(f'message checksum:\n        {message_checksum}')

    return ad


# Perform action CREATE_W_RANDOM
# --------------------------------------------------------------------------- #


def create_with_random(ad: ActData) -> ActData:
    """
    Create a new output file and fill it with random data.

    Orchestrates file creation (create_with_random_input) and the write
    phase (create_with_random_handler). On success, ad.err remains False
    and ad.written_sum == ad.total_out_data_size.

    Parameters
    ----------
    ad : ActData
        ActData instance with .action set. On return the function will
        have updated .out_file_obj, .total_out_data_size, .written_sum,
        and .err.

    Returns
    -------
    ActData
        The same ActData instance. ad.err is set to True on failure.
    """
    ad = create_with_random_input(ad)
    ad = create_with_random_handler(ad)
    return ad


def create_with_random_input(ad: ActData) -> ActData:
    """
    Create a new empty output file for the given action and record its
    size.

    Uses ad.action to create and open a new output file, logs the
    created path, stores the opened file object on ad.out_file_obj, and
    sets ad.total_out_data_size to the file's size in bytes (typically
    zero for a new file).

    Parameters
    ----------
    ad : ActData
        ActData instance whose .action field selects the output file. On
        return the function sets:
        - ad.out_file_obj: opened output file object.
        - ad.total_out_data_size (int): size of the created output file
          in bytes.

    Returns
    -------
    ActData
        The same ActData instance with updated fields. On failure ad.err
        should be set by the called helpers.
    """
    out_file_path: str

    out_file_path, ad.out_file_obj = get_output_file_new(ad.action)

    log_i(f'new empty file {out_file_path!r} created')

    ad.total_out_data_size = get_output_file_size()

    log_i(f'size: {format_size(ad.total_out_data_size)}')

    return ad


def create_with_random_handler(ad: ActData) -> ActData:
    """
    Write cryptographically random data to the output file in chunks and
    report progress.

    This handler writes `ad.total_out_data_size` bytes of
    cryptographically random data to `ad.out_file_obj` in chunked writes
    of up to `MAX_PT_CHUNK_SIZE`. While writing, it sets the module
    signal reference so a concurrent termination handler can truncate
    the incomplete file. Progress timestamps and counters on the
    provided `ActData` instance are updated; on error the function sets
    `ad.err = True` and returns the same
    `ActData` instance.

    Parameters
    ----------
    ad : ActData
        Action data with these expected fields before call:
        - out_file_obj: a writable binary file-like object.
        - total_out_data_size (int): total number of bytes to write.
        The function sets/updates:
        - ad.start_time (float): monotonic timestamp when writing
          started.
        - ad.last_progress_time (float): monotonic timestamp of last
          progress.
        - ad.written_sum (int): cumulative bytes written.
        - ad.err (bool): set to True on failure.

    Returns
    -------
    ActData
        The same `ad` instance. On failure `ad.err` is set to True.

    Behavior and error handling
    ---------------------------
    - Sets the module-global `file_obj_to_truncate_by_signal` to
      `ad.out_file_obj` before writing and relies on callers/cleanup to
      clear it afterward.
    - Writes full-size chunks (MAX_PT_CHUNK_SIZE) using `token_bytes()`
      and `write_data(data=..., ad=ad)` for each chunk.
    - If `write_data` indicates an error (`ad.err`), returns immediately
      with `ad.err` set True.
    - After all chunks are written, calls `log_progress_final(ad)` to
      record final progress.
    - Verifies `ad.written_sum == ad.total_out_data_size`; on mismatch
      logs an error via `log_e` and sets `ad.err = True`.

    Globals and dependencies
    ------------------------
    Relies on module-level names and helpers:
    `file_obj_to_truncate_by_signal`, `MAX_PT_CHUNK_SIZE`,
    `token_bytes`, `write_data`, `log_i`, `log_e`, `log_progress_final`,
    and `monotonic`.
    """
    global file_obj_to_truncate_by_signal
    file_obj_to_truncate_by_signal = ad.out_file_obj

    log_i('writing random data')

    ad.start_time = monotonic()
    ad.last_progress_time = monotonic()

    # Calculate the number of complete chunks and remaining bytes to write
    full_chunks: int = ad.total_out_data_size // MAX_PT_CHUNK_SIZE
    remain_size: int = ad.total_out_data_size % MAX_PT_CHUNK_SIZE

    # Write complete chunks of random data
    for _ in range(full_chunks):
        # Generate a chunk of random data
        chunk: bytes = token_bytes(MAX_PT_CHUNK_SIZE)

        # Write the generated chunk to the output file
        ad = write_data(data=chunk, ad=ad)
        if ad.err:
            return ad

    # Write any remaining bytes that do not fit into a full chunk
    if remain_size:
        # Generate the last chunk of random data
        chunk = token_bytes(remain_size)

        ad = write_data(data=chunk, ad=ad)
        if ad.err:
            return ad

    log_progress_final(ad)

    # Validate the total written size against the expected output size
    if ad.written_sum != ad.total_out_data_size:
        log_e(f'written data size ({ad.written_sum:,} B) does not '
              f'equal expected size ({ad.total_out_data_size:,} B)')
        ad.err = True

    return ad


# Perform action OVERWRITE_W_RANDOM
# --------------------------------------------------------------------------- #


def overwrite_with_random(ad: ActData) -> ActData:
    """
    Overwrite a specified range of the output file with random data.

    Orchestrates the interactive input phase and the write phase: it
    determines the overwrite range (overwrite_with_random_input), and if
    that preparation succeeds, writes cryptographically random data to
    the output file in chunks (overwrite_with_random_handler).

    Parameters
    ----------
    ad : ActData
        ActData instance with .action set. On success the function will
        set .start_pos, .total_out_data_size, .out_file_obj, and update
        .written_sum and .err as the operation progresses.

    Returns
    -------
    ActData
        The same ActData instance. On failure ad.err is set True.
    """
    ad = overwrite_with_random_input(ad)
    if ad.err:
        return ad

    ad = overwrite_with_random_handler(ad)
    return ad


def overwrite_with_random_input(ad: ActData) -> ActData:
    """
    Determine overwrite range for an output file and prepare ActData.

    Retrieves the output file path and size for the given action,
    prompts the user for a start and end position, computes the data
    size to be overwritten, and stores these values in the provided
    ActData instance.

    Parameters
    ----------
    ad : ActData
        ActData instance whose .action field is used to locate the
        output file. On success the function sets:
        - ad.out_file_obj: opened output file object
        - ad.start_pos (int): start offset for overwrite
        - ad.total_out_data_size (int): number of bytes to write
        The function sets ad.err = True if the operation is cancelled or
        otherwise cannot proceed.

    Returns
    -------
    ActData
        The same ActData instance. If the operation is cancelled or
        there is nothing to do, ad.err is set to True.

    Notes
    -----
    - Uses get_output_file_exist() to obtain (path, size, file_obj).
    - Uses get_start_position() and get_end_position() to determine the
      overwrite range; computed data_size = end_pos - start_pos.
    - Prompts the user for confirmation via
      proceed_request(PROCEED_OVERWRITE, ad) and aborts (ad.err = True)
      if the user declines.
    - Logs path, sizes, start/end positions, and the data size to be
      written.
    """
    out_file_path: str
    out_file_size: int

    # Retrieve the output file path and size based on the provided action
    out_file_path, out_file_size, ad.out_file_obj = get_output_file_exist(
        in_file_path='',
        min_out_size=0,
        action=ad.action,
    )
    log_i(f'path: {out_file_path!r}; size: {format_size(out_file_size)}')

    # Get the starting position for the overwrite operation
    start_pos: int = get_start_position(
        max_start_pos=out_file_size,
        no_default=False,
    )
    log_i(f'start position: {start_pos} (offset: {start_pos:,} B)')

    # Get the ending position for the overwrite operation
    end_pos: int = get_end_position(
        min_pos=start_pos,
        max_pos=out_file_size,
        no_default=False,
    )
    log_i(f'end position: {end_pos} (offset: {end_pos:,} B)')

    # Calculate the size of the data to be written
    data_size: int = end_pos - start_pos
    log_i(f'data size to write: {format_size(data_size)}')

    ad.start_pos = start_pos
    ad.total_out_data_size = data_size

    # Prompt the user for confirmation before proceeding
    if not proceed_request(proceed_type=PROCEED_OVERWRITE, ad=ad):
        log_i('stopped by user request')
        ad.err = True

    return ad


def overwrite_with_random_handler(ad: ActData) -> ActData:
    """
    Overwrite a range of the output file with random data and
    verify/sync.

    Seeks to ad.start_pos in the output file and writes
    ad.total_out_data_size bytes of cryptographically random data in
    chunks. Tracks bytes written, logs progress, verifies the final
    written size, and fsyncs the file.

    Parameters
    ----------
    ad : ActData
        ActData instance with at least these fields set/used:
        - start_pos (int): starting position in the output file.
        - total_out_data_size (int): number of bytes to write.
        - out_file_obj: file-like object for writing.
        The function updates ad.written_sum, ad.start_time,
        ad.last_progress_time, and ad.err as it runs.

    Returns
    -------
    ActData
        The same ActData instance with ad.err set to True on failure.
        On success ad.err remains False and
        ad.written_sum == total_out_data_size.

    Notes
    -----
    - Uses MAX_PT_CHUNK_SIZE to split writes into full chunks plus a
      remainder.
    - Writes are generated with token_bytes().
    - write_data(ad, chunk) is expected to update ad.written_sum and
      ad.err.
    - If UNSAFE_DEBUG is enabled, current stream positions may be
      logged.
    - After writing, log_progress_final(ad) is called, then
      fsync_written_data(ad)
      is used to flush data to disk. Timing for fsync is logged.
    - On mismatch between ad.written_sum and expected size, ad.err is
      set and an error is logged.
    """
    start_pos = ad.start_pos
    data_size = ad.total_out_data_size

    # Seek to the specified start position in the output file
    if not seek_position(ad.out_file_obj, offset=start_pos):
        ad.err = True
        return ad

    log_i('writing random data')

    ad.start_time = monotonic()
    ad.last_progress_time = monotonic()

    # Calculate the number of complete chunks and remaining bytes to write
    full_chunks: int = data_size // MAX_PT_CHUNK_SIZE
    remain_size: int = data_size % MAX_PT_CHUNK_SIZE

    # Write complete chunks of random data
    for _ in range(full_chunks):
        chunk: bytes = token_bytes(MAX_PT_CHUNK_SIZE)
        ad = write_data(data=chunk, ad=ad)
        if ad.err:
            return ad

    # Write any remaining bytes that do not fit into a full chunk
    if remain_size:
        chunk = token_bytes(remain_size)
        ad = write_data(data=chunk, ad=ad)
        if ad.err:
            return ad

    log_progress_final(ad)

    # Validate the total written size against the expected output size
    if ad.written_sum != data_size:
        ad.err = True
        log_e(f'written data size ({ad.written_sum:,} B) does not '
              f'equal expected size ({data_size:,} B)')
        return ad

    log_i('syncing output data to disk')

    fsync_start_time: float = monotonic()

    # Synchronize the file to ensure all changes are flushed to disk
    if not fsync_written_data(ad):
        ad.err = True
        return ad

    fsync_end_time: float = monotonic()

    # Log the time taken for fsync
    log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    return ad


# Misc
# --------------------------------------------------------------------------- #


def perform_file_action(action: ActionID) -> None:
    """
    Execute a file-oriented action, run cleanup, and log results.

    This function records that a file operation is in progress, creates
    an ActData instance for the action, dispatches the corresponding
    handler from FILE_ACTION_MAP, and always runs post-action cleanup.

    Parameters
    ----------
    action : ActionID
        Identifier of the file action to perform. Must be a key in
        FILE_ACTION_MAP.

    Returns
    -------
    None
        Performs side effects (calls handler, cleanup, logging) and does
        not return a value.

    Behavior and error handling
    ---------------------------
    - Initializes a new `ActData` object `ad` and sets:
    - `ad.action` to the provided action,
    - `ad.written_sum` to 0,
    - `ad.err` to False.
    - If `UNSAFE_DEBUG` is true, logs each message in
      `UNSAFE_DEBUG_WARNINGS` via `log_w`.
    - Dispatches the action handler: `ad = FILE_ACTION_MAP[action](ad)`.
    - Always calls `post_action_clean_up(ad)` after the handler returns.
    - If the handler indicates success (`ad.err` is False), logs
      "action completed" with `log_i`.
    - Handlers are expected to mutate and/or return the `ActData`
      instance, setting `ad.err` to a truthy value on failure.

    Globals and dependencies
    ------------------------
    Relies on these module-level names being defined:
    `ANY_D`, `UNSAFE_DEBUG`, `UNSAFE_DEBUG_WARNINGS`, `FILE_ACTION_MAP`,
    `ActData`, `post_action_clean_up`, `log_w`, and `log_i`.
    """
    if UNSAFE_DEBUG:
        for warning in UNSAFE_DEBUG_WARNINGS:
            log_w(warning)

    ad: ActData = ActData()

    ad.action = action
    ad.written_sum = 0
    ad.err = False

    ad = FILE_ACTION_MAP[action](ad)

    post_action_clean_up(ad)

    if not ad.err:
        log_i('action completed')


def post_action_clean_up(ad: ActData) -> None:
    """
    Perform resource cleanup and post-action housekeeping.

    Closes any open input/output file objects referenced by the provided
    ActData, removes a partially written output file when appropriate,
    clears the module-level signal flag that may reference an output
    file, and triggers a garbage-collection pass.

    Parameters
    ----------
    ad : ActData
        ActData instance describing the just-performed action. Expected
        attributes used by this function:
        - in_file_obj (optional): input file-like object to close.
        - out_file_obj (optional): output file-like object to close or
          truncate.
        - action (ActionID): performed action (used to decide
          output-file handling).
        - err (bool): indicates whether the action failed.

    Returns
    -------
    None

    Notes
    -----
    - If `ad.in_file_obj` exists, it is closed via `close_file()`.
    - If `ad.out_file_obj` exists:
        - If the action succeeded (`ad.err` is False) or the action does
          not create a new output file (`ad.action not in
          NEW_OUT_FILE_ACTIONS`), the output file is closed via
          `close_file()`.
        - Otherwise (failed write for an action that creates a new
          output file), the output file is truncated via
          `truncate_output_file(ad)` and `remove_output_path(ad)` is
          called to remove the partial file.
    - The module-level reference `file_obj_to_truncate_by_signal` is
      cleared (set to `None`) unconditionally.
    - `collect()` is called to run a garbage-collection pass.
    - This function performs non-signal-safe cleanup and must be invoked
      from normal program flow (not directly from a signal handler).
    """
    check_for_signal()  # Check if a termination signal has been received

    if hasattr(ad, 'in_file_obj'):
        close_file(ad.in_file_obj)

    if hasattr(ad, 'out_file_obj'):
        if not ad.err or ad.action not in NEW_OUT_FILE_ACTIONS:
            close_file(ad.out_file_obj)
        else:
            truncate_output_file(ad)
            remove_output_path(ad)

    global file_obj_to_truncate_by_signal
    file_obj_to_truncate_by_signal = None

    collect()


def cli_handler() -> tuple[bool, bool]:
    """
    Parse command-line arguments and return feature flags.

    This function inspects sys.argv[1:] and interprets a small, explicit
    set of supported options. Duplicate arguments are ignored (arguments
    are treated as a set). Behavior is strict: any unrecognized option
    causes an error message (printed to stderr-styled output), displays
    the help text, and exits the process.

    Supported options
    -----------------
    --help
        Print the help message and exit with status 0.
    --unsafe-debug
        Enable unsafe debug mode; returned as the first boolean in the
        tuple.
    --unsafe-decrypt
        Enable unsafe decrypt mode (unsafe — releases plaintext even if
        MAC verification failed); returned as the second boolean in the
        tuple.

    Returns
    -------
    tuple[bool, bool]
        (unsafe_debug_enabled, unsafe_decrypt_enabled)
        - unsafe_debug_enabled: True when '--unsafe-debug' is present
          (False otherwise).
        - unsafe_decrypt_enabled: True when '--unsafe-decrypt' is
          present (False otherwise).

    Behavior on invalid input
    -------------------------
    If any unrecognized option is present, prints an error line showing
    the invalid option (with ERR/RES color markers) to stderr, prints
    the help message to stderr, and exits with status 1. When '--help'
    is explicitly requested the help message is printed to stdout and
    the process exits with status 0.

    Notes
    -----
    - The function uses a set of argv[1:], so argument order and
      duplicates are discarded.
    - HELP_MESSAGE, argv, stderr, and color markers (ERR, RES) are
      expected to be defined in the module scope.
    """
    help_enabled: bool = False
    unsafe_debug_enabled: bool = False
    unsafe_decrypt_enabled: bool = False

    user_options: set[str] = set(argv[1:])

    for option in user_options:

        if option == '--help':
            help_enabled = True

        elif option == '--unsafe-debug':
            unsafe_debug_enabled = True

        elif option == '--unsafe-decrypt':
            unsafe_decrypt_enabled = True

        else:
            print(f'{ERR}Error: invalid option: {option!r}{RES}\n')
            print(HELP_MESSAGE, file=stderr)
            sys_exit(1)

    if help_enabled:
        print(HELP_MESSAGE)
        sys_exit(0)

    return unsafe_debug_enabled, unsafe_decrypt_enabled


def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
    """
    Signal-safe handler that requests orderly termination.

    Sets the module-level flag `termination_signal_received` to True so
    the main thread can perform non-signal-safe cleanup and exit. If no
    file handler is running, the handler writes a brief message to
    stderr using the signal-safe `os.write` and calls `os_exit(1)` to
    terminate immediately.

    Parameters
    ----------
    signum : int
        Signal number delivered to the process.
    frame : Optional[FrameType]
        Current stack frame (may be `None`).

    Returns
    -------
    None

    Notes
    -----
    - The handler performs only async-signal-safe operations: setting a
      simple global boolean and a single `os.write` on file
      descriptor 2. It ignores `OSError` from `os.write` to avoid
      raising exceptions in the handler.
    - If `termination_signal_received` is already `True`, the handler
      is a no-op.
    - If `file_obj_to_truncate_by_signal` is not `None` (indicating an
      in-progress file operation), the handler sets the flag and returns
      so the main thread can finish and clean up.
    - If no file handler is active, a short message is written to stderr
      and `os_exit(1)` is invoked to terminate immediately.
    - All non-signal-safe cleanup must be done by the main thread after
      it observes `termination_signal_received == True`.
    """
    global termination_signal_received

    if termination_signal_received:
        return

    # Main thread checks and performs cleanup/exit
    termination_signal_received = True

    if file_obj_to_truncate_by_signal is not None:
        return

    try:
        write(2, TERMINATED_MESSAGE)
    except OSError:
        pass

    os_exit(1)


def check_for_signal() -> None:
    """
    Perform main-thread cleanup and exit if a termination signal was
    received.

    When a termination signal has been recorded by the signal handler
    (termination_signal_received is true), this function performs non-
    signal-safe cleanup for any in-progress output-file operation,
    writes a
    brief termination message to stderr using a signal-safe os.write,
    and then exits the process with status code 1.

    Parameters
    ----------
    None

    Returns
    -------
    None
        Performs side effects (flush, ftruncate, close, write, exit) and
        does not return.

    Behavior and error handling
    ---------------------------
    - Must be invoked from the main thread at safe points. The signal
      handler itself must only set `termination_signal_received`.
    - If no termination signal has been recorded, the function returns
      immediately.
    - If `file_obj_to_truncate_by_signal` is not None, the function
      will:
      1. Flush the file object,
      2. Truncate its underlying file descriptor to zero bytes via
         `ftruncate`,
      3. Close the file object.
      Any OSError or ValueError raised during these steps is suppressed
      to avoid interfering with process termination.
    - Writes a short termination message to file descriptor 2 using a
      signal-safe `write(fd, bytes)` call. OSError from `write` is
      ignored.
    - Calls `sys_exit(1)` to terminate the process.

    Globals and dependencies
    ------------------------
    Relies on these module-level names being defined:
    `termination_signal_received`, `file_obj_to_truncate_by_signal`,
    `ftruncate`, `TERMINATED_MESSAGE`, `write`, and `sys_exit`.

    Examples
    --------
    # Periodically call from main loop to react to signals:
    check_for_signal()
    """
    if not termination_signal_received:
        return

    # Clean up: truncate incomplete output
    if file_obj_to_truncate_by_signal is not None:
        try:
            file_obj_to_truncate_by_signal.flush()
            ftruncate(file_obj_to_truncate_by_signal.fileno(), 0)
            file_obj_to_truncate_by_signal.close()
        except (OSError, ValueError):
            pass

    try:
        write(2, TERMINATED_MESSAGE)
    except OSError:
        pass

    sys_exit(1)


def prevent_coredump() -> None:
    """
    Disable core dumps by setting RLIMIT_CORE to zero.

    Calls setrlimit(RLIMIT_CORE, (0, 0)) to set both the soft and hard
    core-file size limits to 0, preventing core dump creation on POSIX
    systems. Useful to avoid accidental leakage of sensitive memory
    (for example, cryptographic material) if the process crashes.

    Notes
    -----
    - Intended for POSIX-compliant systems; setrlimit may not exist on
      non-POSIX platforms.
    - Exceptions (OSError, ValueError) are caught; when UNSAFE_DEBUG is
      true the error is logged.
    """
    try:
        setrlimit(RLIMIT_CORE, (0, 0))
    except (OSError, ValueError) as error:
        if UNSAFE_DEBUG:
            log_e(f'{error}')


def main() -> NoReturn:
    """
    Program entry point: initialize, register signal handlers, and run
    loop.

    Initializes runtime settings, registers signal handlers (SIGINT,
    SIGTERM, and on POSIX also SIGHUP and SIGQUIT), optionally disables
    core dumps, and enters the main interactive loop that prompts the
    user for actions and dispatches them until the user chooses to exit.

    Parameters
    ----------
    None

    Returns
    -------
    NoReturn
        This function does not return; it exits the process on
        termination.

    Notes
    -----
    - When UNSAFE_DEBUG is enabled, initial debug warnings from
      UNSAFE_DEBUG_WARNINGS are logged.
    - If RESOURCE_MODULE_AVAILABLE is True, prevent_coredump() is
      called.
    - Signal handlers are set to signal_handler for graceful
      termination.
    - The main loop repeatedly calls select_action(); when
      select_action() returns EXIT the process exits with status 0. INFO
      triggers info_and_warnings(), other actions are handled by
      perform_file_action(action).
    - Graceful cleanup is performed only if a file operation is in
      progress; otherwise, the process terminates immediately via
      os_exit(1).
    """
    if UNSAFE_DEBUG:
        for warning in UNSAFE_DEBUG_WARNINGS:
            log_w(warning)

    if UNSAFE_DECRYPT:
        for warning in UNSAFE_DECRYPT_WARNINGS:
            log_w(warning)

    if RESOURCE_MODULE_AVAILABLE:
        prevent_coredump()

    signal(SIGINT, signal_handler)
    signal(SIGTERM, signal_handler)

    if platform != 'win32':
        signal(SIGHUP, signal_handler)
        signal(SIGQUIT, signal_handler)

    while True:
        action: ActionID = select_action()

        if action == EXIT:
            sys_exit(0)
        elif action == INFO:
            info_and_warnings()
        else:
            perform_file_action(action)


# Define constants
# --------------------------------------------------------------------------- #


# ANSI escape codes for terminal text formatting
BOL: Final[str] = '\x1b[1m'  # Bold text
ERR: Final[str] = '\x1b[1;97;101m'  # Bold white text, red background
WAR: Final[str] = '\x1b[1;93;40m'  # Bold yellow text, black background
RES: Final[str] = '\x1b[0m'  # Reset formatting to default


# Version of the application
APP_VERSION: Final[str] = '0.22.0'

# Information string for the application
APP_INFO: Final[str] = f"""tird v{APP_VERSION}
        A tool for encrypting files and hiding encrypted data.
        Homepage: https://github.com/hakavlad/tird"""

# Debug information string for the Python version
APP_UNSAFE_DEBUG_INFO: Final[str] = f'Python version {version!r}'

# Warnings related to the application usage
APP_WARNINGS: Final[tuple[str, ...]] = (
    'The author does not have a background in cryptography.',
    'The code has no automated test coverage.',
    'tird has not been independently security-audited by humans.',
    'tird is ineffective in a compromised environment; executing it in such '
    'cases may cause catastrophic data leaks.',
    'tird is unlikely to be effective when used with short and predictable '
    'keys.',
    'tird does not erase its sensitive data from memory after use; '
    'keys may persist in memory after program exit.',
    'Sensitive data may leak into swap space.',
    'tird does not sort digests of keyfiles and passphrases in constant-time.',
    'Overwriting file contents does not guarantee secure destruction of data '
    'on the media.',
    'You cannot prove to an adversary that your random data does not contain '
    'encrypted information.',
    'tird protects data, not the user; it cannot prevent torture if you are '
    'under suspicion.',
    'Key derivation consumes 1 GiB of RAM, which may lead to performance '
    'issues or crashes on low-memory systems.',
    'Integrity/authenticity over availability — altering even a single byte '
    'of a cryptoblob prevents decryption.',
    'Development is not complete, and there may be backward compatibility '
    'issues.',
)

# Prompt message string defining the menu of available actions for the user
APP_MENU: Final[str] = f"""{BOL}
                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ Random  9. Overwrite w/ Random
    ———————————————————————————————————————————
A0. SELECT AN OPTION [0-9]:{RES} """

UNSAFE_DEBUG_WARNINGS: Final[list[str]] = [
    'Unsafe Debug Mode enabled! Sensitive data will be exposed!',
    'do not enter real passphrases or sensitive information!',
]

UNSAFE_DECRYPT_WARNINGS: Final[list[str]] = [
    'Unsafe Decrypt Mode enabled: plaintext will be released even '
    'if integrity/authenticity checks fail!',
    'only use when availability is more important than integrity, '
    'and you understand the risks!',
]

MAC_FAIL_MESSAGE: Final[str] = \
    'decryption failed: invalid data or incorrect keys'

TERMINATED_MESSAGE: Final[bytes] = \
    f'\n{ERR}Terminated by signal{RES}\n'.encode()

HELP_MESSAGE: Final[str] = f"""{APP_INFO}

Start without options for normal usage.

Options:
    --help
        print this message and exit
    --unsafe-debug
        enable unsafe debug mode
    --unsafe-decrypt
        release plaintext even if MAC verification failed (dangerous)"""

# Constants for action types
EXIT: Final[ActionID] = 0  # Exit
INFO: Final[ActionID] = 1  # Info & Warnings
ENCRYPT: Final[ActionID] = 2  # Encrypt
DECRYPT: Final[ActionID] = 3  # Decrypt
EMBED: Final[ActionID] = 4  # Embed
EXTRACT: Final[ActionID] = 5  # Extract
ENCRYPT_EMBED: Final[ActionID] = 6  # Encrypt & Embed
EXTRACT_DECRYPT: Final[ActionID] = 7  # Extract & Decrypt
CREATE_W_RANDOM: Final[ActionID] = 8  # Create w/ Random
OVERWRITE_W_RANDOM: Final[ActionID] = 9  # Overwrite w/ Random

# Actions that creates new output file
NEW_OUT_FILE_ACTIONS: Final[set[ActionID]] = \
    {ENCRYPT, DECRYPT, EXTRACT, EXTRACT_DECRYPT, CREATE_W_RANDOM}

# Define a type for functions that take an ActionID and return a boolean
ActionFunction = Callable[[ActData], ActData]

# Dictionary mapping action identifiers to their corresponding file
# handling functions. This dictionary includes actions that interact
# with files and the user.
FILE_ACTION_MAP: Final[dict[ActionID, ActionFunction]] = {
    ENCRYPT: encrypt_and_embed,
    DECRYPT: encrypt_and_embed,
    EMBED: embed,
    EXTRACT: embed,
    ENCRYPT_EMBED: encrypt_and_embed,
    EXTRACT_DECRYPT: encrypt_and_embed,
    CREATE_W_RANDOM: create_with_random,
    OVERWRITE_W_RANDOM: overwrite_with_random,
}

# Dictionary mapping user input to actions/descriptions
ACTIONS: Final[dict[str, tuple[ActionID, str]]] = {
    '0': (EXIT, """action 0:
        exit application"""),
    '1': (INFO, """action 1:
        display info and warnings"""),
    '2': (ENCRYPT, """action 2:
        encrypt file contents and comments;
        write cryptoblob to new file"""),
    '3': (DECRYPT, """action 3:
        decrypt file; display decrypted comments
        and write decrypted contents to new file"""),
    '4': (EMBED, """action 4:
        embed file contents:
        write input file contents over output file contents"""),
    '5': (EXTRACT, """action 5:
        extract file contents (no decryption) to new file"""),
    '6': (ENCRYPT_EMBED, """action 6:
        encrypt file contents and comments;
        write cryptoblob over container"""),
    '7': (EXTRACT_DECRYPT, """action 7:
        extract and decrypt cryptoblob;
        display decrypted comments and
        write decrypted contents to new file"""),
    '8': (CREATE_W_RANDOM, """action 8:
        create file of specified size with random data"""),
    '9': (OVERWRITE_W_RANDOM, """action 9:
        overwrite file contents with random data"""),
}

# Size constants for data representation
KIB: Final[int] = 2 ** 10
MIB: Final[int] = 2 ** 20
GIB: Final[int] = 2 ** 30
TIB: Final[int] = 2 ** 40
PIB: Final[int] = 2 ** 50
EIB: Final[int] = 2 ** 60

# Valid answers for boolean queries, representing both true and false options
VALID_BOOL_ANSWERS: Final[str] = 'Y, y, 1, N, n, 0'

# Sets representing true and false boolean answers,
# including default false options
TRUE_ANSWERS: Final[set[str]] = {'Y', 'y', '1'}
FALSE_ANSWERS: Final[set[str]] = {'N', 'n', '0'}
DEFAULT_FALSE_ANSWERS: Final[set[str]] = {'', 'N', 'n', '0'}

# Constants for proceed_request() function
PROCEED_OVERWRITE: Final[bool] = True
PROCEED_REMOVE: Final[bool] = False

# Size in bytes for processed comments;
# comments are padded or truncated to this size
PROCESSED_COMMENTS_SIZE: Final[int] = KIB

# Invalid UTF-8 byte constant that separates comments from random data
# (UTF-8 strings cannot contain the byte 0xFF)
COMMENTS_SEPARATOR: Final[bytes] = b'\xff'

# Minimum interval for progress updates
MIN_PROGRESS_INTERVAL: Final[float] = 5

# Byte order for data representation
BYTEORDER: Final[Literal['big', 'little']] = 'little'

# Unicode normalization form for passphrases
UNICODE_NF: Final[Literal['NFC', 'NFD', 'NFKC', 'NFKD']] = 'NFC'

# Normalized and encoded passphrases will be truncated to this value
PASSPHRASE_SIZE_LIMIT: Final[int] = 2 * KIB  # 2048 B

# Maximum size limit for random output file
RAND_OUT_FILE_SIZE_LIMIT: Final[int] = 2 ** 64  # 16 EiB

# Salt size for cryptographic operations
SALT_SIZE: Final[int] = 16

# ChaCha20 constants
ENC_KEY_SIZE: Final[int] = 32  # 256-bit key size
NONCE_SIZE: Final[int] = 12  # 96-bit nonce size
BLOCK_COUNTER_INIT_BYTES: Final[bytes] = \
    bytes(4)  # 32-bit block counter initialized to zero

# Chunk size for reading and writing data during encryption and
# decryption operations. This is the maximum chunk size for any
# read and write operations. Changing this value breaks backward
# compatibility, as it defines the size of the data that can be
# encrypted with a single nonce.
MAX_PT_CHUNK_SIZE: Final[int] = 16 * MIB

# BLAKE2 constants
PERSON_SIZE: Final[int] = 16
PERSON_KEYFILE: Final[bytes] = \
    b'K' * PERSON_SIZE  # 0x4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b
PERSON_PASSPHRASE: Final[bytes] = \
    b'P' * PERSON_SIZE  # 0x50505050505050505050505050505050
IKM_DIGEST_SIZE: Final[int] = 32
MAC_KEY_SIZE: Final[int] = 32
MAC_TAG_SIZE: Final[int] = 32
CHECKSUM_SIZE: Final[int] = 32

# Used to calculate payload file contents size during decryption
MAX_CT_CHUNK_SIZE: Final[int] = MAX_PT_CHUNK_SIZE + MAC_TAG_SIZE

# HKDF info labels (public, stable identifiers used as HKDF info)
# Used to derive specific keys
HKDF_INFO_ENCRYPT: Final[bytes] = b'ENCRYPT'
HKDF_INFO_MAC: Final[bytes] = b'MAC'
HKDF_INFO_PAD: Final[bytes] = b'PAD'

# Defines the byte size of the byte string that specifies
# the length of the data being passed to the MAC function.
SIZE_BYTES_SIZE: Final[int] = 8  # Supports sizes up to 2^64-1

# Padding constants
PAD_KEY_SIZE: Final[int] = 8
PAD_KEY_SPACE: Final[int] = 256 ** PAD_KEY_SIZE
MAX_PAD_SIZE_PERCENT: Final[int] = 25

# Argon2 constants
ARGON2_TAG_SIZE: Final[int] = 32
ARGON2_MEMORY_COST: Final[int] = GIB
DEFAULT_ARGON2_TIME_COST: Final[int] = 4
MIN_ARGON2_TIME_COST: Final[int] = DEFAULT_ARGON2_TIME_COST

# Minimum valid cryptoblob size
MIN_VALID_UNPADDED_SIZE: Final[int] = \
    SALT_SIZE * 2 + PAD_KEY_SIZE + PROCESSED_COMMENTS_SIZE + MAC_TAG_SIZE * 2

# Maximum valid cryptoblob size
MAX_VALID_PADDED_SIZE: Final[int] = 256 ** SIZE_BYTES_SIZE - 1

# Flag set by signal handler when a termination signal is received;
# main thread must check it and perform cleanup.
termination_signal_received: bool = False

# File object to truncate on signal termination, or None if not set
file_obj_to_truncate_by_signal: Optional[BinaryIO] = None


# Start the application
# --------------------------------------------------------------------------- #


# Adjust ANSI codes for Windows platform, which does not support them
if platform == 'win32':
    just_fix_windows_console()


CLI_VALUES: Final[tuple[bool, bool]] = cli_handler()
UNSAFE_DEBUG: Final[bool] = CLI_VALUES[0]
UNSAFE_DECRYPT: Final[bool] = CLI_VALUES[1]


if __name__ == '__main__':
    main()
