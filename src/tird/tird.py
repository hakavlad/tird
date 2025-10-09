#!/usr/bin/env python3
"""
tird /tɪrd/ (an acronym for "this is random data")

A tool for encrypting files and hiding encrypted data.

Requirements:
- Python >= 3.9.2

Dependencies:
- cryptography >= 2.1 (ChaCha20, HKDF-SHA-256)
- PyNaCl >= 1.2.0 (Argon2id, BLAKE2b)
- colorama >= 0.4.6 (Windows-specific)

SPDX-License-Identifier: 0BSD

Homepage: https://github.com/hakavlad/tird
"""

# pylint: disable=invalid-name
# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-lines
# pylint: disable=too-many-locals
# pylint: disable=too-many-positional-arguments
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-statements

from collections.abc import Callable
from gc import collect
from getpass import getpass
from os import (SEEK_CUR, SEEK_END, SEEK_SET, _exit, chmod, fsync, ftruncate,
                path, remove, walk, write)

try:
    from resource import RLIMIT_CORE, setrlimit
    RESOURCE_MODULE_AVAILABLE: bool = True
except ModuleNotFoundError:
    RESOURCE_MODULE_AVAILABLE = False

from io import BytesIO
from secrets import compare_digest, token_bytes
from sys import argv, exit, platform, version
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
    from signal import SIGINT, SIGTERM, signal

    from colorama import just_fix_windows_console
else:
    from signal import SIGHUP, SIGINT, SIGQUIT, SIGTERM, signal


# Define a type alias for action identifiers
ActionID = Literal[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]


class KeyfileScanError(Exception):
    """Exception raised by keyfile directory scanning errors."""


class EE:
    """
    Class for transferring variable values
    from encrypt_and_embed_input()
    to encrypt_and_embed_handler().
    """
    in_file_size: int

    pad_ikm: Optional[bytes]
    unpadded_size: Optional[int]
    padded_size: int

    processed_comments: Optional[bytes]

    start_pos: Optional[int]
    end_pos: Optional[int]


# ANSI escape codes for terminal text formatting
BOL: Final[str] = '\x1b[1m'  # Bold text
ERR: Final[str] = '\x1b[1;97;101m'  # Bold white text, red background
WAR: Final[str] = '\x1b[1;93;40m'  # Bold yellow text, black background
RES: Final[str] = '\x1b[0m'  # Reset formatting to default

# Adjust ANSI codes for Windows platform, which does not support them
if platform == 'win32':
    just_fix_windows_console()


# Formatting output messages and logging
# --------------------------------------------------------------------------- #


def log_e(error_message: str) -> None:
    """Logs a message at the Error level."""
    print(f'    {ERR}E: {error_message}{RES}')


def log_w(warning_message: str) -> None:
    """Logs a message at the Warning level."""
    print(f'    {WAR}W: {warning_message}{RES}')


def log_i(info_message: str) -> None:
    """Logs a message at the Info level."""
    print(f'    I: {info_message}')


def log_d(debug_message: str) -> None:
    """Logs a message at the Debug level."""
    print(f'    D: {debug_message}')


def format_size(size: int) -> str:
    """
    Converts a size in bytes to a human-readable string representation.

    This function takes an integer representing a size in bytes and
    converts it into a more readable format, displaying the size in
    bytes along with its equivalent in EiB, PiB, TiB, GiB, MiB, or KiB,
    depending on the size. The converted sizes are rounded to one
    decimal place for clarity.

    Args:
        size (int): The size in bytes to be converted.

    Returns:
        str: A string representation of the size, including the original
             size in bytes and its equivalent in EiB, PiB, TiB, GiB,
             MiB, or KiB, as appropriate.
    """
    formatted_size: str

    if size >= E:
        formatted_size = f'{size:,} B ({round(size / E, 1)} EiB)'
    elif size >= P:
        formatted_size = f'{size:,} B ({round(size / P, 1)} PiB)'
    elif size >= T:
        formatted_size = f'{size:,} B ({round(size / T, 1)} TiB)'
    elif size >= G:
        formatted_size = f'{size:,} B ({round(size / G, 1)} GiB)'
    elif size >= M:
        formatted_size = f'{size:,} B ({round(size / M, 1)} MiB)'
    elif size >= K:
        formatted_size = f'{size:,} B ({round(size / K, 1)} KiB)'
    else:
        formatted_size = f'{size:,} B'

    return formatted_size


def short_format_size(size: int) -> str:
    """
    Converts a size in bytes to a human-readable string representation.

    This function takes an integer representing a size in bytes and
    converts it into a more readable format, displaying the size in
    the appropriate unit (EiB, PiB, TiB, GiB, MiB, or KiB) depending on
    the size. If the size is less than 1 KiB, it will be displayed in
    bytes. The converted sizes are rounded to one decimal place for
    clarity.

    Args:
        size (int): The size in bytes to be converted.

    Returns:
        str: A string representation of the size, including its
             equivalent in EiB, PiB, TiB, GiB, MiB, or KiB, as
             appropriate. If the size is less than 1 KiB, it will be
             displayed in bytes.
    """
    formatted_size: str

    if size >= E:
        formatted_size = f'{round(size / E, 1)} EiB'
    elif size >= P:
        formatted_size = f'{round(size / P, 1)} PiB'
    elif size >= T:
        formatted_size = f'{round(size / T, 1)} TiB'
    elif size >= G:
        formatted_size = f'{round(size / G, 1)} GiB'
    elif size >= M:
        formatted_size = f'{round(size / M, 1)} MiB'
    elif size >= K:
        formatted_size = f'{round(size / K, 1)} KiB'
    else:
        formatted_size = f'{size:,} B'

    return formatted_size


def format_time(total_s: float) -> str:
    """
    Formats a given time in seconds into a more readable string format.

    The output format will be:
    - For less than 60 seconds: "Xs" (where X is seconds)
    - For less than 3600 seconds (1 hour): "Xs (Ym Zs)" (where Y is
      minutes and Z is seconds)
    - For 1 hour or more: "Xs (Ah Bm Cs)" (where A is hours, B is
      minutes, and C is seconds)

    Args:
        total_s (float): The time in seconds to be formatted.

    Returns:
        str: A string representing the time in seconds, along with its
             equivalent in minutes and seconds, or hours, minutes, and
             seconds, depending on the total duration. The seconds in
             the output are rounded to one decimal place.
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


def log_progress() -> None:
    """
    Logs the progress of a data writing operation.

    This function calculates and logs the percentage of completion, the
    amount of data written, the elapsed time since the start of the
    operation, and the average writing speed in MiB/s. The total data
    size and the current written amount are now obtained from a global
    dictionary, where INT_D['total_out_data_size'] represents the total
    size of the data to be written and INT_D['written_sum'] the total
    data written so far.

    Returns:
        None

    Note:
        This function relies on global variables FLOAT_D and INT_D.
        FLOAT_D['start_time'] is the start time of the operation,
        INT_D['written_sum'] is the total amount of data written so far,
        and INT_D['total_out_data_size'] is the total size of the data
        to be written. If INT_D['total_out_data_size'] is zero, a
        message indicating that 0 bytes have been written will be logged
        to avoid division by zero.
    """

    # Check if the total data size is zero to avoid division by zero
    if not INT_D['total_out_data_size']:
        log_i('written 0 B')
        return

    # Calculate the elapsed time since the start of the operation
    elapsed_time: float = monotonic() - FLOAT_D['start_time']

    # Calculate the percentage of data written
    percentage: float = \
        INT_D['written_sum'] / INT_D['total_out_data_size'] * 100

    # Format the amount of data written for logging
    formatted_written: str = short_format_size(INT_D['written_sum'])

    if not elapsed_time:
        # Log progress without average speed if elapsed time is zero
        log_i(f'written {round(percentage, 1)}%; '
              f'{formatted_written} in 0.0s')
        return

    # Calculate the average writing speed in MiB/s
    average_speed: float = round(INT_D['written_sum'] / M / elapsed_time, 1)

    # Log the detailed progress information
    log_i(f'written {round(percentage, 1)}%; '
          f'{formatted_written} in {format_time(elapsed_time)}; '
          f'avg {average_speed:,} MiB/s')


def log_progress_if_time_elapsed() -> None:
    """
    Logs the progress of an operation if the specified time interval has
    passed.

    This function checks the elapsed time since the last progress log.
    If the time since the last log exceeds the defined minimum progress
    interval (MIN_PROGRESS_INTERVAL), it logs the current progress. Note
    that the total data size and progress information are obtained from
    global dictionaries, so there is no function parameter for
    total_data_size.

    Returns:
        None
    """

    # Check if the minimum progress interval has passed since the last log
    if monotonic() - FLOAT_D['last_progress_time'] >= MIN_PROGRESS_INTERVAL:

        # Log the current progress based on the total data size
        log_progress()

        # Update the last progress log time to the current time
        FLOAT_D['last_progress_time'] = monotonic()


def log_progress_final() -> None:
    """
    Logs the final progress of the writing operation.

    This function logs the total progress of the data writing operation
    by first invoking log_progress() to log the latest progress details
    and then logging a final message indicating that the writing has
    completed and the total amount of data written (obtained from the
    global dictionary) in bytes.

    Returns:
        None
    """
    log_progress()

    log_i(f'writing completed; total of {INT_D["written_sum"]:,} B written')


# Handle files and paths
# --------------------------------------------------------------------------- #


def open_file(
    file_path: str,
    access_mode: Literal['rb', 'rb+', 'xb'],
) -> Optional[BinaryIO]:
    """
    Opens a file in the specified mode and returns the file object.
    Handles exceptions related to file operations.

    Args:
        file_path (str): The path to the file.
        access_mode (Literal['rb', 'rb+', 'xb']): The mode in which to
                                                  open the file.

    Returns:
        Optional[BinaryIO]: The file object if successful, or None if an
                            error occurs.

    Exceptions handled:
        - FileNotFoundError: Raised when trying to read a file that does
          not exist.
        - PermissionError: Raised when the user does not have the
          appropriate permissions.
        - FileExistsError (subclass of OSError): Raised in exclusive
          creation mode ('xb') if the file already exists.
        - OSError: Handles other OS-related errors.
    """
    check_for_signal()  # Check if a termination signal has been received

    if DEBUG:
        log_d(f'opening file {file_path!r} in mode {access_mode!r}')

    try:
        file_obj: BinaryIO = open(file_path, access_mode)
        if DEBUG:
            log_d(f'opened file object: {file_obj}')
        return file_obj
    except (
        FileNotFoundError, PermissionError, FileExistsError, OSError
    ) as error:
        log_e(f'{error}')
        return None


def close_file(file_obj: BinaryIO) -> None:
    """
    The function attempts to close the provided file object. If the
    DEBUG flag is set, it logs before and after the close operation. If,
    after calling .close(), file_obj.closed remains False, then an error
    is logged.

    Args:
        file_obj (BinaryIO): The file object to close.

    Returns:
        None
    """
    check_for_signal()  # Check if a termination signal has been received

    if not file_obj.closed:
        if DEBUG:
            log_d(f'closing {file_obj}')

        try:
            file_obj.close()
        except OSError as error:
            log_e(f'{error}')

        if file_obj.closed:
            if DEBUG:
                log_d(f'{file_obj} closed')
        else:
            log_e(f'file descriptor of {file_obj} NOT closed')
    else:
        if DEBUG:
            log_d(f'{file_obj} is already closed')


def get_file_size(file_path: str) -> Optional[int]:
    """
    Retrieve the size of a file or block device in bytes.

    This function opens a file in binary read mode, seeks to the end,
    and returns the position as the size. Unlike os.path.getsize(), it
    works with block devices (e.g., /dev/sda) on Unix systems.

    Args:
        file_path (str): Path to the file or block device.

    Returns:
        Optional[int]: File size in bytes if successful, None on error
                       (e.g., permission denied, seek failure).

    Example:
        >>> get_file_size("/dev/sda")  # Size of a block device
        500107862016
        >>> get_file_size("normal_file.txt")
        1024
    """
    try:
        with open(file_path, 'rb') as file_obj:
            # Move to the end of the file
            file_size: int = file_obj.seek(0, SEEK_END)
            return file_size
    except (FileNotFoundError, PermissionError, OSError) as error:
        log_e(f'{error}')
        return None


def seek_position(
    file_obj: BinaryIO,
    offset: int,
    whence: int = SEEK_SET,
) -> bool:
    """
    Moves the file pointer to a specified position in a file.

    This function seeks to a new position in the file based on the
    provided offset and whence parameters. It returns True if the
    operation is successful, or False if an error occurs during the seek
    operation.

    Args:
        file_obj (BinaryIO): The file object to seek within. It must be
            opened in a mode that allows seeking.
        offset (int): The number of bytes to move the file pointer from
            the position specified by whence.
        whence (int): The reference point for the offset. It must be one
            of the following:
            - SEEK_SET: Beginning of the file (default)
            - SEEK_CUR: Current file position

    Returns:
        bool: True if the seek operation was successful,
              False otherwise.
    """
    if DEBUG:
        current_pos: int = file_obj.tell()

        if whence == SEEK_SET:
            log_d(f'moving from position {current_pos:,} '
                  f'to position {offset:,} in {file_obj}')

        elif whence == SEEK_CUR:
            next_pos: int = current_pos + offset
            log_d(f'moving from position {current_pos:,} '
                  f'to position {next_pos:,} in {file_obj}')

    try:
        file_obj.seek(offset, whence)
        return True
    except OSError as error:
        log_e(f'{error}')
        return False


def read_data(file_obj: BinaryIO, data_size: int) -> Optional[bytes]:
    """
    Reads exactly `data_size` bytes from a file object.

    This function performs a strict read operation: it either reads the
    exact     requested number of bytes or returns None
    (unlike file_obj.read() which may return fewer bytes). Useful for
    cryptographic operations where partial reads are unacceptable.

    Args:
        file_obj (BinaryIO): File object opened in binary mode (must
                             support read() and seek/tell operations if
                             DEBUG is enabled).
        data_size (int): Exact number of bytes to read. Must be
                         non-negative.

    Returns:
        Optional[bytes]: Bytes read (exactly `data_size` bytes) if
                         successful, None if:
                         - EOF reached before reading `data_size` bytes.
                         - I/O error occurred.
                         - DEBUG enabled and seek position changed
                           unexpectedly.
    """
    check_for_signal()  # Check if a termination signal has been received

    if DEBUG:
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

    if DEBUG:
        end_pos: int = file_obj.tell()
        log_d(f'read {format_size(end_pos - start_pos)} from {file_obj}; '
              f'position moved from {start_pos:,} to {end_pos:,}')

    return data


def write_data(data: bytes) -> bool:
    """
    Writes binary data to the global output file (BIO_D['OUT']) with
    error handling.

    This function performs a single atomic write operation to the
    pre-opened output file stored in the global BIO_D dictionary. It is
    designed for reliability in cryptographic operations where partial
    writes must be avoided. The function also updates the cumulative
    written data sum and logs overall progress based on the total
    progress of the writing operation.

    Args:
        data (bytes): Binary data to write.

    Returns:
        bool: True if all bytes were successfully written, False if:
              - An OS-level write error occurred (e.g., disk full,
                permission denied, etc.).
              - The file object is not properly initialized in
                BIO_D['OUT'].
              - DEBUG enabled and position tracking fails.

    Side Effects:
        - Advances the file position by len(data) bytes on success.
        - Updates INT_D['written_sum'] to keep track of the cumulative
          number of bytes written.
        - Logs the current progress of the writing operation via
          log_progress_if_time_elapsed().
        - In DEBUG mode, logs the file position before and after the
          write for position validation.

    Notes:
        - For proper error recovery, the caller should close or remove
          the output file if False is returned.
        - Does NOT perform fsync() - use fsync_written_data() for
          persistence guarantees.
        - DEBUG mode adds position validation but doesn't affect write
          atomicity.
    """
    check_for_signal()  # Check if a termination signal has been received

    file_obj: BinaryIO = BIO_D['OUT']

    if DEBUG:
        start_pos: int = file_obj.tell()

    try:
        file_obj.write(data)
    except OSError as error:
        log_e(f'{error}')
        return False

    if DEBUG:
        end_pos: int = file_obj.tell()
        log_d(f'written {format_size(end_pos - start_pos)} to {file_obj}; '
              f'position moved from {start_pos:,} to {end_pos:,}')

    INT_D['written_sum'] += len(data)

    log_progress_if_time_elapsed()

    return True


def fsync_written_data() -> bool:
    """
    Flushes the global output file buffer and synchronizes to disk.

    Flushes the output buffer of the file associated with the global
    `BIO_D['OUT']` and synchronizes its state to disk using the `fsync`
    method.

    Returns:
        bool: True if flushed and synchronized successfully,
              False otherwise.
    """
    check_for_signal()  # Check if a termination signal has been received

    try:
        # Get the output file object from the global `BIO_D` dictionary
        file_obj: BinaryIO = BIO_D['OUT']

        # Flush the output buffer
        file_obj.flush()

        # Synchronize the file to disk
        fsync(file_obj.fileno())
    except OSError as error:
        log_e(f'{error}')
        return False

    if DEBUG:
        log_d(f'fsynced {file_obj}')

    return True


def truncate_output_file() -> None:
    """
    Truncate the output file to zero bytes and clear the active
    file-handler flag.

    Preconditions

    BIO_D['OUT'] contains a valid file-like object implementing
    BinaryIO with fileno().

    Behavior

    - Flushes the file object and calls ftruncate() on its file
      descriptor to set its length to 0 bytes.
    - Does not close the file; closing must be done separately by the
      caller.
    - Logs success with log_i(...) or errors with log_e(...).

    Side effects

    - Removes the 'file_handler_started' key from ANY_D if present,
      indicating no file write is currently in progress.

    Notes

    - Designed for use outside of signal handlers (performs
      non-signal-safe operations).
    - Any exceptions during flush or ftruncate are caught and logged;
      the function does not re-raise them.
    """
    out_file_obj: BinaryIO = BIO_D['OUT']

    if DEBUG:
        log_d('truncating output file')

    try:
        out_file_obj.flush()
        ftruncate(out_file_obj.fileno(), 0)
        log_i('output file truncated to 0')
    except Exception as truncate_error:
        log_e(f'cannot truncate output file: {truncate_error}')

    if 'file_handler_started' in ANY_D:
        del ANY_D['file_handler_started']


def remove_output_path(action: ActionID) -> None:
    """
    Remove the output file on disk after closing the file object and
    obtaining explicit user confirmation.

    Behavior:
      - Close the global output file object stored at BIO_D['OUT'].
      - Prompt the user (via proceed_request) to confirm removal.
      - If confirmed, attempt to remove the file at the closed file
        object's path and log success or failure.
      - If not confirmed, leave the file in place and log that no
        removal occurred.

    Args:
        action (ActionID): Action identifier used for logging and passed
                           to the confirmation prompt.

    Returns:
        None

    Notes:
      - The function always attempts to close BIO_D['OUT'] before
        prompting.
      - Removal errors are caught and logged; they do not raise out of
        this function.
      - Logging is performed for debug, info, and error conditions.
    """
    out_file_obj: BinaryIO = BIO_D['OUT']

    out_file_name: str = out_file_obj.name

    close_file(BIO_D['OUT'])

    if proceed_request(PROCEED_REMOVE, action):
        if DEBUG:
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
    Prompts the user for input until a valid response is received.
    If an EOFError is encountered, it logs the error and prompts again.

    Args:
        prompt (str): The message to display to the user.

    Returns:
        str: The user input.
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
    Prompts the user for a passphrase input until a valid response is
    received. If an EOFError is encountered, it logs the error and
    prompts again.

    Args:
        prompt (str): The message to display to the user when asking for
                      the passphrase.

    Returns:
        str: The user input (passphrase).
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
    Prompts the user to select an action from a predefined menu.

    Displays a menu of available actions and their descriptions, as
    defined in the global ACTIONS dictionary. The function uses a loop
    to continuously ask for input until a valid response is given. If
    the user enters an invalid value, an error message is displayed and
    the user is prompted again.

    Returns:
        ActionID: The selected action number (0-9), which corresponds to
                  a valid action in the ACTIONS dictionary.
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
    Prompts the user for an input file based on the specified action.

    Determines the type of input file required based on the provided
    action, using global formatting variables. Prompts the user to enter
    the file path, validates the input, and returns the file path, its
    size, and the file object.

    Args:
        action (ActionID): Action determining the type of input file.

    Returns:
        tuple: Input file path, size, and file object.
    """

    # Dictionary mapping actions to corresponding prompt messages
    action_prompts: dict[ActionID, str] = {
        ENCRYPT: 'File to encrypt (opt)',
        DECRYPT: 'File to decrypt',
        EMBED: 'File to embed',
        EXTRACT: 'Container',
        ENCRYPT_EMBED: 'File to encrypt and embed (opt)',
        EXTRACT_DECRYPT: 'Container',
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

        # Log the real path if in DEBUG mode
        if DEBUG:
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
    Prompts the user for comments and returns the input.

    Returns:
        str: The comments entered by the user. May be an empty string.
    """
    return no_eof_input(
        f"{BOL}D2. Comments (default='{basename}'):{RES} ")


def get_output_file_new(action: ActionID) -> tuple[str, BinaryIO]:
    """
    Prompts the user for a new output file path and creates the file.

    Determines the prompt based on the provided action, using global
    formatting variables. Prompts the user to enter the file path,
    validates the input, creates the file in exclusive-creation mode,
    and sets restrictive file permissions for actions ENCRYPT and
    CREATE_W_RANDOM. Failure to change permissions is logged but
    does not cause the function to fail.

    Args:
        action (ActionID): Action being performed (ENCRYPT, DECRYPT,
                           EXTRACT, EXTRACT_DECRYPT, or CREATE_W_RANDOM).

    Returns:
        tuple: (output file path, file object).
    """

    # Determine the prompt message based on the action provided
    if action == ENCRYPT:
        prompt_message: str = 'Output (encrypted) file'
    elif action in (DECRYPT, EXTRACT_DECRYPT):
        prompt_message = 'Output (decrypted) file'
    else:  # For actions EXTRACT and CREATE_W_RANDOM
        prompt_message = 'Output file'

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

            # Log the real path if in DEBUG mode
            if DEBUG:
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
    Prompts the user for an existing output file path and ensures
    it meets criteria.

    Determines the prompt based on the provided action, using global
    formatting variables. Prompts the user to enter the file path,
    validates the input, and returns the file path, its size, and the
    file object.

    Args:
        in_file_path (str): Input file path.
        min_out_size (int): Minimum required output file size in bytes.
        action (ActionID): Action type.

    Returns:
        tuple: Output file path, size, and file object.
    """

    # Determine the prompt message based on the action provided
    if action in (EMBED, ENCRYPT_EMBED):
        prompt_message: str = 'File to overwrite (container)'
    else:  # For action OVERWRITE_W_RANDOM
        prompt_message = 'File to overwrite'

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

        # Log the real path if in DEBUG mode
        if DEBUG:
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
    Prompts the user to enter the desired output file size in bytes and
    returns the value as an integer.

    The function repeatedly prompts the user until a valid input is
    provided. A valid input is defined as a non-empty string that can be
    converted to a non-negative integer within the valid range. If the
    user enters an empty string, a negative value, a non-integer value,
    or a value that exceeds the upper limit, the function logs an error
    message and prompts the user again. The valid range for the output
    file size is from 0 to RAND_OUT_FILE_SIZE_LIMIT (inclusive).

    Returns:
        int: The output file size in bytes, as a non-negative integer
        within the range [0; RAND_OUT_FILE_SIZE_LIMIT].
    """
    prompt_message: str = f'{BOL}D4. Output file size in bytes:{RES} '

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
    Prompts the user for a start position within a specified range.

    Repeatedly asks the user for a start position until a valid integer
    within the range [0; max_start_pos] is provided, using global
    formatting variables. If no_default is False, the user can leave the
    input blank to use a default value of 0. The valid range for the
    start position is from 0 to max_start_pos.

    Args:
        max_start_pos (int): Maximum valid start position.
        no_default (bool): If True, the user must provide a start
                           position.

    Returns:
        int: A valid start position within the specified range.
    """
    prompt_message_no_default: str = \
        f'{BOL}D5. Start position [0; {max_start_pos}]:{RES} '

    prompt_message_default: str = \
        f'{BOL}D5. Start position [0; {max_start_pos}], default=0:{RES} '

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
    Prompts the user for an end position within a specified range.

    Repeatedly asks the user for an end position until a valid integer
    within the range [min_pos; max_pos] is provided, using global
    formatting variables. If no_default is False, the user can leave the
    input blank to use a default value of max_pos. The valid range for
    the end position is from min_pos to max_pos.

    Args:
        min_pos (int): Minimum valid end position.
        max_pos (int): Maximum valid end position.
        no_default (bool): If True, the user must provide an end
                           position.

    Returns:
        int: A valid end position within the specified range.
    """
    prompt_message_no_default: str = f'{BOL}D6. End position [{min_pos}; ' \
        f'{max_pos}]:{RES} '

    prompt_message_default: str = f'{BOL}D6. End position [{min_pos}; ' \
        f'{max_pos}], default={max_pos}:{RES} '

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


def collect_and_handle_ikm(action: ActionID) -> list[bytes]:
    """
    Collects input keying material (keyfiles and passphrases) and
    returns a list of their digests.

    Asks the user to input paths to keyfiles and optional passphrases,
    using global formatting variables. Validates the existence of the
    keyfiles and computes their digests. The user can enter multiple
    keyfiles and passphrases, and the function will return a list
    containing the digests of all accepted keyfiles and passphrases.

    Keyfile paths can be individual files or directories. If a directory
    is provided, the function will attempt to gather all valid keyfiles
    within that directory. If a passphrase is entered, the user must
    confirm it by entering it again.

    If it is impossible to handle at least one file from the directory,
    then all files from the specified keyfile path are ignored.

    Passphrase handling involves the following steps:
    1. The user is prompted to enter a passphrase. This input is
       optional.
    2. If a passphrase is provided, the user is required to confirm it
       by entering it a second time.
    3. Both the original and confirmed passphrases are normalized,
       encoded, and truncated as necessary to ensure consistency and
       security.
    4. The function compares the two passphrases using a secure
       comparison method to prevent timing attacks.
    5. If the passphrases match, a digest of the passphrase is computed
       and added to the list of digests. If they do not match, an error
       message is logged, and the passphrase is not accepted.

    Args:
        action (ActionID): The action identifier that determines the
                           context in which the keying material is being
                           collected.

    Returns:
        list: A list of digests (bytes) corresponding to the accepted
              keyfiles and passphrases. The list may be empty if no
              valid keyfiles or passphrases were provided.
    """
    if DEBUG:
        log_d('collecting IKM')

    # List to store the digests of keying material
    ikm_digest_list: list[bytes] = []

    # Handle keyfile paths
    # ----------------------------------------------------------------------- #

    while True:
        # Prompt for the keyfile path
        keyfile_path: str = \
            no_eof_input(f'{BOL}K1. Keyfile path (opt):{RES} ')

        if not keyfile_path:
            break  # Exit the loop if the user does not enter a path

        if not path.exists(keyfile_path):
            # Log error if the keyfile path does not exist
            log_e(f'file {keyfile_path!r} not found')
            log_e('keyfile NOT accepted')
            continue

        if DEBUG:
            log_d(f'real path: {path.realpath(keyfile_path)!r}')

        # Handle existing path (directory or individual file)
        # ------------------------------------------------------------------- #

        if path.isdir(keyfile_path):
            # If the path is a directory, get the digests of all keyfiles
            # within it
            digest_list: Optional[list[bytes]] = \
                get_keyfile_digest_list(keyfile_path)

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
            file_digest: Optional[bytes] = get_keyfile_digest(keyfile_path)

            if file_digest is None:
                log_e('keyfile NOT accepted')
            else:
                # Add the file digest to the list
                ikm_digest_list.append(file_digest)
                log_i('keyfile accepted')
            continue

    # Handle passphrases
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_w('entered passphrases will be displayed!')

    while True:
        raw_passphrase_1: str = \
            no_eof_getpass(f'{BOL}K2. Passphrase (opt):{RES} ')

        if not raw_passphrase_1:
            break  # Exit the loop if the user does not enter a passphrase

        # Normalize, encode, truncate
        encoded_passphrase_1: bytes = handle_raw_passphrase(raw_passphrase_1)

        # Prompt for confirming the passphrase
        raw_passphrase_2: str = \
            no_eof_getpass(f'{BOL}K2. Confirm passphrase:{RES} ')

        encoded_passphrase_2: bytes = handle_raw_passphrase(raw_passphrase_2)

        if compare_digest(encoded_passphrase_1, encoded_passphrase_2):
            passphrase_digest: bytes = \
                get_passphrase_digest(encoded_passphrase_1)

            ikm_digest_list.append(passphrase_digest)

            log_i('passphrase accepted')

            break

        log_e('passphrase NOT accepted: confirmation failed')

    # Log results
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('collecting IKM completed')

    if DEBUG:
        log_d(f'{len(ikm_digest_list)} IKM digests collected')

    if not ikm_digest_list and action in (ENCRYPT, ENCRYPT_EMBED):
        log_w('no keyfile or passphrase specified!')

    return ikm_digest_list


def get_argon2_time_cost(action: ActionID) -> None:
    """
    Prompt for and validate the Argon2 time cost, then store the result.

    Behavior

    - Prompts the user for an Argon2 "time cost" value using an
      interactive prompt.
    - Accepts an empty input or the textual default as meaning the
      predefined DEFAULT_ARGON2_TIME_COST.
    - Validates that the entered value is an integer within the
      inclusive range [MIN_ARGON2_TIME_COST, argon2id.OPSLIMIT_MAX]. On
      invalid input, prints an error and reprompts.
    - Logs the chosen time cost (info). If the current action is an
      encryption action and the user selected a non-default value, logs
      a warning that decryption will require the same value.
    - Stores the final integer in INT_D['argon2_time_cost'].

    Args:
        action (ActionID): the current action; used to determine whether
                           to warn about non-default values during
                           encryption.

    Side effects

    - Interacts with the user via no_eof_input().
    - Calls logging helpers: log_i, log_w, log_e.
    - Writes the accepted integer into INT_D['argon2_time_cost'].

    Returns:
        None
    """
    prompt_message: str = \
        f'{BOL}K3. Time cost (default={DEFAULT_ARGON2_TIME_COST}):{RES} '

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
        log_w('decryption will require the same "Time cost" value!')

    INT_D['argon2_time_cost'] = time_cost


def proceed_request(proceed_type: bool, action: ActionID) -> bool:
    """
    Prompts the user to confirm whether to proceed with an action.

    The prompt message and default behavior depend on the value of the
    `proceed_type` parameter:
    - If `proceed_type` is PROCEED_OVERWRITE, the prompt warns that the
      output file contents will be partially overwritten, and the
      default is to not proceed.
    - If `proceed_type` is PROCEED_REMOVE, the prompt informs that the
      next step is to remove the output file path, and the default is to
      proceed.

    Args:
        proceed_type (bool): An boolean value that determines the prompt
                             message and default behavior.
        action (ActionID): The action identifier that triggered the
                           confirmation request. This may affect the
                           prompt message and logging.

    Returns:
        bool: True if the user confirms to proceed, False otherwise.
    """

    # Check the action type to determine the appropriate prompt message
    if proceed_type is PROCEED_OVERWRITE:
        if action == ENCRYPT_EMBED:
            start_pos: int = INT_D['start_pos']
            max_end_pos: int = INT_D['max_end_pos']

            log_w(f'output file will be overwritten from '
                  f'{start_pos} to {max_end_pos}!')
        else:
            log_w('output file will be partially overwritten!')

        prompt_message: str = f'{BOL}P0. Proceed overwriting? (Y/N):{RES} '
    else:
        log_i('removing output file path')

        prompt_message = f'{BOL}P0. Proceed removing? (Y/N, default=Y):{RES} '

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
    action: ActionID
) -> bool:
    """
    Retrieves or generates salts for cryptographic operations based on
    the specified action.

    Depending on the action provided:
      - For actions ENCRYPT and ENCRYPT_EMBED, the function generates
        new salts (using random bytes) for Argon2 and BLAKE2.
      - For actions DECRYPT and EXTRACT_DECRYPT, the function reads
        salts from a cryptoblob. It reads the Argon2 salt from the
        beginning of the cryptoblob, and then reads the BLAKE2 salt from
        near the end. For DECRYPT, the BLAKE2 salt is read starting from
        position (input_size - ONE_SALT_SIZE), while for EXTRACT_DECRYPT,
        it is read starting from position (end_pos - ONE_SALT_SIZE).

    The retrieved or generated salts are stored in the global dictionary
    `BYTES_D`.

    Args:
        input_size (int): The total size of the input data, used to
                          calculate the position to read the BLAKE2 salt
                          when action is DECRYPT.
        end_pos (Optional[int]): The end position in the cryptoblob;
                                 required when the action is
                                 EXTRACT_DECRYPT to calculate the BLAKE2
                                 salt position. It can be None for
                                 actions that generate salts.
        action (ActionID): The action that determines how salts are
                           handled. Actions ENCRYPT and ENCRYPT_EMBED
                           generate new salts, whereas actions DECRYPT
                           and EXTRACT_DECRYPT read the salts from the
                           cryptoblob.

    Returns:
        bool: True if the salts were successfully generated or retrieved,
              False otherwise. A False return indicates a failure in
              reading salts or seeking positions in the cryptoblob.
    """

    # Log the start of getting salts if debugging is enabled
    if DEBUG:
        log_d('getting salts')

    # Check if the action requires generating new salts
    if action in (ENCRYPT, ENCRYPT_EMBED):
        # Generate random salts for Argon2 and BLAKE2 functions
        argon2_salt: bytes = token_bytes(ONE_SALT_SIZE)
        blake2_salt: bytes = token_bytes(ONE_SALT_SIZE)
    else:
        # Read the salts from the cryptoblob for actions DECRYPT and
        # EXTRACT_DECRYPT
        opt_argon2_salt: Optional[bytes]
        opt_blake2_salt: Optional[bytes]

        if DEBUG:
            log_d('reading argon2_salt from start of cryptoblob')

        # Try to read argon2_salt from the cryptoblob
        opt_argon2_salt = read_data(BIO_D['IN'], ONE_SALT_SIZE)

        # Return False if reading argon2_salt fails
        if opt_argon2_salt is None:
            return False

        # Store argon2_salt
        argon2_salt = opt_argon2_salt

        # Log that the argon2_salt has been read if debugging is enabled
        if DEBUG:
            log_d('argon2_salt read')

        # Save the current position in the cryptoblob
        pos_after_argon2_salt: int = BIO_D['IN'].tell()

        # Determine the new position based on the action
        if action == DECRYPT:
            pos_before_blake2_salt: int = input_size - ONE_SALT_SIZE
        else:  # action == EXTRACT_DECRYPT
            if end_pos is None:
                raise TypeError

            pos_before_blake2_salt = end_pos - ONE_SALT_SIZE

        # Move to the position for reading blake2_salt
        if not seek_position(BIO_D['IN'], pos_before_blake2_salt):
            return False

        if DEBUG:
            log_d('reading blake2_salt from end of cryptoblob')

        # Try to read blake2_salt from the cryptoblob
        opt_blake2_salt = read_data(BIO_D['IN'], ONE_SALT_SIZE)

        # Return False if reading blake2_salt fails
        if opt_blake2_salt is None:
            return False

        # Store blake2_salt
        blake2_salt = opt_blake2_salt

        # Log that blake2_salt has been read if debugging is enabled
        if DEBUG:
            log_d('blake2_salt read')

        # Move back to the previously saved position
        if not seek_position(BIO_D['IN'], pos_after_argon2_salt):
            return False

    # Store the generated or retrieved salts in the global `BYTES_D` dictionary
    BYTES_D['argon2_salt'] = argon2_salt
    BYTES_D['blake2_salt'] = blake2_salt

    # Log the salts if debugging is enabled
    if DEBUG:
        log_d(f'salts:\n'
              f'        argon2_salt:  {argon2_salt.hex()}\n'
              f'        blake2_salt:  {blake2_salt.hex()}')
        log_d('getting salts completed')

    return True


def hash_keyfile_contents(
    file_obj: BinaryIO,
    file_size: int,
) -> Optional[bytes]:
    """
    Computes the BLAKE2 digest of the contents of a keyfile.

    This function reads the contents of the provided file object in
    chunks and updates the BLAKE2 hash object with the data read. The
    final digest is returned as a byte string. The file should be opened
    in binary mode. The digest is computed using a specific salt and
    personalization string

    Args:
        file_obj (BinaryIO): A file object to read data from,
                             opened in binary mode.
        file_size (int): The total size of the file in bytes.

    Returns:
        Optional[bytes]: The computed BLAKE2 digest as a byte string,
                         or None if an error occurs during reading.
    """

    # Create a BLAKE2 hash object with the specified digest size,
    # personalization, and salt
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        person=PERSON_KEYFILE,
        salt=BYTES_D['blake2_salt'],
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


def get_keyfile_digest(file_path: str) -> Optional[bytes]:
    """
    Compute and return the digest of a keyfile.

    Reads the file at file_path and returns its cryptographic digest as
    bytes.

    The function:

    - obtains the file size (via get_file_size),
    - opens the file in binary mode (open_file),
    - reads and hashes the contents (hash_keyfile_contents),
    - closes the file (close_file).

    Returns:
        bytes: the digest of the file contents on success.
        None: if the file does not exist, cannot be opened, size cannot
              be determined, or hashing fails.

    Side effects:

    - Logs file path and size (log_i) and debug hex output when DEBUG is
      True.
    - Uses helper functions: get_file_size, open_file,
      hash_keyfile_contents, close_file.

    Notes:

    - The exact hash algorithm and digest length are determined by
      hash_keyfile_contents.
    - This function does not raise on I/O errors; it returns None and
      suppresses/handles errors via the helpers.
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
    file_digest: Optional[bytes] = hash_keyfile_contents(file_obj, file_size)

    # Close the file after reading
    close_file(file_obj)

    # If the digest could not be computed, return None
    if file_digest is None:
        return None

    if DEBUG:
        log_d(f'digest of {file_path!r} contents:'
              f'\n        {file_digest.hex()}')

    return file_digest


def get_keyfile_digest_list(directory_path: str) -> Optional[list[bytes]]:
    """
    Scan a directory for keyfiles and return a list of their digests.

    Traverse directory_path (recursively), collect all regular files,
    and compute a cryptographic digest for each file using
    hash_keyfile_contents(file_obj, size). Returns a list of digest
    bytes in arbitrary order corresponding to the found files.

    Behavior and return values

    - On success returns list[bytes] (possibly empty if no files found).
    - Returns None if an error occurs while traversing the directory,
      opening a file, obtaining a file size, or hashing a file.
    - If a single file fails to be processed, the function aborts and
      returns None.

    Side effects and logging

    - Logs progress and file sizes via log_i and debug output via log_d
      when DEBUG is set.
    - Uses open_file/close_file/get_file_size/hash_keyfile_contents
      helpers.
    - On directory traversal errors, walk() onerror handler logs and
      raises KeyfileScanError.

    Assumptions and notes

    - directory_path should point to an accessible directory; symbolic
      links are followed as per os.walk behavior.
    - The exact hash algorithm and digest length are determined by
      hash_keyfile_contents.
    - This function performs I/O and should be called from a context
      that may block (not from a signal handler).

    Raises / Errors

    Does not raise exceptions for I/O errors; instead propagates failure
    by returning None (KeyfileScanError is caught internally).

    Args:
        directory_path (str): The path to the directory to scan for
                              keyfiles.

    Returns:
        Optional[list]: A list of digests for the keyfiles found in the
                        directory, or None if an error occurs. If no
                        files are found, an empty list is returned.
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
        if DEBUG:
            log_d(f'getting size of {full_file_path!r} '
                  f'(real path: {path.realpath(full_file_path)!r})')

        # Get the size of the current file
        optional_file_size: Optional[int] = get_file_size(full_file_path)

        # If the file size cannot be determined, return None
        if optional_file_size is None:
            return None

        # Store the file size
        file_size: int = optional_file_size

        if DEBUG:
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

        if DEBUG:
            log_d(f'reading and hashing contents of {full_file_path!r}')

        # Open the file for reading in binary mode
        file_obj: Optional[BinaryIO] = open_file(full_file_path, 'rb')

        # If the file cannot be opened, return None
        if file_obj is None:
            return None

        # Compute the digest of the keyfile
        file_digest: Optional[bytes] = \
            hash_keyfile_contents(file_obj, file_size)

        # Close the file after reading
        close_file(file_obj)

        # If the digest could not be computed, return None
        if file_digest is None:
            return None

        if DEBUG:
            log_d(f'digest of {full_file_path!r} contents:\n'
                  f'        {file_digest.hex()}')

        # Add the computed digest to the list
        digest_list.append(file_digest)

    # Return the list of computed digests
    return digest_list


def handle_raw_passphrase(raw_passphrase: str) -> bytes:
    """
    Normalizes, encodes and truncates a raw passphrase to a standardized
    format.

    Processes passphrases consistently for cryptographic use by:
    1. Applying Unicode normalization
    2. UTF-8 encoding
    3. Truncating to PASSPHRASE_SIZE_LIMIT

    Args:
        raw_passphrase (str): Input passphrase string. May contain:
                             - Any Unicode characters
                             - Leading/trailing whitespace (not stripped)
                             - Mixed scripts (e.g., Cyrillic + Latin)

    Returns:
        bytes: Normalized byte sequence ready for hashing, with
               properties:
               - Always <= PASSPHRASE_SIZE_LIMIT bytes
               - Consistent for canonically equivalent Unicode inputs

    Notes:
        - Empty string input returns empty bytes (b'')
        - DEBUG mode logs raw/normalized forms and lengths
    """

    # Normalize the raw passphrase using Unicode Normalization Form
    normalized_passphrase: str = normalize(UNICODE_NF, raw_passphrase)

    # Encode the normalized passphrase to bytes and truncate to the size limit
    encoded_passphrase: bytes = \
        normalized_passphrase.encode('utf-8')[:PASSPHRASE_SIZE_LIMIT]

    # Log details if debugging is enabled
    if DEBUG:
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


def get_passphrase_digest(passphrase: bytes) -> bytes:
    """
    Computes the BLAKE2 digest of the provided passphrase.

    This function takes a passphrase in bytes, updates the BLAKE2 hash
    object with the passphrase, and returns the resulting digest. The
    digest is computed using a specific salt and personalization string.

    Args:
        passphrase (bytes): The passphrase to be hashed, provided as a
                            byte string.

    Returns:
        bytes: The BLAKE2 digest of the passphrase as a byte string.
    """

    # Create a BLAKE2 hash object with the specified
    # digest size, personalization, and salt
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        person=PERSON_PASSPHRASE,
        salt=BYTES_D['blake2_salt'],
    )

    # Update the hash object with the provided passphrase
    hash_obj.update(passphrase)

    # Compute the final digest of the passphrase
    digest: bytes = hash_obj.digest()

    if DEBUG:
        log_d(f'passphrase digest:\n        {digest.hex()}')

    return digest


def sort_digest_list(digest_list: list[bytes]) -> list[bytes]:
    """
    Sorts a list of byte sequences (digests) in ascending order based on
    their byte values.

    This function modifies the original `digest_list` in place using the
    `sort()` method, which orders the elements from the smallest to the
    largest byte value. If debugging is enabled, it logs the sorting
    process and the sorted results.

    Args:
        digest_list (list[bytes]): A list of byte sequences (digests)
                                   to be sorted.

    Returns:
        list[bytes]: The sorted list of byte sequences, which is the
                     same as the input list after sorting (the same
                     object reference).
    """
    if not digest_list:
        if DEBUG:
            log_d('digest list is empty, nothing to sort')

        return digest_list

    if DEBUG:
        log_d('sorting IKM digests')

    # Sort the digest list in place in ascending order
    digest_list.sort(key=None, reverse=False)

    # Log sorted digests if debugging is enabled
    if DEBUG:
        log_d('sorted IKM digests:')
        for digest in digest_list:
            log_d(f'\r      - {digest.hex()}')

    return digest_list


def hash_digest_list(digest_list: list[bytes]) -> bytes:
    """
    Computes a BLAKE2b hash of concatenated digests using a specified
    salt.

    The hash calculation is performed as follows:
    BLAKE2b(
        data = digest_list[0] + digest_list[1] + ... + digest_list[N],
        salt = BYTES_D['blake2_salt'],
        digest_size = IKM_DIGEST_SIZE  # Should be defined globally
    )

    The order of the digests in the input list is preserved in the hash
    computation. An empty list will return the hash of an empty input.

    Args:
        digest_list: List of binary digests (order-sensitive).
                     If empty, returns the hash of an empty input.

    Returns:
        bytes: BLAKE2b hash with length determined by IKM_DIGEST_SIZE.
    """
    if DEBUG:
        log_d('hashing digest list')

    # Create a new BLAKE2 hash object with specified digest size and salt
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        salt=BYTES_D['blake2_salt'],
    )

    # Update the hash object with each byte sequence in the digest list
    for digest in digest_list:
        hash_obj.update(digest)

    # Finalize the hash and obtain the digest
    digest_list_hash: bytes = hash_obj.digest()

    if DEBUG:
        log_d(f'list containing {len(digest_list)} digests hashed')

    return digest_list_hash


def get_argon2_password(action: ActionID) -> None:
    """
    Computes the Argon2 password from the input keying material.

    This function collects keying material digests by calling the
    `collect_and_handle_ikm` function, sorts them, and computes the
    Argon2 password using the BLAKE2 hash function. The resulting digest
    is stored in the global `BYTES_D` dictionary under the key
    'argon2_password'.

    The function logs debug information throughout the process if the
    DEBUG flag is set, including the final Argon2 password in
    hexadecimal format.

    Args:
        action (ActionID): The action identifier.

    Returns:
        None
    """
    digest_list: list[bytes] = collect_and_handle_ikm(action)

    sorted_digest_list: list[bytes] = sort_digest_list(digest_list)

    argon2_password: bytes = hash_digest_list(sorted_digest_list)

    if DEBUG:
        log_d(f'argon2_password:\n        {argon2_password.hex()}')

    BYTES_D['argon2_password'] = argon2_password


def derive_keys() -> bool:
    """
    Derive symmetric keys from the Argon2 input key ("password").

    Performs an Argon2id key derivation (argon2id.kdf) to produce a
    fixed-size Argon2 tag, then derives application-specific working
    keys from that tag by calling derive_working_keys(argon2_tag).

    Behavior
    - Reads inputs from module-level dictionaries:
    - BYTES_D['argon2_password'] (bytes input to Argon2)
    - BYTES_D['argon2_salt'] (salt bytes)
    - INT_D['argon2_time_cost'] (ops limit/time cost)
    - Uses ARGON2_MEMORY_COST and ARGON2_TAG_SIZE for memory and output
      size.
    - Logs start/finish and elapsed time.

    Error handling
    - Returns False if the Argon2 KDF raises an exception (e.g.,
      RuntimeError).
    - Returns True on success after derive_working_keys completes.

    Side effects
    - Calls derive_working_keys(argon2_tag), which produces and stores
      working key material in module state.
    - Performs potentially expensive computation; caller should account
      for blocking/latency.

    Returns
        bool: True on success, False on failure.
    """
    log_i('deriving keys (time-consuming)')

    start_time: float = monotonic()

    try:
        argon2_tag: bytes = argon2id.kdf(
            size=ARGON2_TAG_SIZE,
            password=BYTES_D['argon2_password'],
            salt=BYTES_D['argon2_salt'],
            opslimit=INT_D['argon2_time_cost'],
            memlimit=ARGON2_MEMORY_COST,
        )
    except RuntimeError as error:
        log_e(f'{error}')
        return False

    derive_working_keys(argon2_tag)

    end_time: float = monotonic()

    log_i(f'keys derived in {format_time(end_time - start_time)}')

    return True


def hkdf_sha256(input_key: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-SHA-256 wrapper using empty salt.

    Args:
        input_key (bytes): Input keying material (HKDF `IKM`).
        info (bytes): Context-specific info (HKDF `info`),
                      can be any length.
        length (int): Number of bytes to derive (must be > 0).

    Returns:
        bytes: Derived key of exactly `length` bytes.
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


def derive_working_keys(argon2_tag: bytes) -> None:
    """
    Derive encryption and MAC keys from an Argon2 tag using HKDF-SHA-256.

    This function treats the provided Argon2 tag as HKDF input keying
    material (IKM) and derives two separate purpose-specific keys via
    HKDF-SHA-256, storing them in module state.

    Behavior

    - Uses hkdf_sha256(input_key, info, length) to derive:
        * a MAC key (stored at BYTES_D['mac_key'], length MAC_KEY_SIZE)
        * an encryption key (stored at BYTES_D['enc_key'], length
          ENC_KEY_SIZE)
    - Computes a key-commitment for the encryption key by hashing it
      with BLAKE2b (digest size = ENC_KEY_SIZE) and stores the result at
      BYTES_D['enc_key_hash'].
    - When DEBUG is true, logs the Argon2 tag and the derived values in
      hex.

    Args:
        argon2_tag (bytes): Raw output bytes from Argon2; used as
                            HKDF IKM.

    Returns:
        None
    """
    mac_key: bytes = hkdf_sha256(
        input_key=argon2_tag,
        info=HKDF_INFO_MAC,
        length=MAC_KEY_SIZE,
    )

    enc_key: bytes = hkdf_sha256(
        input_key=argon2_tag,
        info=HKDF_INFO_ENCRYPT,
        length=ENC_KEY_SIZE,
    )

    enc_key_hash: bytes = blake2b(enc_key, digest_size=ENC_KEY_SIZE).digest()

    BYTES_D['mac_key'] = mac_key
    BYTES_D['enc_key'] = enc_key
    BYTES_D['enc_key_hash'] = enc_key_hash

    if DEBUG:
        log_d(f'argon2_tag:\n        {argon2_tag.hex()}')
        log_d(f'mac_key:\n        {mac_key.hex()}')
        log_d(f'enc_key:\n        {enc_key.hex()}')
        log_d(f'enc_key_hash:\n        {enc_key_hash.hex()}')


# Perform encryption/decryption and authentication
# --------------------------------------------------------------------------- #


def init_nonce_counter() -> None:
    """
    Initialize the nonce counter.

    This function sets the nonce counter to its initial value (0)
    in preparation for encryption/authentication.

    The nonce counter is stored in a global dictionary, allowing
    it to be accessed by other functions involved in the encryption
    and authentication processes. This function can be called multiple
    times, and each invocation will reset the nonce counter to 0.

    If the DEBUG flag is enabled, the initialization of the nonce
    counter will be logged for debugging purposes.

    Returns:
        None
    """
    init_value: int = 0

    INT_D['nonce_counter'] = init_value

    if DEBUG:
        log_d(f'nonce counter initialized to {init_value}')


def increment_nonce() -> None:
    """
    Increment the nonce/counter and store the derived nonce bytes.

    This function increments the nonce counter stored in
    INT_D['nonce_counter'], derives the nonce byte sequence of length
    NONCE_SIZE using BYTEORDER, and writes it to BYTES_D['nonce']. The
    resulting nonce is used both for ChaCha20 encryption and as part of
    the keyed BLAKE2b MAC input.

    Notes and requirements:
      - The nonce must be unique for every encryption operation under
        the same key; reuse of nonce with the same key breaks security
        for ChaCha20 and may compromise MAC guarantees.
      - Ensure INT_D['nonce_counter'] and NONCE_SIZE are initialized and
        that BYTEORDER matches the protocol's endianness.
      - This function mutates INT_D and BYTES_D.
      - If DEBUG is true, the new counter value and nonce are logged.

    Returns:
        None
    """
    INT_D['nonce_counter'] += 1

    incremented_nonce: bytes = \
        INT_D['nonce_counter'].to_bytes(NONCE_SIZE, BYTEORDER)

    BYTES_D['nonce'] = incremented_nonce

    if DEBUG:
        incremented_counter: int = INT_D['nonce_counter']
        log_d(f'nonce counter incremented to {incremented_counter}; '
              f'new nonce: {incremented_nonce.hex()}')


def init_new_mac_chunk() -> None:
    """
    Initialize a new MAC chunk and reset its state.

    This function starts a new MAC (Message Authentication Code) chunk
    by:
      - incrementing the nonce (via increment_nonce()),
      - deriving/initializing a fresh MAC hash object
        (stored in ANY_D['mac_hash_obj']) using blake2b with the
        configured MAC key and digest size,
      - resetting the running chunk byte counter
        (INT_D['mac_chunk_size_sum'] = 0).

    Returns:
        None

    Notes:
      - Relies on global containers ANY_D, BYTES_D and INT_D and the
        functions increment_nonce() and blake2b being available in
        scope.
      - Emits debug logs when DEBUG is enabled.
    """
    if DEBUG:
        log_d('init new MAC chunk with new nonce')

    increment_nonce()  # For MAC and encryption

    ANY_D['mac_hash_obj'] = blake2b(
        digest_size=MAC_TAG_SIZE,
        key=BYTES_D['mac_key'],
    )

    if DEBUG:
        log_d('MAC hash object initialized')

    INT_D['mac_chunk_size_sum'] = 0


def update_mac(chunk: bytes, comment: str) -> None:
    """
    Update the MAC hash object with a data chunk.

    Retrieves the MAC hash object from ANY_D['mac_hash_obj'] and updates
    it with the provided byte chunk. Also increments the running total
    of processed message bytes stored in INT_D['mac_chunk_size_sum'].

    Args:
        chunk (bytes): Data to feed into the MAC.

    Returns:
        None

    Notes:
      - Uses ANY_D and INT_D globals for the hash object and size
        accumulator.
      - Logs the chunk size when DEBUG is enabled.
    """
    ANY_D['mac_hash_obj'].update(chunk)

    chunk_size: int = len(chunk)

    if DEBUG:
        log_d(f'MAC updated with: {comment}, {format_size(chunk_size)}')

    INT_D['mac_chunk_size_sum'] += chunk_size


def get_computed_mac_tag() -> bytes:
    """
    Compute and return the MAC tag.

    Steps:
    - Serialize the accumulated total processed size
      (INT_D['mac_chunk_size_sum']) into a fixed-length byte sequence of
      SIZE_BYTES_SIZE using BYTEORDER and feed it to the MAC.
    - Feed the current nonce (BYTES_D['nonce']) into the MAC.
    - Feed the session-associated data (BYTES_D['session_aad']) into the
      MAC.
    - Finalize the MAC via ANY_D['mac_hash_obj'].digest() and return the
      resulting tag bytes.

    Side effects:
    - Consumes and deletes ANY_D['mac_hash_obj'],
      INT_D['mac_chunk_size_sum'], and BYTES_D['nonce'] from their
      containers.
    - Expects ANY_D['mac_hash_obj'] to be a pre-initialized keyed
      MAC/hash object (e.g., keyed BLAKE2b or HMAC) with prior chunk
      updates.
    - Requires SIZE_BYTES_SIZE and BYTEORDER to be defined and
      consistent with the protocol.
    - Does not perform constant-time tag comparison; verification must
      be done elsewhere using a constant-time compare.

    Returns:
        bytes: The finalized MAC tag.
    """
    mac_chunk_size: int = INT_D['mac_chunk_size_sum']

    mac_chunk_size_bytes: bytes = \
        mac_chunk_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)

    if DEBUG:
        log_d(f'mac_chunk_size: {format_size(mac_chunk_size)}, '
              f'mac_chunk_size_bytes: {mac_chunk_size_bytes.hex()}')

    update_mac(mac_chunk_size_bytes, 'mac_chunk_size_bytes')
    update_mac(BYTES_D['nonce'], 'nonce')
    update_mac(BYTES_D['session_aad'], 'session_aad')

    computed_mac_tag: bytes = ANY_D['mac_hash_obj'].digest()

    del ANY_D['mac_hash_obj'], INT_D['mac_chunk_size_sum']

    if DEBUG:
        log_d(f'computed MAC tag:\n        {computed_mac_tag.hex()}')

    return computed_mac_tag


def write_mac_tag() -> bool:
    """
    Write the computed MAC tag to the output.

    This function obtains the MAC tag produced by get_computed_mac_tag()
    and writes it to the output using write_data(). It returns True
    on successful write and False on failure. Debug logs are emitted
    when DEBUG is enabled.

    Returns:
        bool: True if the MAC tag was retrieved and written successfully;
              False otherwise.
    """
    computed_mac_tag: bytes = get_computed_mac_tag()

    if DEBUG:
        log_d('writing computed MAC tag')

    if not write_data(computed_mac_tag):
        return False

    if DEBUG:
        log_d('computed MAC tag written')

    return True


def read_and_verify_mac_tag() -> bool:
    """
    Read and verify MAC tag by comparing a computed tag with a retrieved
    tag.

    Returns:
        bool: True if tags are present and equal
              (time-constant comparison). False otherwise.
    """
    computed_mac_tag: bytes = get_computed_mac_tag()

    retrieved_mac_tag: Optional[bytes] = \
        read_data(BIO_D['IN'], MAC_TAG_SIZE)

    if retrieved_mac_tag is None:
        log_e(MAC_FAIL_MESSAGE)
        return False

    if DEBUG:
        log_d(f'retrieved MAC tag:\n        {retrieved_mac_tag.hex()}')

    if compare_digest(computed_mac_tag, retrieved_mac_tag):

        if DEBUG:
            log_d('computed MAC tag is equal to retrieved MAC tag')

        return True

    log_e(MAC_FAIL_MESSAGE)
    return False


def feed_stream_cipher(input_data: bytes, comment: str) -> bytes:
    """
    Symmetric ChaCha20 encrypt/decrypt for a single chunk using a
    current nonce.

    Performs ChaCha20 stream cipher processing on input_data. On each
    use the caller must have incremented the nonce counter
    (so BYTES_D['nonce'] holds a fresh nonce). The same function works
    for encryption and decryption (symmetric stream cipher).

    Key behaviors and invariants:
      - Uses a 256-bit key from BYTES_D['enc_key'].
      - Builds a 128-bit full nonce as
        BLOCK_COUNTER_INIT_BYTES || BYTES_D['nonce'].
      - Does NOT provide authenticity; integrity must be ensured
        separately (e.g., keyed BLAKE2b tag over ciphertext + associated
        data).
      - Nonce reuse under the same key is catastrophic; ensure the
        counter is correctly incremented and persisted.

    Args:
        input_data (bytes): Data to process. Empty input yields empty
                            output.

    Returns:
        bytes: Processed output (ciphertext or plaintext), same length
               as input.

    Notes:
      - The function updates INT_D counters for debugging only
        (INT_D['enc_sum'], INT_D['enc_chunk_count']) when DEBUG is True.
      - Ensure NONCE_SIZE, BLOCK_COUNTER_INIT_BYTES length, and
        endianness of the counter are consistent with the protocol.
    """

    # Retrieve the incremented nonce value as queried by ChaCha20
    nonce: bytes = BYTES_D['nonce']

    # This ChaCha20 implementation uses a 128-bit full nonce
    full_nonce: bytes = BLOCK_COUNTER_INIT_BYTES + nonce

    # Create the ChaCha20 algorithm object
    algorithm: ChaCha20 = ChaCha20(
        key=BYTES_D['enc_key'],  # 256-bit encryption key
        nonce=full_nonce,  # 128-bit full nonce
    )

    # Create the cipher object
    cipher: Cipher[None] = Cipher(algorithm, mode=None)

    # Feed input data to the encryptor object and get the output
    output_data: bytes = cipher.encryptor().update(input_data)

    # Log the chunk size and nonce value if debugging is enabled
    if DEBUG:
        chunk_size: int = len(output_data)
        INT_D['enc_sum'] += chunk_size
        INT_D['enc_chunk_count'] += 1
        log_d(f'ChaCha20 input: {comment}, '
              f'size: {format_size(chunk_size)}, with nonce {nonce.hex()}')

    return output_data


# Handle padding
# --------------------------------------------------------------------------- #


def get_pad_size_from_unpadded(unpadded_size: int, pad_key: bytes) -> int:
    """
    Calculates the padding size based on the unpadded size and a padding
    key.

    This function computes the padding size to be applied to the
    unpadded size based on the provided parameters. The padding size is
    determined by the size of the unpadded size, a padding key converted
    from bytes to an integer, and a maximum padding size percentage
    (MAX_PAD_SIZE_PERCENT).

    The relationship between the unpadded size and the padding size is
    defined as follows:

    +———————————————+——————————+
    | unpadded_size | pad_size |
    +———————————————+——————————+
    |         padded_size      |
    +——————————————————————————+

    `padded_size` represents the total size of the cryptoblob.

    Args:
        unpadded_size (int): The size of the unpadded data in bytes.
            This value is used to calculate the padding size.

        pad_key (bytes): A byte string that influences the padding size.
            This key is converted to an integer to affect the padding
            size calculation.

    Returns:
        int: The calculated padding size in bytes.
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
    if DEBUG:
        max_pad_size: int = (unpadded_size * MAX_PAD_SIZE_PERCENT) // 100

        if max_pad_size:
            percent_of_max_total: float = \
                (pad_size * 100) / max_pad_size

        percent_of_unpadded: float = (pad_size * 100) / unpadded_size
        padded_size: int = unpadded_size + pad_size

        log_d('getting pad_size')

        log_d(f'pad_key_int:                {pad_key_int}')
        log_d(f'pad_key_int/PAD_KEY_SPACE:  {pad_key_int / PAD_KEY_SPACE}')

        log_d(f'unpadded_size:  {format_size(unpadded_size)}')
        log_d(f'max_pad_size:   {format_size(max_pad_size)}')

        if max_pad_size:
            log_d(f'pad_size:       {format_size(pad_size)}, '
                  f'{round(percent_of_unpadded, 1)}% of unpadded_size, '
                  f'{round(percent_of_max_total, 1)}% of max_pad_size')
        else:
            log_d(f'pad_size:       {format_size(pad_size)}, '
                  f'{round(percent_of_unpadded, 1)}% of unpadded_size')

        log_d(f'padded_size:    {format_size(padded_size)}')

    return pad_size


def get_pad_size_from_padded(padded_size: int, pad_key: bytes) -> int:
    """
    Calculates the padding size based on the padded size and the
    padding key.

    This function computes the padding size that was applied to the
    unpadded size using the specified padding key and maximum padding
    percentage (MAX_PAD_SIZE_PERCENT). The padding size is derived from
    the padded size and the integer value of the padding key.

    Args:
        padded_size (int): The size of the padded data in bytes. This
            parameter represents the size of the cryptoblob and is used
            to calculate the padding size.

        pad_key (bytes): A byte string representing a padding key. This
            key is converted to an integer to influence the padding
            size calculation.

    Returns:
        int: The calculated padding size in bytes.
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
    if DEBUG:
        unpadded_size: int = padded_size - pad_size
        percent_of_unpadded: float = (pad_size * 100) / unpadded_size

        log_d('getting pad_size')

        log_d(f'pad_key_int:                {pad_key_int}')
        log_d(f'pad_key_int/PAD_KEY_SPACE:  {pad_key_int / PAD_KEY_SPACE}')

        log_d(f'padded_size:    {format_size(padded_size)}')
        log_d(f'pad_size:       {format_size(pad_size)}, '
              f'{round(percent_of_unpadded, 1)}% of unpadded_size')
        log_d(f'unpadded_size:  {format_size(unpadded_size)}')

    return pad_size


def handle_padding(pad_size: int, action: ActionID) -> bool:
    """
    Handles padding: read/write, authenticate.

    This function processes `pad_size` bytes of padding either by
    writing random padding (when performing encryption/embed) or by
    reading padding bytes from the input (when performing
    decryption/verification). All padding data is fed into the running
    MAC to ensure authenticity, and a MAC tag is written or verified at
    the end of the padding region.

    If action is ENCRYPT or ENCRYPT_EMBED:
      - Generate and write pad_size bytes of random data in
        MAX_PT_CHUNK_SIZE chunks (full chunks first, then a final
        partial chunk if needed).
      - Each written chunk is passed to update_mac(...) for
        authentication.
      - After all padding is written, compute and write the MAC tag via
        write_mac_tag().

    Otherwise (decryption/verification mode):
      - Read pad_size bytes from BIO_D['IN'] in identical chunk sizes.
      - If any read returns None, the function fails.
      - Each read chunk is passed to update_mac(...) for authentication.
      - After all padding is read, read_and_verify_mac_tag() is called
        to verify the MAC; verification failure causes the function to
        fail.

    Args:
        pad_size (int): Total number of padding bytes to process.
        action (ActionID): Operation mode (e.g., ENCRYPT, ENCRYPT_EMBED,
            or a decryption/verification mode). Determines whether
            padding is written or read and whether the MAC tag is
            written or verified.

    Returns:
        bool: True on success; False on any I/O or MAC verification
              failure.

    Side effects:
      - Reads from or writes to BIO_D['IN'] and other global I/O
        helpers.
      - Updates the MAC state via update_mac(...).
      - Calls write_data, read_data, write_mac_tag, or
        read_and_verify_mac_tag, which may perform additional logging
        or I/O.
      - Relies on globals/constants: MAX_PT_CHUNK_SIZE, BIO_D, ENCRYPT,
        ENCRYPT_EMBED, and the functions token_bytes, write_data,
        read_data, update_mac, write_mac_tag, read_and_verify_mac_tag.
    """
    chunk: Optional[bytes]

    # Calculate the number of complete chunks and remaining bytes to write
    full_chunks: int = pad_size // MAX_PT_CHUNK_SIZE
    remain_size: int = pad_size % MAX_PT_CHUNK_SIZE

    # Write the full chunks of random data
    for _ in range(full_chunks):

        if action in (ENCRYPT, ENCRYPT_EMBED):

            # Generate a random data chunk of size MAX_PT_CHUNK_SIZE
            chunk = token_bytes(MAX_PT_CHUNK_SIZE)

            # Attempt to write the chunk; return False if it fails
            if not write_data(chunk):
                return False
        else:
            chunk = read_data(BIO_D['IN'], MAX_PT_CHUNK_SIZE)

            if chunk is None:
                return False

        update_mac(chunk, 'padding contents chunk')

    # If there is remaining data to write, handle it
    if remain_size:
        if action in (ENCRYPT, ENCRYPT_EMBED):

            # Generate a random data chunk of size MAX_PT_CHUNK_SIZE
            chunk = token_bytes(remain_size)

            # Attempt to write the chunk; return False if it fails
            if not write_data(chunk):
                return False
        else:
            chunk = read_data(BIO_D['IN'], remain_size)

            if chunk is None:
                return False

        update_mac(chunk, 'padding contents chunk')

    if action in (ENCRYPT, ENCRYPT_EMBED):
        if not write_mac_tag():
            return False
    else:
        if not read_and_verify_mac_tag():
            return False

    return True


# Handle payload file contents
# --------------------------------------------------------------------------- #


def get_enc_contents_size_from_contents(contents_size: int) -> int:
    """
    Compute the encrypted payload size (including per-chunk MAC tags)
    produced from a plaintext of the given length.

    Args:
        contents_size (int): Plaintext size in bytes (must be >= 0).

    Returns:
        int: Resulting encrypted payload size in bytes
            (ciphertext + per-chunk MAC tags). For each full plaintext
            chunk the size increases by MAX_CT_CHUNK_SIZE. If a final
            partial plaintext chunk exists, its ciphertext size is
            remain_size + MAC_TAG_SIZE.
    """
    full_chunks = contents_size // MAX_PT_CHUNK_SIZE
    remain_size = contents_size % MAX_PT_CHUNK_SIZE

    # Encrypted payload file conents (with MAC tags) from full
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
    Compute the plaintext size corresponding to an encrypted payload
    (with MAC tags) length.

    Args:
        enc_contents_size (int): Encrypted payload size in bytes
            (including per-chunk MAC tags). Must be >= 0.

    Returns:
        Optional[int]: Plaintext size in bytes if enc_contents_size is a
            valid length produced by the chunking scheme; otherwise None.

    Notes:
    - Uses chunk sizes MAX_CT_CHUNK_SIZE (ciphertext chunk including
      MAC) and MAX_PT_CHUNK_SIZE (corresponding plaintext chunk).
    - For a whole number of full ciphertext chunks the plaintext size is
      full_chunks * MAX_PT_CHUNK_SIZE. For a final partial ciphertext
      chunk the minimum size is 1 + MAC_TAG_SIZE and the plaintext
      portion is (partial_ct_size - MAC_TAG_SIZE).
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


def handle_payload_file_contents(action: ActionID, contents_size: int) -> bool:
    """
    Process a payload's plaintext-sized contents by handling each chunk.

    This function splits a payload of length contents_size into full
    chunks of size MAX_PT_CHUNK_SIZE and a final partial chunk (if any),
    then calls file_chunk_handler(action, chunk_size) for each chunk in
    sequence.

    Args:
        action (ActionID): Operation to perform on each chunk (e.g.,
                           ENCRYPT/DECRYPT).
        contents_size (int): Total plaintext-size payload length in
                             bytes (>= 0).

    Returns:
        bool: True if all chunk handlers succeeded; False if any
              file_chunk_handler call failed (in which case processing
              stops immediately).

    Notes:
    - file_chunk_handler is expected to perform per-chunk processing and
      return a boolean success indicator.
    - This function does not perform I/O itself; it delegates chunk work
      to file_chunk_handler.
    """

    # Calculate the number of complete chunks and remaining bytes
    full_chunks: int = contents_size // MAX_PT_CHUNK_SIZE
    remain_size: int = contents_size % MAX_PT_CHUNK_SIZE

    # Process complete chunks
    for _ in range(full_chunks):
        if not file_chunk_handler(action, MAX_PT_CHUNK_SIZE):
            return False

    # Process any remaining bytes
    if remain_size:
        if not file_chunk_handler(action, remain_size):
            return False

    return True


def file_chunk_handler(action: ActionID, chunk_size: int) -> bool:
    """
    Process a single plaintext/ciphertext chunk: read, transform, write
    and MAC.

    Reads chunk_size bytes from the input (BIO_D['IN']), performs the
    requested action (encryption or decryption), updates/validates the
    per-chunk MAC, and writes output and MAC tag as appropriate.

    Args:
        action (ActionID): Operation to perform. Supported values:
            - ENCRYPT, ENCRYPT_EMBED: encrypt input -> write ciphertext,
              update MAC, write MAC tag.
            - DECRYPT, EXTRACT_DECRYPT: update MAC from ciphertext,
              read/verify MAC tag, decrypt -> write plaintext.
        chunk_size (int): Number of plaintext bytes to read for
            encryption, or ciphertext bytes to process for decryption
            (must be >= 0 and match protocol expectations).

    Returns:
        bool: True on success; False on failure (I/O, MAC verification,
              or internal error). The function does not raise on
              expected runtime errors - callers should check the boolean
              result and handle cleanup.

    Side effects:
    - Reads from BIO_D['IN'] and writes to the output via write_data().
    - Updates MAC state via init_new_mac_chunk(), update_mac(), and
      write_mac_tag()/read_and_verify_mac_tag().
    - Logs progress as implemented by underlying helpers.

    Notes:
    - Caller is responsible for setting up BIO_D and for handling
      termination on failure.
    - The precise semantics of feed_stream_cipher(), write_data(), and
      MAC helpers determine on-disk layout (ciphertext + MAC tags).
    """
    init_new_mac_chunk()

    in_chunk: Optional[bytes] = read_data(BIO_D['IN'], chunk_size)

    if in_chunk is None:
        return False

    if action in (ENCRYPT, ENCRYPT_EMBED):

        out_chunk: bytes = feed_stream_cipher(in_chunk, 'file contents chunk')

        if not write_data(out_chunk):
            return False

        update_mac(out_chunk, 'encrypted file contents chunk')

        if not write_mac_tag():
            return False

    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)

        update_mac(in_chunk, 'encrypted file contents chunk')

        if not read_and_verify_mac_tag():
            return False

        out_chunk = \
            feed_stream_cipher(in_chunk, 'encrypted file contents chunk')

        if not write_data(out_chunk):
            return False

    return True


# Handle Comments
# --------------------------------------------------------------------------- #


def get_processed_comments(basename: str) -> bytes:
    """
    This function obtains a raw comment provided by a user and returns a
    byte-string of exactly PROCESSED_COMMENTS_SIZE bytes. Processing
    steps:

    1. Read the raw comment via get_raw_comments(basename). If the
       returned value is empty, the basename argument (the previously
       provided filename) is used as the comment.
    2. Encode the comment to UTF-8 bytes.
    3. If the encoded comment exceeds PROCESSED_COMMENTS_SIZE bytes, it
       is truncated to that limit (a warning is logged).
    4. To avoid potential partial-byte or invalid-Unicode issues after
       truncation, the truncated bytes are decoded back to a Unicode
       string with errors='ignore' (dropping any incomplete/invalid
       sequences), then re-encoded to UTF-8 bytes. This produces a
       sanitized byte sequence that is valid UTF-8.
    5. A COMMENTS_SEPARATOR is appended after the sanitized text,
       followed by random bytes produced by
       token_bytes(PROCESSED_COMMENTS_SIZE). The combined sequence is
       then sliced to PROCESSED_COMMENTS_SIZE bytes so the result has a
       deterministic length.
    6. For debugging, the function logs the raw and processed sizes and
       the decoded representation of the processed bytes (via
       decode_processed_comments).
    7. The resulting bytes are returned.

    Notes and guarantees:
    - The returned value is always exactly PROCESSED_COMMENTS_SIZE bytes
      long (or shorter only if PROCESSED_COMMENTS_SIZE is not positive).
    - The sanitized portion is guaranteed to be valid UTF-8; trailing
      padding (random) bytes may be arbitrary binary data.
    - If the original comment is empty, basename is used so the caller
      always has some content to display.
    - Truncation may remove characters if their UTF-8 encoded form would
      exceed the size limit; partial codepoints are dropped during
      sanitization to ensure valid decoding.
    - Side effects: logs warnings/info when truncation or debug logging
      occurs. decode_processed_comments is called for logging but its
      returned value is not otherwise used here.

    Args:
        basename (str): Base name of an input file previously supplied;
                        used as a fallback comment when no raw comment
                        is present.

    Returns:
        bytes: A byte string padded and/or truncated to
               PROCESSED_COMMENTS_SIZE bytes containing a UTF-8 valid
               sanitized comment followed by a separator and random
               padding.
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

    if DEBUG:
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
    Processes a byte string of processed comments and attempts to decode
    it into a valid comment (UTF-8 string).

    The function takes a byte string of processed_comments and first
    splits it into two parts at the first occurrence of the byte
    COMMENTS_SEPARATOR (which is not valid in UTF-8). The left part
    (before the separator, `processed_comments_part`) is then
    interpreted as a valid comment, and an attempt is made to decode it
    into a UTF-8 string. If the byte string contains an invalid UTF-8
    byte sequence, the function will return None.

    Args:
        processed_comments (bytes): The byte string containing processed
                                    comments to be decoded.

    Returns:
        Optional[str]: The decoded UTF-8 string if successful, or None
                       if decoding fails due to invalid UTF-8 byte
                       sequences.

    Notes:
        - The function uses the `partition` method to split the input
          byte string at the first occurrence of COMMENTS_SEPARATOR,
          discarding any bytes that follow.
        - If the left part of the input byte string is valid UTF-8, it
          will be returned as a string.
        - If a `UnicodeDecodeError` occurs during decoding, None is
          returned.
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
    action: ActionID,
    processed_comments: Optional[bytes],
) -> bool:
    """
    Handles processed comments: encrypt/decrypt, authenticate with MAC,
    and display when decrypting.

    This function performs the complete processing of the fixed-size
    processed comments block as part of the protocol's I/O flow.
    Behavior depends on the action mode:

    Encrypting modes (ENCRYPT, ENCRYPT_EMBED)

    - Prepares a new MAC chunk (init_new_mac_chunk()).
    - Requires processed_comments to be provided (bytes) and raises
      TypeError if None.
    - Encrypts the processed_comments with feed_stream_cipher(...).
    - Updates the running MAC with the encrypted comment bytes.
    - Writes the encrypted comment to the output (write_data).
    - Finalizes and writes the MAC tag for this chunk (write_mac_tag).
    - Returns False on any write/encryption/MAC failure; True on success.

    Decrypting modes (DECRYPT, EXTRACT_DECRYPT)

    - Prepares a new MAC chunk (init_new_mac_chunk()).
    - Reads exactly PROCESSED_COMMENTS_SIZE bytes from the input
      (read_data).
    - Updates the running MAC with the encrypted comment bytes.
    - Reads and verifies the MAC tag for this chunk
      (read_and_verify_mac_tag()); returns False on failure.
    - Decrypts the encrypted comment with feed_stream_cipher(...).
    - Decodes the decrypted processed comments to a string via
      decode_processed_comments(...) and logs them.
    - Returns False on any read/decryption/MAC failure; True on success.

    Side effects and requirements

    - Uses and modifies global/stateful helpers and containers:
      init_new_mac_chunk, update_mac, write_data, read_data,
      write_mac_tag, read_and_verify_mac_tag, feed_stream_cipher,
      decode_processed_comments, BIO_D, and constants such as
      PROCESSED_COMMENTS_SIZE.
    - init_new_mac_chunk() is called at the start to reset nonce/MAC
      state for this chunk.
    - On encrypt paths the function consumes processed_comments input
      and writes authenticated ciphertext.
    - On decrypt paths the function logs the decoded comments but does
      not return them; callers relying on the decoded value should
      obtain it from logs or adapt the function.
    - All MAC operations assume a pre-configured keyed MAC/hash
      implementation and that update_mac records data into the active
      MAC object.
    - Errors: missing processed_comments in an encrypt path raises
      TypeError; I/O, MAC, and crypto operation failures cause the
      function to return False.

    Args:
        action (ActionID): Operation mode, one of ENCRYPT,
            ENCRYPT_EMBED, DECRYPT, EXTRACT_DECRYPT.
        processed_comments (Optional[bytes]): Fixed-size comment bytes
            to encrypt when in an encrypting mode. Ignored (may be None)
            in decrypting modes.

    Returns:
        bool: True on success, False on failure (I/O, MAC verification,
              or crypto error).
    """
    init_new_mac_chunk()

    enc_processed_comments: Optional[bytes]  # Encrypted processed_comments

    if action in (ENCRYPT, ENCRYPT_EMBED):

        if processed_comments is None:
            raise TypeError

        enc_processed_comments = \
            feed_stream_cipher(processed_comments, 'processed_comments')

        update_mac(enc_processed_comments, 'enc_processed_comments')

        if not write_data(enc_processed_comments):
            return False

        if not write_mac_tag():
            return False

    else:  # DECRYPT, EXTRACT_DECRYPT
        enc_processed_comments = \
            read_data(BIO_D['IN'], PROCESSED_COMMENTS_SIZE)

        if enc_processed_comments is None:
            return False

        update_mac(enc_processed_comments, 'enc_processed_comments')

        if not read_and_verify_mac_tag():
            return False

        # Get decrypted processed_comments
        processed_comments = feed_stream_cipher(
            enc_processed_comments, 'enc_processed_comments')

        decoded_comments: Optional[str] = \
            decode_processed_comments(processed_comments)

        log_i(f'comments:\n        {[decoded_comments]}')

    return True


# Perform action INFO
# --------------------------------------------------------------------------- #


def info_and_warnings() -> None:
    """
    Logs general information, warnings, and debug information.

    This function performs the following actions:
    1. Logs general information.
    2. Iterates through a list of warnings and logs each one.
    3. If debug mode is enabled, it logs additional debug information.

    Returns:
        None
    """

    # Log general information
    log_i(APP_INFO)

    # Log any warnings
    for warning in APP_WARNINGS:
        log_w(warning)

    # Log debug information if debug mode is enabled
    if DEBUG:
        log_d(APP_DEBUG_INFO)


# Perform actions ENCRYPT, DECRYPT, ENCRYPT_EMBED, EXTRACT_DECRYPT
# --------------------------------------------------------------------------- #


def encrypt_and_embed(action: ActionID) -> bool:
    """
    Orchestrate a full encrypt/decrypt and (optional)
    embed/extract operation.

    This function gathers inputs via encrypt_and_embed_input(action), runs
    garbage collection, and then performs the core operation by calling
    encrypt_and_embed_handler(action, xxx).

    Args:
        action (ActionID): Operation mode (ENCRYPT, ENCRYPT_EMBED,
                           DECRYPT, EXTRACT_DECRYPT).

    Returns:
        bool: True on success; False if input collection fails
              or the handler returns False.
    """

    # Retrieve input parameters for the encryption and embedding process
    xxx: Optional[EE] = encrypt_and_embed_input(action)

    # If input retrieval fails, return False
    if xxx is None:
        return False

    # Perform garbage collection before proceeding
    collect()

    # Call the handler function to perform the action
    success: bool = encrypt_and_embed_handler(action, xxx)

    # Return the success status of the operation
    return success


def encrypt_and_embed_input(action: ActionID) -> Optional[EE]:
    """
    Collect and validate inputs required to perform encryption,
    embedding, or decryption, and return an EE instance populated with
    those parameters.

    This function performs all user- and file-related preparation for
    the encrypt/embed/decrypt workflow. It determines input and output
    file paths and sizes, computes padded/unpadded sizes and padding,
    generates or retrieves pad IKM and derived pad key (for encryption),
    gathers processed comments, computes start/end positions for
    embedding or extraction, reads required salts, prompts for Argon2
    password and time cost, and confirms overwrite when needed.

    Behavior summary
    - Opens and logs the input file (sets BIO_D['IN']).
    - For encryption actions (ENCRYPT, ENCRYPT_EMBED):
        - Generates pad IKM and derives pad key.
        - Computes enc_contents_size, unpadded_size and pad_size, then
          padded_size.
        - Collects processed comments (using input filename as default
          comment).
    - For decryption/extraction actions (DECRYPT, EXTRACT_DECRYPT):
        - Validates input file is large enough to contain a valid
          cryptoblob.
        - Uses input size (or user-provided start/end positions) to
          determine padded_size.
    - Sets up the output file (BIO_D['OUT']) for new files or selects an
      embed location for ENCRYPT_EMBED.
    - Determines start_pos and end_pos when embedding/extracting and
      seeks file handles to those positions.
    - Reads salts needed later and prompts for Argon2 password and time
      cost.
    - Requests user confirmation for overwrite when required.
    - Returns an EE instance populated with collected values, or None on
      error.

    Args:
        action (ActionID): The action to perform; one of ENCRYPT,
            ENCRYPT_EMBED, DECRYPT, EXTRACT_DECRYPT. This controls how
            inputs are collected and validated.

    Returns:
        Optional[EE]: An EE instance with these attributes set on
            success:
            - in_file_size (int): Input file size (bytes).
            - pad_ikm (Optional[bytes]): Pad input keying material
              (randomly generated for encryption; None for decryption).
            - unpadded_size (Optional[int]): Unpadded cryptoblob size
              (for encryption) or computed during decryption/extraction.
            - padded_size (int): Total padded size to read/write.
            - processed_comments (Optional[bytes]): Comment bytes to
              include (encryption) or validate (decryption).
            - start_pos (Optional[int]): Start offset in the container
              (for embed/extract modes) or None.
            - end_pos (Optional[int]): End offset in the container (for
              extract mode) or None.
        Returns None if input collection or validation fails (I/O error,
        user cancellation, size validation failure, or helper function
        failure).

    Side effects / global state:
    - Sets BIO_D['IN'] and BIO_D['OUT'] to opened file-like objects.
    - May set INT_D['start_pos'] and INT_D['max_end_pos'] for embed flow.
    - Calls functions which mutate global dictionaries (BYTES_D, INT_D,
      FLOAT_D) and may write to disk.
    - Logs informational, debug, warning and error messages via
      log_i/log_d/log_w/log_e.

    Failure modes:
    - Returns None on invalid sizes, I/O problems, user cancellation,
      exceeding maximum cryptoblob size, or if helper functions
      (get_salts, get_argon2_password, get_argon2_time_cost, etc.) fail.
    - May raise TypeError where the implementation requires non-None
      values but receives None (e.g., unpadded_size or start_pos missing
      when required).

    Preconditions:
    - Calling code should expect that helper functions perform
      additional validation and user prompts; this function does not
      re-check those validations beyond handling their return values.
    """

    # 0. Initialize variables
    # ----------------------------------------------------------------------- #

    pad_ikm: Optional[bytes] = None
    unpadded_size: Optional[int] = None

    processed_comments: Optional[bytes] = None

    start_pos: Optional[int] = None
    end_pos: Optional[int] = None

    # 1. Get input file path and size
    # ----------------------------------------------------------------------- #

    in_file_path: str
    in_file_size: int

    # Retrieve the input file path, size, and file object
    in_file_path, in_file_size, BIO_D['IN'] = get_input_file(action)

    # Log the input file path and size
    log_i(f'path: {in_file_path!r}; size: {format_size(in_file_size)}')

    # 2. Get pad_key
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):

        pad_ikm = token_bytes(PAD_KEY_SIZE)

        pad_key: bytes = hkdf_sha256(
            input_key=pad_ikm,
            info=HKDF_INFO_PAD,
            length=PAD_KEY_SIZE
        )

        if DEBUG:
            log_d(f'pad_ikm:  {pad_ikm.hex()}')
            log_d(f'pad_key:  {pad_key.hex()}')

    # 3. Retrieve and verify additional sizes
    # ----------------------------------------------------------------------- #

    # Handle encryption actions (ENCRYPT, ENCRYPT_EMBED)
    if action in (ENCRYPT, ENCRYPT_EMBED):

        # Get size of encrypted payload file contents (with MAC tags)
        enc_contents_size: int = \
            get_enc_contents_size_from_contents(in_file_size)

        # Get the size of unpadded cryptoblob
        unpadded_size = enc_contents_size + MIN_VALID_UNPADDED_SIZE

        if unpadded_size is None:
            raise TypeError

        pad_size = get_pad_size_from_unpadded(unpadded_size, pad_key)
        padded_size = unpadded_size + pad_size

    # Handle decryption actions (DECRYPT, EXTRACT_DECRYPT) and validate
    # input file size
    else:
        if in_file_size < MIN_VALID_UNPADDED_SIZE:
            log_e(f'input file is too small; size must be '
                  f'>= {format_size(MIN_VALID_UNPADDED_SIZE)}')
            return None

    if action == DECRYPT:
        padded_size = in_file_size

    # 4. Get processed comments for their further encryption
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):

        try:
            basename: str = path.basename(in_file_path)
        except TypeError:
            basename = ''

        processed_comments = get_processed_comments(basename)

    # 5. Retrieve the output file path, size, and file object
    # ----------------------------------------------------------------------- #

    out_file_path: str
    out_file_size: int

    # Set up output file based on the action
    if action in (ENCRYPT, DECRYPT):  # New file creation
        out_file_path, BIO_D['OUT'] = get_output_file_new(action)
        log_i(f'new empty file {out_file_path!r} created')

    elif action == ENCRYPT_EMBED:  # Existing file handling for encryption
        out_file_path, out_file_size, BIO_D['OUT'] = \
            get_output_file_exist(
                in_file_path,
                padded_size,
                action,
        )
        max_start_pos: int = out_file_size - padded_size
        log_i(f'path: {out_file_path!r}')

    else:  # action == EXTRACT_DECRYPT, new file creation for decryption
        out_file_path, BIO_D['OUT'] = get_output_file_new(action)
        max_start_pos = in_file_size - MIN_VALID_UNPADDED_SIZE
        log_i(f'new empty file {out_file_path!r} created')

    # Log the size of the output file if applicable
    if action == ENCRYPT_EMBED:
        log_i(f'size: {format_size(out_file_size)}')

    # 6. Get positions for embedding/extraction
    # ----------------------------------------------------------------------- #

    # Get the starting position for the operation
    if action in (ENCRYPT_EMBED, EXTRACT_DECRYPT):
        start_pos = get_start_position(max_start_pos, no_default=True)
        log_i(f'start position: {start_pos} (offset: {start_pos:,} B)')

        if action == ENCRYPT_EMBED:
            # These values will be used in proceed_request()
            INT_D['start_pos'] = start_pos
            INT_D['max_end_pos'] = start_pos + padded_size

    # Get the ending position for extraction
    if action == EXTRACT_DECRYPT:
        if start_pos is None:
            raise TypeError

        end_pos = get_end_position(
            min_pos=start_pos + MIN_VALID_UNPADDED_SIZE,
            max_pos=in_file_size,
            no_default=True,
        )
        log_i(f'end position: {end_pos} (offset: {end_pos:,} B)')

        padded_size = end_pos - start_pos

        if DEBUG:
            log_d(f'cryptoblob size: {format_size(padded_size)}')

    # 7. Check if the size of the cryptoblob exceeds the maximum valid size
    # ----------------------------------------------------------------------- #

    if padded_size > MAX_VALID_PADDED_SIZE:
        log_e(f'cryptoblob size is too big: {format_size(padded_size)}')
        return None

    # 8. Set file pointers to the specified positions
    # ----------------------------------------------------------------------- #

    # Seek to the start position in the container
    if action in (ENCRYPT_EMBED, EXTRACT_DECRYPT):

        if start_pos is None:
            raise TypeError

        if action == ENCRYPT_EMBED:
            if not seek_position(BIO_D['OUT'], start_pos):
                return None
        else:
            if not seek_position(BIO_D['IN'], start_pos):
                return None

    # 9. Get salts: need for handling IKM and for performing Argon2
    # ----------------------------------------------------------------------- #

    if not get_salts(in_file_size, end_pos, action):
        return None

    # 10. Collect and handle IKM, and get the Argon2 password for
    # further key derivation
    # ----------------------------------------------------------------------- #

    get_argon2_password(action)

    # 11. Get time cost value
    # ----------------------------------------------------------------------- #

    get_argon2_time_cost(action)

    # 12. Ask user confirmation for proceeding
    # ----------------------------------------------------------------------- #

    if action == ENCRYPT_EMBED:
        if not proceed_request(PROCEED_OVERWRITE, action):
            log_i('stopped by user request')
            return None

    # 13. Return the retrieved parameters for further processing
    # ----------------------------------------------------------------------- #

    xxx: EE = EE()

    xxx.in_file_size = \
        in_file_size

    xxx.pad_ikm = \
        pad_ikm

    xxx.unpadded_size = \
        unpadded_size

    xxx.padded_size = \
        padded_size

    xxx.processed_comments = \
        processed_comments

    xxx.start_pos = \
        start_pos

    xxx.end_pos = \
        end_pos

    return xxx


def encrypt_and_embed_handler(action: ActionID, xxx: EE) -> bool:
    """
    Perform the core cryptographic workflow for encrypt or decrypt
    actions and (optionally) embed the cryptoblob.

    This function executes the end-to-end processing after user inputs
    and high-level validation are complete. It derives working keys,
    prepares and authenticates associated data (AAD), encrypts or
    decrypts the padding and payload, writes or reads cryptographic
    metadata (argon2 and blake2 salts, encrypted pad IKM), updates
    progress counters, and ensures final integrity and synchronization.

    Behavior summary

    - Derives encryption and MAC keys via derive_keys().
    - Clears sensitive in-memory secrets and triggers garbage collection.
    - Initializes nonces, counters, and timing metrics.
    - For encryption actions (ENCRYPT, ENCRYPT_EMBED):
        Writes argon2 salt, encrypts and writes pad IKM, computes pad
        size from provided unpadded/padded sizes, processes payload and
        comments, writes blake2 salt, and (for ENCRYPT_EMBED) fsyncs
        output.
    - For decryption actions (DECRYPT, EXTRACT_DECRYPT):
        Reads and decrypts the encrypted pad IKM, derives pad key,
        computes pad size from padded size, validates sizes and MACs,
        processes payload and comments, and logs final progress.
    - Constructs session AAD from salts, encrypted pad IKM and size
      fields and stores it in BYTES_D['session_aad'].
    - Validates that total written bytes equal the expected output size
      and returns False on mismatch or any step failure.
    - Emits informational, debug, warning, and error logs throughout the
      process.

    Args:
        action (ActionID): The operation mode; expected values include
            ENCRYPT, ENCRYPT_EMBED, DECRYPT, EXTRACT_DECRYPT.
        xxx (EE): An instance of the EE class containing input-related
            values used by this handler:
            in_file_size (int): original input payload file size (for
                encryption).
            pad_ikm (Optional[bytes]): pad input keying material
                (present during encryption) or None (during decryption).
            unpadded_size (Optional[int]): unpadded total size (provided
                for encryption) or computed during decryption.
            padded_size (int): total padded size read from metadata.
            processed_comments (Optional[bytes]): comment bytes to
                include (encryption) or validate (decryption).
            start_pos (Optional[int]): start offset in the container
                (used for embed-mode logging).
            end_pos (Optional[int]): end offset in the container
                (updated in embed mode). `end_pos` is set only for
                EXTRACT_DECRYPT during input collection; for
                ENCRYPT_EMBED it is computed and logged later in the
                handler.

    Returns:
        bool: True on successful completion of all steps; False on any
              error, validation failure, or I/O/authentication problem.

    Side effects and global state

    - Reads and writes global dictionaries and resources such as
      BYTES_D, INT_D, FLOAT_D, BIO_D and may call functions that mutate
      other global state.
    - May write to BIO_D['OUT'] and read from BIO_D['IN'].
    - Stores session AAD into BYTES_D['session_aad'].
    - Logs via log_i/log_e/log_w/log_d and updates progress counters.
    - Calls functions that perform I/O (write_data, read_data),
      cryptographic operations (feed_stream_cipher, hkdf_sha256,
      derive_keys, init_nonce_counter), padding and comment handling
      (handle_padding, handle_payload_file_contents, handle_comments),
      and final synchronization (fsync_written_data).

    Failure modes

    - Returns False on I/O errors, MAC/authentication failures,
      unexpected sizes, missing required fields, or any helper function
      returning False.
    - Raises TypeError where the implementation explicitly requires a
      non-None value but receives None (e.g., missing pad_ikm or
      unpadded_size during encryption).

    Notes

    - This function assumes its preconditions are met by prior
      validation code (correct action, populated fields in xxx, and that
      helper functions behave as documented).
    - Sensitive values are deleted as soon as they are no longer needed;
      ensure surrounding code follows similar hygiene.
    """

    # 0. Unpack values
    # ----------------------------------------------------------------------- #

    in_file_size: int = \
        xxx.in_file_size

    pad_ikm: Optional[bytes] = \
        xxx.pad_ikm

    unpadded_size: Optional[int] = \
        xxx.unpadded_size

    padded_size: int = \
        xxx.padded_size

    processed_comments: Optional[bytes] = \
        xxx.processed_comments

    start_pos: Optional[int] = \
        xxx.start_pos

    end_pos: Optional[int] = \
        xxx.end_pos

    # 1. Derive keys needed for encryption/authentication
    # ----------------------------------------------------------------------- #

    if not derive_keys():
        return False

    # 2. Clean up sensitive data from memory and trigger garbage collection
    # ----------------------------------------------------------------------- #

    del BYTES_D['argon2_password']

    collect()

    # 3. Initialize values
    # ----------------------------------------------------------------------- #

    # Initialize nonce counter for the current action
    init_nonce_counter()

    # Initialize the total written bytes counter
    INT_D['written_sum'] = 0

    # Start timing the operation
    FLOAT_D['start_time'] = monotonic()
    FLOAT_D['last_progress_time'] = monotonic()

    if DEBUG:
        # Initialize the counter for the total size of encrypted/decrypted data
        INT_D['enc_sum'] = 0

        # Initialize the counter for the total number of encrypted chunks
        INT_D['enc_chunk_count'] = 0

    # Set the 'file_handler_started' flag (used for handling signals)
    ANY_D['file_handler_started'] = None

    # 4. Write argon2_salt if encrypting
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):
        log_i('writing cryptoblob')

        if DEBUG:
            log_d('writing argon2_salt')

        if not write_data(BYTES_D['argon2_salt']):
            return False

        if DEBUG:
            log_d('argon2_salt written')

    else:
        log_i('trying to decrypt data')

    # 5. Handle pad_ikm
    # ----------------------------------------------------------------------- #

    init_new_mac_chunk()

    encrypted_pad_ikm: Optional[bytes]

    # encrypt pad_ikm, wrie encrypted_pad_ikm
    if action in (ENCRYPT, ENCRYPT_EMBED):

        if pad_ikm is None:
            raise TypeError

        encrypted_pad_ikm = feed_stream_cipher(pad_ikm, 'pad_ikm')

        if DEBUG:
            log_d(f'encrypted_pad_ikm:  {encrypted_pad_ikm.hex()}')
            log_d('writing encrypted_pad_ikm')

        if not write_data(encrypted_pad_ikm):
            return False

        if DEBUG:
            log_d(f'encrypted_pad_ikm:  {encrypted_pad_ikm.hex()}')
            log_d('writing encrypted_pad_ikm completed')

    # get pad_ikm and pad_key
    else:

        if DEBUG:
            log_d('reading encrypted_pad_ikm')

        encrypted_pad_ikm = read_data(BIO_D['IN'], PAD_KEY_SIZE)

        if encrypted_pad_ikm is None:
            return False

        if DEBUG:
            log_d('reading encrypted_pad_ikm completed')

        pad_ikm = feed_stream_cipher(encrypted_pad_ikm, 'encrypted_pad_ikm')

        pad_key = hkdf_sha256(
            input_key=pad_ikm,
            info=HKDF_INFO_PAD,
            length=PAD_KEY_SIZE,
        )

        if DEBUG:
            log_d(f'encrypted_pad_ikm:  {encrypted_pad_ikm.hex()}')
            log_d(f'pad_ikm:            {pad_ikm.hex()}')
            log_d(f'pad_key:            {pad_key.hex()}')

    # 6. Get pad_size
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):

        if unpadded_size is None:
            raise TypeError

        pad_size: int = padded_size - unpadded_size

    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
        pad_size = get_pad_size_from_padded(padded_size, pad_key)

        unpadded_size = padded_size - pad_size

    # 7. Calculate, log, and validate sizes
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('calculating additional sizes')

    # Determine the size of the payload file contents to be processed
    if action in (ENCRYPT, ENCRYPT_EMBED):

        contents_size: Optional[int] = in_file_size

    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)

        enc_contents_size: int = unpadded_size - MIN_VALID_UNPADDED_SIZE

        contents_size = get_contents_size_from_enc_contents(enc_contents_size)

        if DEBUG:
            log_d(f'unpadded_size:  {unpadded_size}')
            log_d(f'enc_contents_size:        {enc_contents_size}')
            log_d(f'contents_size:  {contents_size}')

        if contents_size is None:
            log_e(MAC_FAIL_MESSAGE)
            return False

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
    INT_D['total_out_data_size'] = out_data_size

    # Debug logging for sizes
    if DEBUG:
        log_d(f'payload file contents size:  {format_size(contents_size)}')
        log_d(f'output data size:            {format_size(out_data_size)}')

    # Validate contents size (for decryption actions)
    if contents_size < 0:
        log_e(MAC_FAIL_MESSAGE)
        return False

    if action in (ENCRYPT, ENCRYPT_EMBED):
        log_i(f'data size to write: {format_size(out_data_size)}')

    # 8. Convert sizes to bytes for further authentication
    # ----------------------------------------------------------------------- #

    padded_size_bytes: bytes = \
        padded_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)

    pad_size_bytes: bytes = \
        pad_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)

    contents_size_bytes: bytes = \
        contents_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)

    if DEBUG:
        log_d(f'padded_size_bytes:    {padded_size_bytes.hex()}')
        log_d(f'pad_size_bytes:       {pad_size_bytes.hex()}')
        log_d(f'contents_size_bytes:  {contents_size_bytes.hex()}')

    # 9. Construct AAD for this session/action
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('constructing the session AAD by concatenating the '
              'following byte strings:')

    aad_list: list[bytes] = [
        BYTES_D['argon2_salt'],
        BYTES_D['blake2_salt'],
        encrypted_pad_ikm,
        padded_size_bytes,
        pad_size_bytes,
        contents_size_bytes,
        BYTES_D['enc_key_hash'],
    ]

    session_aad: bytes = b''.join(aad_list)

    BYTES_D['session_aad'] = session_aad

    if DEBUG:
        for byte_string in aad_list:
            log_d(f'- {byte_string.hex()}')

        log_d(f'resulting session AAD:\n        {session_aad.hex()}')

    # 10. Handle padding
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('handling padding')

    if not handle_padding(pad_size, action):
        return False

    if DEBUG:
        log_d('handling padding completed')

    # 11. Handle contents of the payload file based on the action type
    # ----------------------------------------------------------------------- #

    if action in (DECRYPT, EXTRACT_DECRYPT):
        log_i(f'data size to write: {format_size(out_data_size)}')

    if DEBUG:
        log_d('handling payload file contents')

    if not handle_payload_file_contents(action, contents_size):
        return False

    if DEBUG:
        log_d('handling payload file contents completed')

    # 12. Handle comments based on the action type
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('handling comments')

    if not handle_comments(action, processed_comments):
        return False

    if DEBUG:
        log_d('handling comments completed')

    # 13. Summary
    # ----------------------------------------------------------------------- #

    if DEBUG:
        enc_sum: int = INT_D['enc_sum']
        enc_chunk_count: int = INT_D['enc_chunk_count']

        if action in (ENCRYPT, ENCRYPT_EMBED):
            log_d(f'encryption completed; total encrypted with ChaCha20: '
                  f'{enc_chunk_count} chunks, {format_size(enc_sum)}')
        else:
            log_d(f'decryption completed; total decrypted with ChaCha20: '
                  f'{enc_chunk_count} chunks, {format_size(enc_sum)}')

    # Log progress for decryption actions
    if action in (DECRYPT, EXTRACT_DECRYPT):
        log_progress_final()

    # 14. Write blake2_salt if encrypting
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):
        if DEBUG:
            log_d('writing blake2_salt')

        if not write_data(BYTES_D['blake2_salt']):
            return False

        if DEBUG:
            log_d('blake2_salt written')

        log_progress_final()

    # 15. Validate the total written size against the expected output size
    # -----------------------------------------------------------------------

    if INT_D['written_sum'] != out_data_size:
        written_sum: int = INT_D['written_sum']
        log_e(f'written data size ({written_sum:,} B) does not '
              f'equal expected size ({out_data_size:,} B)')
        return False

    # 16. Synchronize data to disk if necessary
    # ----------------------------------------------------------------------- #

    if action == ENCRYPT_EMBED:
        log_i('syncing output data to disk')
        fsync_start_time: float = monotonic()

        if not fsync_written_data():
            return False

        fsync_end_time: float = monotonic()
        log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    # 17. Log progress and locations
    # ----------------------------------------------------------------------- #

    # Log the location of the cryptoblob in the container if encrypting
    if action == ENCRYPT_EMBED:
        end_pos = BIO_D['OUT'].tell()
        log_w('cryptoblob location is important for its further extraction!')
        log_i(f'remember cryptoblob location in container:\n'
              f'        [{start_pos}:{end_pos}]')

    return True


# Perform actions EMBED, EXTRACT
# --------------------------------------------------------------------------- #


def embed(action: ActionID) -> bool:
    """
    Handles the embedding or extraction of a message based on the
    specified action.

    This function orchestrates the process of embedding or extracting a
    message by first retrieving the necessary input parameters
    (start position and message size) through the `embed_input`
    function. If the input retrieval is successful, it then calls the
    `embed_handler` function to perform the actual operation.

    Args:
        action (ActionID): An integer indicating the action to perform.
            - EMBED: Embed data into an existing output file.
            - EXTRACT: Extract data from the container.

    Returns:
        bool: True if the embedding or extraction operation was
              successful, False if the operation was canceled or failed.

    Notes:
        - If the input retrieval fails (returns None), the function
          will return False immediately.
        - The function relies on the `embed_input` and `embed_handler`
          functions to handle the specifics of input retrieval and
          data embedding/extraction, respectively.
    """

    # Retrieve the start position and message size based on the action
    input_values: Optional[tuple[int, int]] = embed_input(action)

    # If input retrieval fails, return False
    if input_values is None:
        return False

    # Unpack the start position and message size from the retrieved values
    start_pos: int = input_values[0]
    message_size: int = input_values[1]

    # Call the handler to perform the embedding or extraction operation
    success: bool = embed_handler(action, start_pos, message_size)

    return success


def embed_input(action: ActionID) -> Optional[tuple[int, int]]:
    """
    Prepares the input file and determines the start and message sizes
    for embedding or extracting.

    This function retrieves the input file based on the specified
    action, logs relevant information about the file, and calculates the
    start position and message size for either embedding or extracting.
    It supports two actions: embedding data into an existing output file
    (action EMBED) or extracting data from the container into a new file
    (action EXTRACT).

    Args:
        action (ActionID): An integer indicating the action to perform.
            - EMBED: Embed data into an existing output file.
            - EXTRACT: Extract data from the container into a new file.

    Returns:
        Optional[tuple]: A tuple containing the start position (int) and
            the message size (int) if successful, or None if the
            operation was canceled by the user.

    Notes:
        - The function logs the path and size of the input file.
        - For action EMBED, it retrieves the output file and its size,
          and calculates the maximum starting position for embedding.
        - For action EXTRACT, it creates a new output file and sets the
          maximum starting position accordingly for extraction.
        - The function prompts the user for confirmation if action EMBED
          is selected and the embedding process is about to proceed.
    """
    in_file_path: str
    out_file_path: str
    in_file_size: int
    out_file_size: int
    start_pos: int
    end_pos: int
    max_start_pos: int
    message_size: int

    # Retrieve the input file path and size based on the action
    in_file_path, in_file_size, BIO_D['IN'] = get_input_file(action)

    # Log the path and size of the input file
    log_i(f'path: {in_file_path!r}; size: {format_size(in_file_size)}')

    if action == EMBED:
        # For embedding, retrieve the existing output file and its size
        out_file_path, out_file_size, BIO_D['OUT'] = get_output_file_exist(
            in_file_path, in_file_size, action)

        max_start_pos = out_file_size - in_file_size
        log_i(f'path: {out_file_path!r}')

    else:  # action EXTRACT
        # For extraction, create a new output file
        out_file_path, BIO_D['OUT'] = get_output_file_new(action)

        max_start_pos = in_file_size
        log_i(f'new empty file {out_file_path!r} created')

    if action == EMBED:
        # Log the size of the output file for embedding
        log_i(f'size: {format_size(out_file_size)}')

    # Get the starting position for embedding or extraction
    start_pos = get_start_position(max_start_pos, no_default=True)
    log_i(f'start position: {start_pos} (offset: {start_pos:,} B)')

    if action == EMBED:
        # For embedding, set message size to input file size
        message_size = in_file_size
        end_pos = start_pos + message_size
        log_i(f'end position: {end_pos} (offset: {end_pos:,} B)')

        # Prompt user for confirmation before proceeding
        if not proceed_request(PROCEED_OVERWRITE, action):
            log_i('stopped by user request\n')
            return None
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

    # Return the start position and message size
    return start_pos, message_size


def embed_handler(action: ActionID, start_pos: int, message_size: int) -> bool:
    """
    Handles the embedding or extraction of a message in a specified
    container.

    This function reads data from an input source, writes it to an
    output destination, and computes a checksum of the written data.
    It supports two actions: embedding data into a container (action
    EMBED) or extracting data from the container into a new file (action
    EXTRACT). The function also manages progress reporting and
    synchronization of the output data.

    Args:
        action (ActionID): An integer indicating the action to perform.
            - EMBED: Embed data into the output container.
            - EXTRACT: Extract data from the container into a new file.
        start_pos (int): The position in the container where the
                         embedding or extraction should start.
        message_size (int): The total size of the message to be embedded
                            or extracted in bytes.

    Returns:
        bool: True if the operation was successful, False otherwise.

    Notes:
        - The function uses a debug mode to print positions and progress
          information if the DEBUG flag is set.
        - It handles reading and writing in chunks defined by
          MAX_PT_CHUNK_SIZE.
        - The function computes a checksum using the BLAKE2 hashing
          algorithm and logs the checksum and the position of the
          embedded or extracted message.
        - If action EMBED is performed, it ensures that the output data
          is synchronized after writing.
    """

    # Set the 'file_handler_started' flag (used for handling signals)
    ANY_D['file_handler_started'] = None

    # Seek to the start position in the appropriate container
    if action == EMBED:
        if not seek_position(BIO_D['OUT'], start_pos):
            return False  # Return False if seeking fails

        log_i('reading message from input and writing it over output')

    else:  # action == EXTRACT
        if not seek_position(BIO_D['IN'], start_pos):
            return False

        log_i('reading message from input and writing it to output')

    # Initialize the BLAKE2 hash object for checksum calculation
    hash_obj: Any = blake2b(digest_size=CHECKSUM_SIZE)

    # Start timing the operation
    FLOAT_D['start_time'] = monotonic()
    FLOAT_D['last_progress_time'] = monotonic()

    # Initialize the total written bytes counter
    INT_D['written_sum'] = 0

    INT_D['total_out_data_size'] = message_size

    # Calculate the number of complete chunks and remaining bytes
    full_chunks: int = message_size // MAX_PT_CHUNK_SIZE
    remain_size: int = message_size % MAX_PT_CHUNK_SIZE

    # Read and write complete chunks of data
    for _ in range(full_chunks):
        message_chunk: Optional[bytes] = \
            read_data(BIO_D['IN'], MAX_PT_CHUNK_SIZE)

        if message_chunk is None:
            return False  # Return False if reading fails

        if not write_data(message_chunk):
            return False  # Return False if writing fails

        hash_obj.update(message_chunk)  # Update the checksum with the chunk

    # Write any remaining bytes that do not fit into a full chunk
    if remain_size:
        message_chunk = read_data(BIO_D['IN'], remain_size)

        if message_chunk is None:
            return False

        if not write_data(message_chunk):
            return False

        # Update the checksum with the last chunk
        hash_obj.update(message_chunk)

    log_progress_final()

    # Validate the total written size against the expected output size
    if INT_D['written_sum'] != message_size:
        written_sum: int = INT_D['written_sum']
        log_e(f'written data size ({written_sum:,} B) does not '
              f'equal expected size ({message_size:,} B)')
        return False

    if action == EMBED:
        log_i('syncing output data to disk')
        fsync_start_time: float = monotonic()

        # Synchronize the output data to ensure all changes are flushed
        if not fsync_written_data():
            return False  # Return False if synchronization fails

        fsync_end_time: float = monotonic()
        log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    # Compute the checksum of the written data
    message_checksum: str = hash_obj.hexdigest()

    # Get the current position in the output container
    end_pos: int = BIO_D['OUT'].tell()

    if action == EMBED:
        log_w('message location is important for its further extraction!')

        # Log the location of the embedded message in the container
        log_i(f'remember message location in container:\n'
              f'        [{start_pos}:{end_pos}]')

    log_i(f'message checksum:\n        {message_checksum}')

    return True


# Perform action CREATE_W_RANDOM
# --------------------------------------------------------------------------- #


def create_with_random(action: ActionID) -> bool:
    """
    Creates a file of a specified size with random data.

    Args:
        action (ActionID): The action identifier.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """

    # Initialize the output file and retrieve its size based on the action
    out_file_size: int = create_with_random_input(action)

    # Write random data to the newly created file
    success: bool = create_with_random_handler(out_file_size)

    # Return the success status of the operation
    return success


def create_with_random_input(action: ActionID) -> int:
    """
    Initializes a new output file based on the specified action and
    returns its size.

    This function creates a new output file, logs a creation message,
    and retrieves the size of the newly created file in bytes.

    Args:
        action (ActionID): The action ID that determines the output
                           file.

    Returns:
        int: The size of the newly created output file in bytes.
    """

    # Create a new output file and retrieve its path
    out_file_path: str

    out_file_path, BIO_D['OUT'] = get_output_file_new(action)

    # Log the creation of the new file
    log_i(f'new empty file {out_file_path!r} created')

    # Get the desired size of the newly created output file
    out_file_size: int = get_output_file_size()

    # Log the size of the new file
    log_i(f'size: {format_size(out_file_size)}')

    # Return the size of the newly created output file
    return out_file_size


def create_with_random_handler(out_file_size: int) -> bool:
    """
    Writes random data in chunks of a specified size to the output file.

    This function generates random data in specified chunk sizes and
    writes it to the output file. It reports progress at regular
    intervals.

    Args:
        out_file_size (int): The total size of data to be written in
                             bytes.

    Returns:
        bool: True if all data was written successfully, False
              otherwise.
    """

    # Set the 'file_handler_started' flag (used for handling signals)
    ANY_D['file_handler_started'] = None

    log_i('writing random data')

    # Start timing the operation
    FLOAT_D['start_time'] = monotonic()
    FLOAT_D['last_progress_time'] = monotonic()

    # Initialize the total written bytes counter
    INT_D['written_sum'] = 0

    INT_D['total_out_data_size'] = out_file_size

    # Calculate the number of complete chunks and remaining bytes to write
    full_chunks: int = out_file_size // MAX_PT_CHUNK_SIZE
    remain_size: int = out_file_size % MAX_PT_CHUNK_SIZE

    # Write complete chunks of random data
    for _ in range(full_chunks):
        # Generate a chunk of random data
        chunk: bytes = token_bytes(MAX_PT_CHUNK_SIZE)

        # Write the generated chunk to the output file
        if not write_data(chunk):
            return False

    # Write any remaining bytes that do not fit into a full chunk
    if remain_size:
        # Generate the last chunk of random data
        chunk = token_bytes(remain_size)

        if not write_data(chunk):
            return False

    log_progress_final()

    # Validate the total written size against the expected output size
    if INT_D['written_sum'] != out_file_size:
        written_sum: int = INT_D['written_sum']
        log_e(f'written data size ({written_sum:,} B) does not '
              f'equal expected size ({out_file_size:,} B)')
        return False

    return True


# Perform action OVERWRITE_W_RANDOM
# --------------------------------------------------------------------------- #


def overwrite_with_random(action: ActionID) -> bool:
    """
    Overwrites part of the output file with random data.

    This function takes an action ID as input, retrieves the
    corresponding start position and data size, and then overwrites the
    specified range of data with random bytes.

    Args:
        action (ActionID): The action identifier.

    Returns:
        bool: True if the overwrite operation is successful,
              False otherwise.
    """

    # Retrieve the start position and data size based on the action code
    input_values: Optional[tuple[int, int]] = \
        overwrite_with_random_input(action)

    # If no valid values are returned, the operation cannot proceed
    if input_values is None:
        return False

    # Unpack the start position and data size from the retrieved values
    start_pos: int = input_values[0]
    data_size: int = input_values[1]

    # Perform the overwrite operation with the specified
    # start position and data size
    success: bool = overwrite_with_random_handler(start_pos, data_size)

    return success


def overwrite_with_random_input(action: ActionID) -> Optional[tuple[int, int]]:
    """
    Prepares to overwrite a specified range of an output file with
    random data.

    This function retrieves the output file's path and size based on the
    provided action. It then determines the start and end positions for
    the overwrite operation. If the specified range is valid and the
    user confirms the action, it returns the start position and the size
    of the data to be written.

    Args:
        action (ActionID): An integer representing the action to be
                           performed, which influences the output file
                           retrieval process.

    Returns:
        Optional[tuple]: A tuple containing:
            - start_pos (int): The starting position for the overwrite
                               operation.
            - data_size (int): The size of the data to be written.
        Returns None if there is nothing to do, if the user cancels the
        operation, or if the output file size is zero.

    Notes:
        - The function logs various stages of the process, including the
          output file path, size, start and end positions, and the size
          of the data to be written.
        - The user is prompted for confirmation before proceeding with
          the overwrite operation.
    """
    out_file_path: str
    out_file_size: int

    # Retrieve the output file path and size based on the provided action
    out_file_path, out_file_size, BIO_D['OUT'] = get_output_file_exist(
        in_file_path='',
        min_out_size=0,
        action=action,
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

    # Prompt the user for confirmation before proceeding
    if not proceed_request(PROCEED_OVERWRITE, action):
        log_i('stopped by user request')
        return None  # Return None if the user cancels the operation

    # Return the starting position and the size of the data to be written
    return start_pos, data_size


def overwrite_with_random_handler(start_pos: int, data_size: int) -> bool:
    """
    Overwrites a specified range of an output file with random data.

    This function seeks to the specified start position in the output
    file and writes random data in chunks. It tracks the amount of data
    written and logs progress at regular intervals. After writing the
    data, it synchronizes the file to ensure that all changes are
    flushed to disk.

    Args:
        start_pos (int): The starting position in the output file where
                         the overwrite operation will begin.
        data_size (int): The total size of the data to be written,
                         in bytes.

    Returns:
        bool: Returns True if the overwrite operation is successful,
              or False if any errors occur during seeking, writing,
              or synchronization.

    Notes:
        - If the DEBUG flag is enabled, the function will print the
          current positions of the input and output streams before and
          after the write operation.
        - The function writes data in chunks defined by `MAX_PT_CHUNK_SIZE`
          and handles any remaining data that does not fit into a full
          chunk.
        - Progress is logged during the write operation, and the time
          taken to synchronize the file is also logged.
    """

    # Seek to the specified start position in the output file
    if not seek_position(BIO_D['OUT'], start_pos):
        return False  # Return False if seeking fails

    log_i('writing random data')

    # Start timing the operation
    FLOAT_D['start_time'] = monotonic()
    FLOAT_D['last_progress_time'] = monotonic()

    # Initialize the total written bytes counter
    INT_D['written_sum'] = 0

    INT_D['total_out_data_size'] = data_size

    # Calculate the number of complete chunks and remaining bytes to write
    full_chunks: int = data_size // MAX_PT_CHUNK_SIZE
    remain_size: int = data_size % MAX_PT_CHUNK_SIZE

    # Write complete chunks of random data
    for _ in range(full_chunks):
        # Generate a chunk of random data
        chunk: bytes = token_bytes(MAX_PT_CHUNK_SIZE)

        if not write_data(chunk):  # Write the chunk to the output file
            return False

    # Write any remaining bytes that do not fit into a full chunk
    if remain_size:
        # Generate the last chunk of random data
        chunk = token_bytes(remain_size)

        if not write_data(chunk):
            return False

    log_progress_final()

    # Validate the total written size against the expected output size
    if INT_D['written_sum'] != data_size:
        written_sum: int = INT_D['written_sum']
        log_e(f'written data size ({written_sum:,} B) does not '
              f'equal expected size ({data_size:,} B)')
        return False

    log_i('syncing output data to disk')

    fsync_start_time: float = monotonic()

    # Synchronize the file to ensure all changes are flushed to disk
    if not fsync_written_data():
        return False  # Return False if synchronization fails

    fsync_end_time: float = monotonic()

    # Log the time taken for fsync
    log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    return True


# Misc
# --------------------------------------------------------------------------- #


def perform_file_action(action: ActionID) -> None:
    """
    Execute a file-oriented action and perform cleanup.

    This sets a marker in module state to indicate a file action is in
    progress, dispatches the action handler from FILE_ACTION_MAP, and
    runs post-action cleanup.

    Behavior

    - Sets ANY_D['action'] = action to mark that a file operation is
      ongoing.
    - Calls FILE_ACTION_MAP[action] and captures its boolean success
      result.
    - Always invokes post_action_clean_up(action, success) after the
      handler returns.
    - Logs debug warnings when DEBUG is enabled and logs
      "action completed" on success.

    Args:
        action (ActionID): Action identifier (expected range matches
                           FILE_ACTION_MAP keys).

    Returns:
        None

    Notes:

    - The function relies on global state (ANY_D, DEBUG,
      FILE_ACTION_MAP, DEBUG_WARNINGS).
    - Handlers in FILE_ACTION_MAP are expected to return a bool
      indicating success.
    - post_action_clean_up is responsible for releasing resources and
      any final logging.
    """
    if DEBUG:
        for warning in DEBUG_WARNINGS:
            log_w(warning)

    ANY_D['action'] = action

    success: bool = FILE_ACTION_MAP[action](action)

    post_action_clean_up(action, success)

    if success:
        log_i('action completed')


def post_action_clean_up(action: ActionID, success: bool) -> None:
    """
    Perform resource cleanup and post-action housekeeping.

    Closes any open input/output file objects from BIO_D, removes a
    partially written output file when appropriate, clears module state
    dictionaries, and triggers garbage collection.

    Behavior

    - If BIO_D contains 'IN', closes that file.
    - If BIO_D contains 'OUT':
        - If success is True or the action is not one that creates a new
          output file (NEW_OUT_FILE_ACTIONS), closes the output file.
        - Otherwise (failed write/auth failure for a new output file),
          truncates the output and calls remove_output_path(action) to
          remove it.
    - Clears global state dictionaries: ANY_D, BIO_D, INT_D, BOOL_D,
      BYTES_D, FLOAT_D.
    - Calls collect() to run a garbage collection pass.

    Args:
        action (ActionID): The performed action (used to decide
                           output-file handling).
        success (bool): True if the action completed successfully;
                        False otherwise.

    Returns:
        None

    Side effects:

    - I/O: may close/truncate/remove files.
    - Mutates and clears global state.
    """
    check_for_signal()  # Check if a termination signal has been received

    if 'IN' in BIO_D:
        close_file(BIO_D['IN'])

    if 'OUT' in BIO_D:
        if success or action not in NEW_OUT_FILE_ACTIONS:
            close_file(BIO_D['OUT'])
        else:
            truncate_output_file()
            remove_output_path(action)

    ANY_D.clear()
    BIO_D.clear()
    INT_D.clear()
    BOOL_D.clear()
    BYTES_D.clear()
    FLOAT_D.clear()

    collect()


def cli_handler() -> bool:
    """
    Handles command line interface arguments to determine if debug mode
    is enabled.

    This function checks the command line arguments provided to the
    script (from sys.argv):
    - If no arguments are provided, debug mode is set to False.
    - If the first argument is '--unsafe-debug', it sets the debug mode
      to True.
    - If any other arguments are provided, an error is logged, and the
      program exits.

    Returns:
        bool: True if debug mode is enabled, False otherwise.
    """
    debug_enabled: bool

    if not argv[1:]:
        debug_enabled = False
    elif argv[1:] == ['--unsafe-debug']:
        debug_enabled = True
    else:
        log_e(f'invalid command line options: {argv[1:]}')
        exit(1)

    return debug_enabled


def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
    """
    Signal handler to request orderly termination while remaining
    signal-safe.

    Sets the module-level boolean flag termination_signal_received to
    True. The main thread should poll this flag at safe points, perform
    any non-signal-safe cleanup (flush/close/truncate files, release
    resources), and then exit.

    Behavior

    - If the handler is invoked a second time while
      termination_signal_received is already True, it returns
      immediately (no-op).
    - If ANY_D['file_handler_started'] exists, the handler only sets the
      flag and returns so the main thread can finish an in-progress file
      write and perform cleanup.
    - If no file handler is running, the handler writes a brief message
      ("Exit.") to file descriptor 2 using a signal-safe low-level write
      and then calls _exit(1) to terminate the process immediately.

    Safety and constraints

    - The handler performs only signal-safe operations: setting a simple
      global boolean and a single os.write on a safe file descriptor. It
      avoids high-level I/O, allocation, locking, and other non
      async-signal-safe APIs.
    - All non-signal-safe cleanup must be performed by the main thread
      after it observes termination_signal_received is True.
    - The handler tolerates os.write failures (ignores OSError) to avoid
      raising exceptions inside the signal context.

    Args:
        signum (int): Signal number delivered to the process.
        frame (Optional[FrameType]): Current stack frame (may be None).

    Side effects

    - Sets the global termination_signal_received to True on first
      invocation.
    - May call _exit(1) if no file handler is active.
    """
    global termination_signal_received

    if termination_signal_received:
        return

    # Main thread checks and performs cleanup/exit
    termination_signal_received = True

    if 'file_handler_started' in ANY_D:
        return

    try:
        write(2, b'\nExit.\n')
    except OSError:
        pass

    _exit(1)


def check_for_signal() -> None:
    """
    Check for a termination signal and perform safe cleanup/exit.

    If the module-level flag termination_signal_received (set by the
    signal handler) is True, this function performs cleanup for actions
    that write a new output file (ENCRYPT, DECRYPT, EXTRACT,
    EXTRACT_DECRYPT, CREATE_W_RANDOM). Cleanup includes calling flush(),
    attempting to truncate the output file to zero length (ftruncate)
    and closing it. After cleanup the function writes a short message to
    stderr (using a signal-safe os.write) and exits with status 1.

    Behavior and assumptions:

    - This must be called from the main thread at safe points (after
      critical I/O sections). The signal handler itself only sets the
      flag and returns.
    - All non-signal-safe operations (flush, ftruncate, close) are
      performed here, not in the signal handler.
    - OSError and ValueError raised during cleanup are suppressed to
      ensure the process still terminates.

    Example usage:
    # in main loop or immediately after finishing a write operation
    check_for_signal()
    """
    if not termination_signal_received:
        return

    # Clean up: truncate incomplete output
    if ANY_D['action'] in NEW_OUT_FILE_ACTIONS:
        if 'OUT' in BIO_D:
            try:
                BIO_D['OUT'].flush()
                ftruncate(BIO_D['OUT'].fileno(), 0)
                BIO_D['OUT'].close()
            except (OSError, ValueError):
                pass

    try:
        write(2, b'\nExit: action interrupted.\n')
    except OSError:
        pass

    exit(1)


def prevent_coredump() -> None:
    """
    Prevents the generation of core dumps by setting the core dump size
    limit to 0.

    This function uses the setrlimit system call to disable the core
    dump generation by setting both the soft and hard limits for
    RLIMIT_CORE to 0. This is useful in scenarios where creating a core
    dump could lead to unintentional exposure of sensitive information
    (e.g., cryptographic keys) in case of a process crash.

    Note:
        This function is intended for use on POSIX-compliant operating
        systems.
    """
    try:
        setrlimit(RLIMIT_CORE, (0, 0))
    except (OSError, ValueError) as error:
        if DEBUG:
            log_e(f'{error}')


def main() -> NoReturn:
    """
    Main entry point for the application.

    This function initializes the program, registers signal handlers for
    SIGINT, SIGQUIT, SIGTERM, and (on non-Windows platforms) SIGHUP, and then
    enters an infinite loop that repeatedly prompts the user to select
    an action and executes the corresponding operation. The loop runs
    until the user chooses the "exit" action.

    Returns:
        NoReturn: The function never returns; it terminates only when
                  the application exits explicitly.

    Note:
        The signal handlers allow the application to shut down cleanly
        when it receives SIGINT, SIGQUIT, SIGTERM, or SIGHUP, ensuring
        resources are released properly.
    """
    if DEBUG:
        for warning in DEBUG_WARNINGS:
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
            exit(0)
        elif action == INFO:
            info_and_warnings()
        else:
            perform_file_action(action)


# Define constants
# --------------------------------------------------------------------------- #


# Version of the application
APP_VERSION: Final[str] = '0.22.0'

# Information string for the application
APP_INFO: Final[str] = f"""tird v{APP_VERSION}
        A tool for encrypting files and hiding encrypted data.
        Homepage: https://github.com/hakavlad/tird"""

# Debug information string for the Python version
APP_DEBUG_INFO: Final[str] = f'Python version {version!r}'

# Warnings related to the application usage
APP_WARNINGS: Final[tuple[str, ...]] = (
    'The author does not have a background in cryptography.',
    'The code has no automated test coverage.',
    'tird has not been independently security audited by humans.',
    'tird is ineffective in a compromised environment; executing it in such '
    'cases may cause disastrous data leaks.',
    'tird is unlikely to be effective when used with short and predictable '
    'keys.',
    'tird does not erase its sensitive data from memory after use.',
    'Sensitive data may leak into swap space.',
    'tird does not sort digests of keyfiles and passphrases in constant-time.',
    'Overwriting file contents does not guarantee secure destruction of data '
    'on the media.',
    'You cannot prove to an adversary that your random data does not contain '
    'encrypted information.',
    'tird protects data, not the user; it cannot prevent torture if you are '
    'under suspicion.',
    'Key derivation consumes 1 GiB RAM, which may lead to performance issues '
    'or crashes on low-memory systems.',
    'Integrity/authenticity over availability — altering even a single byte '
    'of a cryptoblob prevents decryption',
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
A0. Select an option [0-9]:{RES} """


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

# Actions that creates new output file.
NEW_OUT_FILE_ACTIONS: Final[tuple[ActionID, ...]] = \
    (ENCRYPT, DECRYPT, EXTRACT, EXTRACT_DECRYPT, CREATE_W_RANDOM)

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
        embed file contents (no encryption):
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

# Define a type for functions that take an ActionID and return a boolean
ActionFunction = Callable[[ActionID], bool]

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


# Global dictionaries for various data types
# (constant references, mutable contents)
ANY_D: Final[dict[str, Any]] = {}
BIO_D: Final[dict[Literal['IN', 'OUT'], BinaryIO]] = {}
INT_D: Final[dict[str, int]] = {}
BOOL_D: Final[dict[str, bool]] = {}
BYTES_D: Final[dict[str, bytes]] = {}
FLOAT_D: Final[dict[str, float]] = {}

# Size constants for data representation
K: Final[int] = 2 ** 10  # KiB
M: Final[int] = 2 ** 20  # MiB
G: Final[int] = 2 ** 30  # GiB
T: Final[int] = 2 ** 40  # TiB
P: Final[int] = 2 ** 50  # PiB
E: Final[int] = 2 ** 60  # EiB

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
PROCESSED_COMMENTS_SIZE: Final[int] = K

# Invalid UTF-8 byte constant that separates comments from random data
# (UTF-8 strings cannot contain the byte 0xFF)
COMMENTS_SEPARATOR: Final[bytes] = b'\xff'

# Minimum interval for progress updates
MIN_PROGRESS_INTERVAL: Final[float] = 5.0

# Byte order for data representation
BYTEORDER: Final[Literal['big', 'little']] = 'little'

# Unicode normalization form for passphrases
UNICODE_NF: Final[Literal['NFC', 'NFD', 'NFKC', 'NFKD']] = 'NFC'

# Normalized and encoded passphrases will be truncated to this value
PASSPHRASE_SIZE_LIMIT: Final[int] = 2 * K  # 2048 B

# Maximum size limit for random output file
RAND_OUT_FILE_SIZE_LIMIT: Final[int] = 2 ** 64  # 16 EiB

# Salt constants for cryptographic operations
ONE_SALT_SIZE: Final[int] = 16
SALTS_SIZE: Final[int] = ONE_SALT_SIZE * 2

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
MAX_PT_CHUNK_SIZE: Final[int] = 16 * M  # 16 MiB, optimized for embedding

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
# Used to derive specific keys from the Argon2 tag
HKDF_INFO_ENCRYPT: Final[bytes] = b'ENCRYPT'
HKDF_INFO_PAD: Final[bytes] = b'PAD'
HKDF_INFO_MAC: Final[bytes] = b'MAC'

# Defines the byte size of the byte string that specifies
# the length of the data being passed to the MAC function.
SIZE_BYTES_SIZE: Final[int] = 8  # Supports sizes up to 2^64-1

# Padding constants
PAD_KEY_SIZE: Final[int] = 8
PAD_KEY_SPACE: Final[int] = 256 ** PAD_KEY_SIZE
MAX_PAD_SIZE_PERCENT: Final[int] = 25

# Argon2 constants
ARGON2_TAG_SIZE: Final[int] = 32
ARGON2_MEMORY_COST: Final[int] = G
DEFAULT_ARGON2_TIME_COST: Final[int] = 4
MIN_ARGON2_TIME_COST: Final[int] = DEFAULT_ARGON2_TIME_COST

# Minimum vilid cryptoblob size
MIN_VALID_UNPADDED_SIZE: Final[int] = \
    SALTS_SIZE + PAD_KEY_SIZE + PROCESSED_COMMENTS_SIZE + MAC_TAG_SIZE * 2

# Maximum valid cryptoblob size
MAX_VALID_PADDED_SIZE: Final[int] = 256 ** SIZE_BYTES_SIZE - 1

# Check if debug mode is enabled via command line arguments
DEBUG: Final[bool] = cli_handler()

DEBUG_WARNINGS: Final[list[str]] = [
    'debug mode enabled! Sensitive data will be exposed!',
    'do not enter real passphrases or sensitive information!',
]

MAC_FAIL_MESSAGE: Final[str] = \
    'decryption FAILED: invalid data or incorrect keys'

# Flag set by signal handler when a termination signal is received;
# main thread must check it and perform cleanup.
termination_signal_received: bool = False


# Start the application
# --------------------------------------------------------------------------- #


if __name__ == '__main__':
    main()
