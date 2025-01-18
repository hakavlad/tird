#!/usr/bin/env python3
"""
A tool for encrypting files and hiding encrypted data.

Dependencies:
- cryptography: for data encryption.
- PyNaCl: for hashing and authentication.

SPDX-License-Identifier: CC0-1.0
"""

from collections.abc import Callable
from gc import collect
from getpass import getpass
from os import SEEK_CUR, SEEK_END, SEEK_SET, fsync, path, remove, walk
from secrets import compare_digest, token_bytes
from signal import SIGINT, signal
from sys import argv, exit, platform, version
from time import monotonic
from types import FrameType
from typing import Any, BinaryIO, Final, Literal, NoReturn, Optional
from unicodedata import normalize

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from nacl.hashlib import blake2b
from nacl.pwhash import argon2id

# pylint: disable=consider-using-with
# pylint: disable=invalid-name
# pylint: disable=broad-exception-caught
# pylint: disable=broad-exception-raised
# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-many-lines
# pylint: disable=too-many-locals
# pylint: disable=too-many-positional-arguments
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-statements


# Define a type alias for action identifiers
ActionID = Literal[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]


# Formatting output messages and logging
# --------------------------------------------------------------------------- #


def log_e(error_message: str) -> None:
    """Logs a message at the Error level."""
    print(f'{ERR}E: {error_message}{RES}')


def log_w(warning_message: str) -> None:
    """Logs a message at the Warning level."""
    print(f'{WAR}W: {warning_message}{RES}')


def log_i(info_message: str) -> None:
    """Logs a message at the Info level."""
    print(f'I: {info_message}')


def log_d(debug_message: str) -> None:
    """Logs a message at the Debug level."""
    print(f'D: {debug_message}')


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


def log_progress(total_data_size: int) -> None:
    """
    Logs the progress of a data writing operation.

    This function calculates and logs the percentage of completion, the
    amount of data written, the elapsed time since the start of the
    operation, and the average writing speed in MiB/s. If no data has
    been written or if the total data size is zero, it logs a message
    indicating that 0 bytes have been written.

    Args:
        total_data_size (int): The total size of the data to be written,
                               in bytes. Must be a non-negative integer.
                               If this is zero, a message indicating
                               that 0 bytes have been written will be
                               logged.

    Returns:
        None

    Note:
        This function relies on global variables FLOAT_D and INT_D,
        where FLOAT_D['start_time'] is the start time of the operation
        and INT_D['written_sum'] is the total amount of data written
        so far.
    """

    # Check if the total data size is zero to avoid division by zero
    if not total_data_size:
        log_i('written 0 B')
        return

    # Calculate the elapsed time since the start of the operation
    elapsed_time: float = monotonic() - FLOAT_D['start_time']

    # Calculate the percentage of data written
    percentage: float = INT_D['written_sum'] / total_data_size * 100

    # Format the amount of data written for logging
    formatted_written: str = format_size(INT_D['written_sum'])

    if not elapsed_time:
        # Log progress without average speed if elapsed time is zero
        log_i(f'written {round(percentage, 1)}%; '
              f'{formatted_written} in 0.0s')
        return

    # Round the elapsed time to one decimal place for logging
    rounded_elapsed_time: float = round(elapsed_time, 1)

    # Calculate the average writing speed in MiB/s
    average_speed: float = round(INT_D['written_sum'] / M / elapsed_time, 1)

    # Log the detailed progress information
    log_i(f'written {round(percentage, 1)}%; '
          f'{formatted_written} in {rounded_elapsed_time:,}s; '
          f'avg {average_speed:,} MiB/s')


# Handle files and paths
# --------------------------------------------------------------------------- #


def open_file(
    file_path: str,
    access_mode: Literal['rb', 'rb+', 'wb'],
) -> Optional[BinaryIO]:
    """
    Opens a file in the specified mode and returns the file object.

    Args:
        file_path (str): The path to the file.
        access_mode (str): The mode in which to open the file.

    Returns:
        Optional[BinaryIO]: The file object if successful, None
                            otherwise.
    """
    if DEBUG:
        log_d(f'opening file {file_path!r} in mode {access_mode!r}')

    try:
        file_obj: BinaryIO = open(file_path, access_mode)

        if DEBUG:
            log_d(f'opened file (object): {file_obj}')

        return file_obj
    except Exception as error:
        log_e(f'{error}')
        return None


def close_file(file_obj: BinaryIO) -> None:
    """
    Closes the given file and logs the action if debugging is enabled.

    This function closes the file and prints debug information if the
    DEBUG flag is set.

    Args:
        file_obj (BinaryIO): The file object to close.
    """
    if DEBUG:
        log_d(f'closing {file_obj}')

    file_obj.close()

    if DEBUG and file_obj.closed:
        log_d(f'{file_obj} closed')


def get_file_size(file_path: str) -> Optional[int]:
    """
    Retrieve the size of a file in bytes.

    This function opens a file in binary read mode and seeks to the end
    of the file to determine its size. If the file cannot be opened or
    an error occurs, it returns None. This function is used instead of
    os.path.getsize() to also determine the size of block devices.

    Args:
        file_path (str): The path to the file whose size is to be
                         retrieved.

    Returns:
        Optional[int]: The size of the file in bytes if successful, None
                       otherwise.
    """
    try:
        with open(file_path, 'rb') as file_obj:
            # Move to the end of the file
            file_size: int = file_obj.seek(0, SEEK_END)
            return file_size
    except Exception as error:
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
        whence (int): The reference point for the offset. It can be one
            of the following:
            - SEEK_SET: Beginning of the file (default)
            - SEEK_CUR: Current file position

    Returns:
        bool: True if the seek operation was successful, False
              otherwise.
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
    Reads a specified number of bytes from a file.

    Attempts to read a given number of bytes from the provided file
    object.

    Args:
        file_obj (BinaryIO): File object to read from
                             (must be opened in read mode).
        data_size (int): Number of bytes to read.

    Returns:
        Optional[bytes]: Bytes read from the file, or None on error.
    """
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
    Writes bytes to the global output file.

    Attempts to write the provided bytes to the output file associated
    with the global `BIO_D['OUT']`.

    Args:
        data (bytes): Bytes to write.

    Returns:
        bool: True if written successfully, False otherwise.
    """
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


def remove_output_path() -> None:
    """
    Removes the output file path specified in the global `BIO_D`
    dictionary if the user confirms the action.

    This function checks if the user wants to proceed with removing the
    output file. If confirmed, it attempts to delete the file associated
    with the output stream in the global `BIO_D` dictionary. It logs the
    outcome of the operation, including any errors that may occur during
    the removal process.

    Returns:
        None
    """

    # Check if the user confirms the action to proceed with removal
    if proceed_request(PROCEED_REMOVE):
        # Get the name of the output file
        out_file_name: str = BIO_D['OUT'].name

        try:
            # Attempt to remove the output file path
            remove(out_file_name)
            log_i(f'path {out_file_name!r} removed')
        except Exception as error:
            log_e(f'{error}')
            log_w(f'failed to remove path {out_file_name!r}!')
    else:
        log_i('output file path NOT removed')


# Handle EOFError on user input
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


# Collect and handle user input
# --------------------------------------------------------------------------- #


def select_action() -> ActionID:
    """
    Prompts the user to select an action from a predefined menu.

    Displays the menu and descriptions for each action, using global
    ACTIONS dictionary. Returns the selected action ID if
    a valid option is chosen.

    Returns:
        ActionID: Selected action number (0-9).
    """
    while True:
        # Prompt the user to input an action number and remove any
        # leading/trailing whitespace
        user_input = no_eof_input(APP_MENU).strip()

        # Check if the entered action is valid
        if user_input in ACTIONS:
            # Get the description of the action
            action_description: str = ACTIONS[user_input][1]

            # Log the action description
            log_i(action_description)

            # Retrieve the action number associated with the user input
            action: ActionID = ACTIONS[user_input][0]

            return action  # Return the valid action number

        # If an invalid value is entered, log an error message
        log_e('invalid value; please select a valid option (0-9)')


def is_custom_settings() -> bool:
    """
    Prompts the user to specify whether to use custom settings.

    Asks the user if they want to use custom settings, using global
    formatting variables. Returns True for 'Y', 'y', or '1', and False
    for 'N', 'n', '0', or blank input.

    Returns:
        bool: True if custom settings are to be used, False otherwise.
    """

    # Define the prompt message with formatting variables
    prompt: str = f'{BOL}[10] Use custom settings? (Y/N, default=N):{RES} '

    # Start an infinite loop to get user input
    while True:
        # Get user input and remove any leading/trailing whitespace
        user_input: str = no_eof_input(prompt).strip()

        # Check if the input indicates not to use custom settings
        if user_input in DEFAULT_FALSE_BOOL_ANSWERS:
            # Return False if the user chooses not to use custom settings
            return False

        # Check if the input indicates to use custom settings
        if user_input in TRUE_BOOL_ANSWERS:
            # Return True if the user chooses to use custom settings
            return True

        log_e(f'invalid value; valid values are: {VALID_BOOL_ANSWERS}, '
              f'or press Enter for default (N)')


def get_argon2_time_cost() -> int:
    """
    Prompts the user to input the Argon2 time cost.

    Asks the user for the Argon2 time cost value, using global
    formatting variables. The function will continue to prompt the user
    until a valid integer is provided. Returns the default value if the
    user provides an empty input or the default value. Ensures the input
    is a valid integer within the specified range (1 to OPSLIMIT_MAX).

    Returns:
        int: The Argon2 time cost value provided by the user or the
             default.
    """
    while True:
        # Get user input and remove any leading/trailing whitespace
        user_input: str = no_eof_input(
            f'    {BOL}[11] Time cost (default'
            f'={DEFAULT_ARGON2_TIME_COST}):{RES} ').strip()

        # Return default value if input is empty or matches the default
        if user_input in ('', str(DEFAULT_ARGON2_TIME_COST)):
            return DEFAULT_ARGON2_TIME_COST

        try:
            # Convert input to integer
            time_cost_value: int = int(user_input)
        except ValueError:
            log_e(f'invalid value; must be an integer from '
                  f'the range [1; {argon2id.OPSLIMIT_MAX}]')
            continue

        # Check if the value is within the valid range
        if time_cost_value < 1 or time_cost_value > argon2id.OPSLIMIT_MAX:
            log_e(f'invalid value; must be an integer from '
                  f'the range [1; {argon2id.OPSLIMIT_MAX}]')
            continue

        return time_cost_value


def get_max_pad_size_percent() -> int:
    """
    Prompts the user to input the maximum padding size percentage.

    Asks the user for the maximum padding size as a percentage, using
    global formatting variables. The function will continue to prompt
    the user until a valid integer is provided. Returns the default
    value if the user provides an empty input or the default value.
    Ensures the input is a valid integer in the range
    [0; MAX_PAD_SIZE_PERCENT_LIMIT].

    Returns:
        int: The maximum padding size percentage provided by the user
             or the default.
    """
    while True:
        # Get user input and remove any leading/trailing whitespace
        user_input: str = no_eof_input(
            f'    {BOL}[12] Max padding size, % (default'
            f'={DEFAULT_MAX_PAD_SIZE_PERCENT}):{RES} ').strip()

        # Return default value if input is empty or matches the default
        if user_input in ('', str(DEFAULT_MAX_PAD_SIZE_PERCENT)):
            return DEFAULT_MAX_PAD_SIZE_PERCENT

        try:
            # Convert input to integer
            max_pad_size_percent: int = int(user_input)
        except ValueError:
            log_e(f'invalid value; must be an integer from the '
                  f'range [0; {MAX_PAD_SIZE_PERCENT_LIMIT}]')
            continue

        # Check if the value is within the valid range
        if (max_pad_size_percent < 0 or
                max_pad_size_percent > MAX_PAD_SIZE_PERCENT_LIMIT):
            log_e(f'invalid value; must be an integer from the '
                  f'range [0; {MAX_PAD_SIZE_PERCENT_LIMIT}]')
            continue

        return max_pad_size_percent


def is_fake_mac() -> bool:
    """
    Prompts the user to specify whether to set a fake MAC tag.

    Asks the user if they want to set a fake MAC tag, using global
    formatting variables. Returns True for 'Y', 'y', or '1', and False
    for 'N', 'n', '0', or blank input.

    Returns:
        bool: True if a fake MAC tag is to be set, False otherwise.
    """

    # Define the prompt message with formatting variables
    prompt: str = f'    {BOL}[13] Set fake MAC tag? (Y/N, default=N):{RES} '

    # Start an infinite loop to get user input
    while True:
        # Get user input and remove any leading/trailing whitespace
        user_input: str = no_eof_input(prompt).strip()

        # Check if the input indicates not to set a fake MAC tag
        if user_input in DEFAULT_FALSE_BOOL_ANSWERS:
            # Return False if the user chooses not to set a fake MAC tag
            return False

        # Check if the input indicates to set a fake MAC tag
        if user_input in TRUE_BOOL_ANSWERS:
            # Return True if the user chooses to set a fake MAC tag
            return True

        # Log an error message for invalid input
        log_e(f'invalid value; valid values are: {VALID_BOOL_ANSWERS}, '
              f'or press Enter for default (N)')


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
        ENCRYPT: 'File to encrypt',
        DECRYPT: 'File to decrypt',
        EMBED: 'File to embed',
        EXTRACT: 'Container',
        ENCRYPT_EMBED: 'File to encrypt and embed',
        EXTRACT_DECRYPT: 'Container',
    }

    # Get the prompt message based on the action provided
    prompt_message: Optional[str] = action_prompts.get(action)

    # Start an infinite loop to get a valid input file path
    while True:
        # Prompt the user for the input file path
        in_file_path: str = no_eof_input(f'{BOL}[21] {prompt_message}:{RES} ')

        # Check if the input file path is empty
        if not in_file_path:
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


def get_raw_comments() -> str:
    """
    Prompts the user for comments and returns the input.

    Returns:
        str: The comments entered by the user. May be an empty string.
    """
    return no_eof_input(f'{BOL}[22] Comments (optional, up to '
                        f'{PROCESSED_COMMENTS_SIZE} B):{RES} ')


def get_output_file_new(action: ActionID) -> tuple[str, BinaryIO]:
    """
    Prompts the user for a new output file path and creates the file.

    Determines the prompt based on the provided action, using global
    formatting variables. Prompts the user to enter the file path,
    validates the input, and returns the file path and file object.

    Args:
        action (ActionID): Action being performed (ENCRYPT, DECRYPT,
                           EXTRACT, EXTRACT_DECRYPT, or CREATE_W_RANDOM).

    Returns:
        tuple: Output file path and file object.
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
        out_file_path: str = no_eof_input(f'{BOL}[23] {prompt_message}:{RES} ')

        # Check if the input file path is empty
        if not out_file_path:
            log_e('output file path not specified')
            continue  # Prompt the user again

        # Check if the file already exists
        if path.exists(out_file_path):
            # Log an error message
            log_e(f'file {out_file_path!r} already exists')
            continue  # Prompt the user again

        # Log the real path if in DEBUG mode
        if DEBUG:
            log_d(f'real path: {path.realpath(out_file_path)!r}')

        # Attempt to open the output file in binary write mode
        out_file_obj: Optional[BinaryIO] = open_file(out_file_path, 'wb')

        # Check if the file object was created successfully
        if out_file_obj is not None:
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
        out_file_path: str = no_eof_input(f'{BOL}[23] {prompt_message}:{RES} ')

        # Check if the input file path is empty
        if not out_file_path:
            log_e('output file path not specified')
            continue

        # Check if the output file path is the same as the input file path
        if out_file_path == in_file_path:
            log_e('input and output files must not be at the same path')
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
            log_e(f'specified output file is too small ({out_file_size} B);'
                  f' size must be >= {min_out_size} B')
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
    converted to a non-negative integer. If the user enters an empty
    string, a negative value, or a non-integer value, the function logs
    an error message and prompts the user again. The valid range for the
    output file size is from 0 to RAND_OUT_FILE_SIZE_LIMIT.

    Returns:
        int: The output file size in bytes, as a non-negative integer.
    """

    # Define the prompt message for user input
    prompt_message: str = f'{BOL}[24] Output file size in bytes:{RES} '

    while True:
        # Get user input and remove any leading/trailing whitespace
        user_input: str = no_eof_input(prompt_message).strip()

        # Check if the user input is empty
        if not user_input:
            # Log error for empty input
            log_e('output file size not specified')
            continue

        try:
            # Attempt to convert the user input to an integer
            out_size = int(user_input)

            # Check if the value is within the valid range
            if out_size < 0 or out_size > RAND_OUT_FILE_SIZE_LIMIT:
                log_e(f'invalid value; must be an integer from '
                      f'the range [0; {RAND_OUT_FILE_SIZE_LIMIT}]')
                continue

            return out_size  # Return the valid output size
        except ValueError:
            # Log an error if the input cannot be converted to an integer
            log_e(f'invalid value; must be an integer from '
                  f'the range [0; {RAND_OUT_FILE_SIZE_LIMIT}]')
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
    while True:
        # Prompt the user for the start position and remove any
        # leading/trailing whitespace
        if no_default:
            user_input: str = no_eof_input(
                f'{BOL}[25] Start position [0; '
                f'{max_start_pos}]:{RES} ').strip()

            # Check if the input is empty
            if not user_input:
                log_e('start position not specified')
                continue
        else:
            user_input = no_eof_input(
                f'{BOL}[25] Start position [0; '
                f'{max_start_pos}], default=0:{RES} ').strip()

            # If input is empty, set default value to 0
            if not user_input:
                user_input = '0'

        # Try to convert the input to an integer
        try:
            start_pos: int = int(user_input)
        except ValueError:
            log_e(f'invalid value; must be an integer '
                  f'from the range [0; {max_start_pos}]')
            continue

        # Check if the start position is within the valid range
        if start_pos < 0 or start_pos > max_start_pos:
            log_e(f'invalid value; must be an integer '
                  f'from the range [0; {max_start_pos}]')
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
    while True:
        # Prompt the user for the end position and remove any
        # leading/trailing whitespace
        if no_default:
            user_input: str = no_eof_input(
                f'{BOL}[26] End position [{min_pos}; '
                f'{max_pos}]:{RES} ').strip()
        else:
            user_input = no_eof_input(
                f'{BOL}[26] End position [{min_pos}; '
                f'{max_pos}], default={max_pos}:{RES} ').strip()

            # If input is empty, set default value to max_pos
            if not user_input:
                user_input = str(max_pos)

        # Try to convert the input to an integer
        try:
            end_pos: int = int(user_input)
        except ValueError:
            log_e(f'invalid value; must be an integer from '
                  f'the range [{min_pos}; {max_pos}]')
            continue

        # Check if the end position is within the valid range
        if end_pos < min_pos or end_pos > max_pos:
            log_e(f'invalid value; must be an integer from '
                  f'the range [{min_pos}; {max_pos}]')
            continue

        # Return the valid end position
        return end_pos


def collect_and_handle_ikm() -> list[bytes]:
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

    Returns:
        list: A list of digests (bytes) corresponding to the accepted
              keyfiles and passphrases. The list may be empty if no
              valid keyfiles or passphrases were provided.
    """
    if DEBUG:
        log_d('collecting input keying material')

    # List to store the digests of keying material
    ikm_digest_list: list[bytes] = []

    # Handle keyfiles
    # ----------------------------------------------------------------------- #

    while True:
        # Prompt for the keyfile path
        keyfile_path: str = \
            no_eof_input(f'{BOL}[31] Keyfile path (optional):{RES} ')

        if not keyfile_path:
            # Exit the loop if the user does not enter a path
            break

        if not path.exists(keyfile_path):
            # Log error if the keyfile path does not exist
            log_e(f'file {keyfile_path!r} not found')
            log_e('keyfile NOT accepted')
            # Move to the next iteration of the loop
            continue

        if DEBUG:
            # Log the real path of the file
            log_d(f'real path: {path.realpath(keyfile_path)!r}')

        # ------------------------------------------------------------------- #

        if path.isdir(keyfile_path):
            # If the path is a directory, get the digests of all keyfiles
            # within it
            digest_list: Optional[list[bytes]] = \
                get_keyfile_digest_list(keyfile_path)

            if digest_list is None:
                # Log error if keyfiles are not accepted
                log_e('keyfiles NOT accepted')
                continue

            if not digest_list:
                # Warning if no files are found in the directory
                log_w('directory is empty; no keyfiles to accept!')
            else:
                # Add the digests to the main list
                ikm_digest_list.extend(digest_list)

                # Log the number of accepted files
                log_i(f'{len(digest_list)} keyfiles accepted')

                del keyfile_path, digest_list  # Clear variables
                collect()  # Garbage collection
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
            no_eof_getpass(f'{BOL}[32] Passphrase (optional):{RES} ')

        if not raw_passphrase_1:
            break  # Exit the loop if the user does not enter a passphrase

        # Normalize, encode, truncate
        encoded_passphrase_1: bytes = handle_raw_passphrase(raw_passphrase_1)

        # Prompt for confirming the passphrase
        raw_passphrase_2: str = \
            no_eof_getpass(f'{BOL}[32] Confirm passphrase:{RES} ')

        encoded_passphrase_2: bytes = handle_raw_passphrase(raw_passphrase_2)

        if compare_digest(encoded_passphrase_1, encoded_passphrase_2):
            # Get the digest of the passphrase
            passphrase_digest: bytes = \
                get_passphrase_digest(encoded_passphrase_1)

            # Add the digest to the list
            ikm_digest_list.append(passphrase_digest)

            # Log acceptance of the passphrase
            log_i('passphrase accepted')
        else:
            # Log error if confirmation fails
            log_e('passphrase NOT accepted: confirmation failed')

    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d(f'{len(ikm_digest_list)} IKM digests collected')

    # Check if any digests were retrieved and log a warning if not
    if not ikm_digest_list:
        log_w('no keyfile or passphrase specified!')

    if DEBUG:
        log_d('collecting input keying material completed')

    return ikm_digest_list


def proceed_request(proceed_type: Literal[1, 2]) -> bool:
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
        proceed_type (Literal[1, 2]): An integer value that determines
                                      the prompt message and default
                                      behavior.

    Returns:
        bool: True if the user confirms to proceed, False otherwise.
    """

    # Check the action type to determine the appropriate prompt message
    if proceed_type == PROCEED_OVERWRITE:
        log_w('output file contents will be partially overwritten!')

        prompt_message: str = f'{BOL}[40] Proceed? (Y/N):{RES} '
    else:
        log_i('removing output file path')

        prompt_message = f'{BOL}[40] Proceed? (Y/N, default=Y):{RES} '

    while True:
        # Get user input and remove any leading/trailing whitespace
        user_input: str = no_eof_input(prompt_message).strip()

        # Check if the user wants to proceed (affirmative response)
        if user_input in TRUE_BOOL_ANSWERS:
            return True

        # If no input is given and proceed_type is PROCEED_REMOVE,
        # default to proceeding
        if not user_input and proceed_type == PROCEED_REMOVE:
            return True

        # Check if the user wants to cancel (negative response)
        if user_input in FALSE_BOOL_ANSWERS:
            return False

        # Log an error message for invalid input
        if proceed_type == PROCEED_OVERWRITE:
            log_e(f'invalid value; valid values are: {VALID_BOOL_ANSWERS}')
        else:
            log_e(f'invalid value; valid values are: {VALID_BOOL_ANSWERS}, '
                  f'or press Enter for default (Y)')


# Handle Comments
# --------------------------------------------------------------------------- #


def get_processed_comments() -> bytes:
    """
    Retrieve and process user comments according to specified rules.

    This function requests raw comments from the user and processes them
    to generate a standardized byte representation. The processing rules
    are as follows:

    - If the raw comments are empty, the function generates random bytes
      of size PROCESSED_COMMENTS_SIZE.
    - If the raw comments are not empty and their length is less than or
      equal to PROCESSED_COMMENTS_SIZE, a special separator byte is
      appended, and the remaining space is filled with random bytes to
      reach the specified size.
    - If the raw comments exceed PROCESSED_COMMENTS_SIZE, they are
      truncated to fit within the size limit after encoding.

    Processed comments of a fixed length are required for subsequent
    encryption, as they form part of the plaintext.

    Returns:
        bytes: A byte representation of the processed comments, ensuring
        compliance with the specified size.
    """
    raw_comments: str = get_raw_comments()
    raw_comments_bytes: bytes = raw_comments.encode('utf-8')
    raw_comments_size: int = len(raw_comments_bytes)

    if raw_comments_size:
        if raw_comments_size > PROCESSED_COMMENTS_SIZE:
            log_w(f'comments size: {raw_comments_size} B; '
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
    else:
        # If there are no raw comments, handle based on the fake MAC option
        if BOOL_D['set_fake_mac']:
            # Just generate random bytes if the fake MAC option is enabled
            processed_comments = token_bytes(PROCESSED_COMMENTS_SIZE)
        else:
            # Continuously generate random bytes until a valid comment is
            # obtained. This ensures that the generated bytes do not decode
            # into a meaningful UTF-8 string.
            while True:
                processed_comments = token_bytes(PROCESSED_COMMENTS_SIZE)

                # If calculated MAC tag set (not fake MAC tag), then
                # processed comments must be decoded to None
                if decode_processed_comments(processed_comments) is None:
                    # Approximately 99.164% chance of success
                    # if PROCESSED_COMMENTS_SIZE=512
                    break

    if DEBUG:
        log_d(f'raw_comments: {[raw_comments]}, size: {raw_comments_size} B')
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


# Handle salts, IKM, and derive keys
# --------------------------------------------------------------------------- #


def get_salts(input_size: int, end_pos: int, action: ActionID) -> bool:
    """
    Retrieves and generates salts for cryptographic operations based
    on the specified action.

    Depending on the action provided, the function either generates
    new salts or reads existing salts from a cryptoblob. For actions
    ENCRYPT and ENCRYPT_EMBED, new salts are generated using random
    bytes. For actions DECRYPT and EXTRACT_DECRYPT, the function reads
    salts from the beginning and end of the cryptoblob. The retrieved
    or generated salts are stored in the global dictionary `BYTES_D`.

    Args:
        input_size (int): The size of the input data, used to determine
                          positions for reading salts.
        end_pos (int): The end position in the cryptoblob, used for
                       calculating blake2_salt position.
        action (ActionID): The action that determines how salts are
                           handled. Actions ENCRYPT and ENCRYPT_EMBED
                           generate new salts, while actions DECRYPT and
                           EXTRACT_DECRYPT read existing salts.

    Returns:
        bool: True if salts were successfully retrieved or generated,
              False otherwise. If False is returned, it indicates a
              failure in reading salts or seeking positions in the
              cryptoblob.
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
        if DEBUG:
            log_d('reading argon2_salt from the start of the cryptoblob')

        read_data_result: Optional[bytes] = read_data(
            BIO_D['IN'], ONE_SALT_SIZE)

        # Return False if reading argon2_salt fails
        if read_data_result is None:
            return False

        # Store argon2_salt
        argon2_salt = read_data_result

        # Log that the argon2_salt has been read if debugging is enabled
        if DEBUG:
            log_d('argon2_salt read')

        # Save the current position in the cryptoblob
        pos_after_argon2_salt: int = BIO_D['IN'].tell()

        # Determine the new position based on the action
        if action == DECRYPT:
            pos_before_blake2_salt: int = input_size - ONE_SALT_SIZE
        else:  # action == EXTRACT_DECRYPT
            pos_before_blake2_salt = end_pos - ONE_SALT_SIZE

        # Move to the position for reading blake2_salt
        if not seek_position(BIO_D['IN'], pos_before_blake2_salt):
            return False

        if DEBUG:
            log_d('reading blake2_salt from the end of the cryptoblob')

        # Read blake2_salt from the cryptoblob
        read_data_result = read_data(BIO_D['IN'], ONE_SALT_SIZE)

        # Return False if reading blake2_salt fails
        if read_data_result is None:
            return False

        # Store blake2_salt
        blake2_salt = read_data_result

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
              f'    argon2_salt:  {argon2_salt.hex()}\n'
              f'    blake2_salt:  {blake2_salt.hex()}')
        log_d('getting salts completed')

    return True


def hash_keyfile_contents(
    file_obj: BinaryIO,
    file_size: int,
) -> Optional[bytes]:
    """
    Computes the BLAKE2 digest of the contents of a keyfile.

    This function reads the contents of the provided file-like object in
    chunks and updates the BLAKE2 hash object with the data read. The
    final digest is returned as a byte string. The file should be opened
    in binary mode.

    Args:
        file_obj (BinaryIO): A file-like object to read data from,
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
    num_complete_chunks: int = file_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = file_size % RW_CHUNK_SIZE

    # Read and process each complete chunk of the file
    for _ in range(num_complete_chunks):
        # Read a chunk of data from the file
        chunk_data: Optional[bytes] = read_data(file_obj, RW_CHUNK_SIZE)

        # If reading the chunk fails, return None
        if chunk_data is None:
            return None

        # Update the hash object with the data from the chunk
        hash_obj.update(chunk_data)

    # If there are remaining bytes, read and process them
    if num_remaining_bytes:
        # Read the remaining bytes from the file
        chunk_data = read_data(file_obj, num_remaining_bytes)

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
    Calculates the BLAKE2 digest of the keyfile at the given file path.

    Args:
        file_path (str): The path to the keyfile.

    Returns:
        Optional[bytes]: The BLAKE2 digest of the keyfile, or None if
                         an error occurs.
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

    # Calculate the BLAKE2 digest of the keyfile
    file_digest: Optional[bytes] = hash_keyfile_contents(file_obj, file_size)

    # Close the file after reading
    close_file(file_obj)

    # If the digest could not be computed, return None
    if file_digest is None:
        return None

    if DEBUG:
        log_d(f'digest of {file_path!r} contents:\n    {file_digest.hex()}')

    return file_digest


def get_keyfile_digest_list(directory_path: str) -> Optional[list[bytes]]:
    """
    Scans the specified directory for keyfiles and computes their
    digests.

    This function traverses the directory at the given path, collects
    the paths of all files, and computes their digests using the
    `hash_keyfile_contents` function. It logs the process and handles
    any errors that occur during file access.

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
        raise Exception

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
    except Exception:
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
        file_info_list.append(file_info)

    log_i('list of these files:')

    # Log the details of each found file
    for file_info in file_info_list:
        full_file_path, file_size = file_info
        log_i(f'\r  '
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
                  f'    {file_digest.hex()}')

        # Add the computed digest to the list
        digest_list.append(file_digest)

    # Return the list of computed digests
    return digest_list


def handle_raw_passphrase(raw_passphrase: str) -> bytes:
    """
    Normalize and encode a raw passphrase, truncating it to a
    specified size limit.

    This function takes a raw passphrase as input, normalizes it
    using Unicode Normalization Form, encodes it to bytes using a
    specified encoding, and truncates the result to a defined size
    limit.

    Args:
        raw_passphrase (str): The raw passphrase input as a string.

    Returns:
        bytes: The encoded and truncated passphrase as a byte sequence.
    """

    # Normalize the raw passphrase using Unicode Normalization Form
    normalized_passphrase: str = normalize(UNICODE_NF, raw_passphrase)

    # Encode the normalized passphrase to bytes and truncate to the size limit
    encoded_passphrase: bytes = \
        normalized_passphrase.encode('utf-8')[:PASSPHRASE_SIZE_LIMIT]

    # Log details if debugging is enabled
    if DEBUG:
        log_d(f'passphrase (raw):\n'
              f'    {raw_passphrase!r}')
        raw_pp_len: int = len(raw_passphrase.encode('utf-8'))
        log_d(f'length: {raw_pp_len} B')

        log_d(f'passphrase (normalized):\n'
              f'    {normalized_passphrase!r}')
        normalized_pp_len: int = len(normalized_passphrase.encode('utf-8'))
        log_d(f'length: {normalized_pp_len} B')

        log_d(f'passphrase (normalized, encoded, truncated):\n'
              f'    {encoded_passphrase!r}')
        log_d(f'length: {len(encoded_passphrase)} B')

    return encoded_passphrase


def get_passphrase_digest(passphrase: bytes) -> bytes:
    """
    Computes the BLAKE2 digest of the provided passphrase.

    This function takes a passphrase in bytes, updates the BLAKE2 hash
    object with the passphrase, and returns the resulting digest. The
    digest is computed using a specific salt and personalization string.

    Args:
        passphrase (bytes): The passphrase to be hashed, provided as
                            a byte string.

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
        log_d(f'passphrase digest:\n    {digest.hex()}')

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
    if not digest_list:  # Check if the list is empty
        if DEBUG:
            log_d('digest list is empty, nothing to sort')

        return digest_list  # Return the empty list immediately

    if DEBUG:
        log_d('sorting digests of keying material')

    # Sort the digest list in place
    digest_list.sort()

    # Log sorted digests if debugging is enabled
    if DEBUG:
        log_d('sorted digests of keying material:')
        for digest in digest_list:
            log_d(f'\r  - {digest.hex()}')

    return digest_list


def hash_digest_list(digest_list: list[bytes]) -> bytes:
    """
    Computes a hash digest for a list of byte sequences using the
    BLAKE2 hashing algorithm.

    Args:
        digest_list (list[bytes]): A list of byte sequences to be hashed.

    Returns:
        bytes: The resulting hash digest as a byte sequence.
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


def get_argon2_password() -> None:
    """
    Computes the Argon2 password from the input keying material.

    This function retrieves a list of keying material digests using the
    `collect_and_handle_ikm` function. It logs the completion of the
    keying material entry process and checks if any digests were
    retrieved. If no digests are available, a warning is logged.

    The function sorts the digest list and computes the Argon2 password
    using the BLAKE2 hash function. The resulting digest is stored
    in the global `BYTES_D` dictionary under the key 'argon2_password'.

    Debug information is logged throughout the process if the DEBUG flag
    is set, including the sorted digests and the final Argon2 password
    digest.

    Returns:
        None
    """
    digest_list: list[bytes] = collect_and_handle_ikm()

    sorted_digest_list: list[bytes] = sort_digest_list(digest_list)

    argon2_password: bytes = hash_digest_list(sorted_digest_list)

    if DEBUG:
        log_d(f'argon2_password:\n    {argon2_password.hex()}')

    BYTES_D['argon2_password'] = argon2_password


def derive_keys() -> bool:
    """
    Derives cryptographic keys using the Argon2 Memory-Hard Function.

    This function computes the encryption, padding, and MAC keys from
    the Argon2 password stored in the global `BYTES_D` dictionary. It
    uses the Argon2 key derivation function with specified parameters
    such as salt, time cost, and memory limit. After deriving the Argon2
    tag, it is passed to the `split_argon2_tag()` function for further
    processing.

    The function logs the process, including the time taken to derive
    the keys and the values of the derived keys if the DEBUG flag is
    enabled.

    Returns:
        bool: True if the keys were successfully derived, False if an
              error occurred during the key derivation process.
    """
    log_i('deriving one-time keys')

    start_time: float = monotonic()

    try:
        argon2_tag: bytes = argon2id.kdf(
            size=ARGON2_TAG_SIZE,
            password=BYTES_D['argon2_password'],
            salt=BYTES_D['argon2_salt'],
            opslimit=INT_D['argon2_time_cost'],
            memlimit=ARGON2_MEM,
        )
    except RuntimeError as error:
        log_e(f'{error}')
        return False

    split_argon2_tag(argon2_tag)

    end_time: float = monotonic()

    log_i(f'keys derived in {round(end_time - start_time, 1)}s')

    return True


def split_argon2_tag(argon2_tag: bytes) -> None:
    """
    Extracts and stores cryptographic keys from the provided Argon2 tag.

    This function takes an Argon2 tag, which contains multiple
    cryptographic keys, and splits it into its constituent parts. The
    keys include padding keys, an encryption key, and a MAC key. The
    extracted keys are then stored in the global `BYTES_D` dictionary
    for later use in cryptographic operations.

    The expected structure of the Argon2 tag is as follows:

    +————————————————+———————————————+————————————————+
    |                | pad_key_t:16  | Secret values  |
    |                +———————————————+ that define    |
    |                | pad_key_hf:16 | padding sizes  |
    | argon2_tag:128 +———————————————+————————————————+
    |                | enc_key:32    | Encryption key |
    |                +———————————————+————————————————+
    |                | mac_key:64    | MAC key        |
    +————————————————+———————————————+————————————————+

    Args:
        argon2_tag (bytes): The Argon2 tag containing the keys to be
                            extracted. This should be provided as a byte
                            string.

    Returns:
        None

    Note:
        The function logs the positions of the keys and their values if
        debugging is enabled, which can be useful for troubleshooting
        and verification.
    """

    # Log the raw Argon2 tag in hexadecimal format if debugging is enabled
    if DEBUG:
        log_d(f'argon2_tag (size: {len(argon2_tag)} B):\n'
              f'    {argon2_tag.hex()}')
        log_d('splitting argon2_tag into separate keys')

    # Define the start and end positions for each key in the Argon2 tag
    pad_key_t_start_pos: int = 0
    pad_key_t_end_pos: int = pad_key_t_start_pos + PAD_KEY_SIZE

    pad_key_hf_start_pos: int = pad_key_t_end_pos
    pad_key_hf_end_pos: int = pad_key_hf_start_pos + PAD_KEY_SIZE

    enc_key_start_pos: int = pad_key_hf_end_pos
    enc_key_end_pos: int = enc_key_start_pos + ENC_KEY_SIZE

    mac_key_start_pos: int = enc_key_end_pos
    mac_key_end_pos: int = mac_key_start_pos + MAC_KEY_SIZE

    # Extract the keys from the Argon2 tag using the defined positions
    pad_key_t: bytes = argon2_tag[
        pad_key_t_start_pos:pad_key_t_end_pos
    ]
    pad_key_hf: bytes = argon2_tag[
        pad_key_hf_start_pos:pad_key_hf_end_pos
    ]
    enc_key: bytes = argon2_tag[
        enc_key_start_pos:enc_key_end_pos
    ]
    mac_key: bytes = argon2_tag[
        mac_key_start_pos:mac_key_end_pos
    ]

    # Store the derived keys back into the global `BYTES_D` dictionary
    BYTES_D['pad_key_t'] = pad_key_t
    BYTES_D['pad_key_hf'] = pad_key_hf
    BYTES_D['enc_key'] = enc_key
    BYTES_D['mac_key'] = mac_key

    if DEBUG:
        log_d(f'positions of the keys in argon2_tag:\n'
              f'    pad_key_t:   {pad_key_t_start_pos}:{pad_key_t_end_pos}'
              f'    (size: {len(pad_key_t)} B)\n'
              f'    pad_key_hf:  {pad_key_hf_start_pos}:{pad_key_hf_end_pos}'
              f'   (size: {len(pad_key_hf)} B)\n'
              f'    enc_key:     {enc_key_start_pos}:{enc_key_end_pos}'
              f'   (size: {len(enc_key)} B)\n'
              f'    mac_key:     {mac_key_start_pos}:{mac_key_end_pos}'
              f'  (size: {len(mac_key)} B)')
        log_d(f'derived keys:\n'
              f'    pad_key_t:   {pad_key_t.hex()}\n'
              f'    pad_key_hf:  {pad_key_hf.hex()}\n'
              f'    enc_key:     {enc_key.hex()}\n'
              f'    mac_key:     {mac_key.hex()}')


# Handle padding
# --------------------------------------------------------------------------- #


def get_pad_size_from_unpadded(
    unpadded_size: int,
    pad_key_t: bytes,
    max_pad_size_percent: int,
) -> int:
    """
    Calculates the total padding size based on the unpadded size and a
    padding key.

    This function computes the total padding size to be applied to the
    unpadded size based on the provided parameters. The padding size is
    determined by the size of the unpadded size, a padding key converted
    from bytes to an integer, and a maximum padding size percentage.

    The relationship between the unpadded size and the total padding
    size is defined as follows:

    +———————————————+————————————————+
    | unpadded_size | total_pad_size |
    +———————————————+————————————————+
    |         padded_size            |
    +————————————————————————————————+

    `padded_size` represents the total size of the cryptoblob.

    Args:
        unpadded_size (int): The size of the unpadded data in bytes.
            This value is used to calculate the total padding size.

        pad_key_t (bytes): A byte string that influences the overall
            padding size. This key is converted to an integer to affect
            the padding size calculation.

        max_pad_size_percent (int): The maximum percentage of the
            unpadded size that can be used for padding. This value
            must not be negative.

    Returns:
        int: The calculated padding size in bytes.
    """

    # Convert the padding key from bytes to an integer
    pad_key_t_int: int = int.from_bytes(pad_key_t, BYTEORDER)

    # Calculate the padding size based on the unpadded size,
    # pad_key_t, and max padding percentage
    total_pad_size: int = (
        unpadded_size * pad_key_t_int * max_pad_size_percent //
        (PAD_KEY_SPACE * 100)
    )

    # If debugging is enabled, log detailed information
    # about the padding calculation
    if DEBUG:
        max_total_pad_size: int = (unpadded_size * max_pad_size_percent) // 100

        if max_total_pad_size:
            percent_of_max_total: float = \
                (total_pad_size * 100) / max_total_pad_size

        percent_of_unpadded: float = (total_pad_size * 100) / unpadded_size
        padded_size: int = unpadded_size + total_pad_size

        log_d('getting total_pad_size')
        log_d(f'pad_key_t_int:                {pad_key_t_int}')
        log_d(f'pad_key_t_int/PAD_KEY_SPACE:  '
              f'{pad_key_t_int / PAD_KEY_SPACE}')
        log_d(f'unpadded_size:       {format_size(unpadded_size)}')
        log_d(f'max_total_pad_size:  {format_size(max_total_pad_size)}')

        if max_total_pad_size:
            log_d(f'total_pad_size:      {format_size(total_pad_size)}, '
                  f'{round(percent_of_unpadded, 1)}% of unpadded_size, '
                  f'{round(percent_of_max_total, 1)}% of max_total_pad_size')
        else:
            log_d(f'total_pad_size:      {format_size(total_pad_size)}, '
                  f'{round(percent_of_unpadded, 1)}% of unpadded_size')

        log_d(f'padded_size:         {format_size(padded_size)}')

    return total_pad_size


def get_pad_size_from_padded(
    padded_size: int,
    pad_key_t: bytes,
    max_pad_size_percent: int,
) -> int:
    """
    Calculates the total padding size based on the padded size and the
    padding key.

    This function computes the total padding size that was applied to
    the unpadded size using the specified padding key and maximum
    padding percentage. The total padding size is derived from the
    padded size and the integer value of the padding key.

    Args:
        padded_size (int): The size of the padded data in bytes. This
            parameter represents the total size of the cryptoblob and is
            used to calculate the total padding size.

        pad_key_t (bytes): A byte string representing a padding key.
            This key is converted to an integer to influence the padding
            size calculation.

        max_pad_size_percent (int): The maximum percentage of the
            unpadded size that can be allocated for padding. This value
            must not be negative.

    Returns:
        int: The calculated padding size in bytes.
    """

    # Convert the padding key from bytes to an integer
    pad_key_t_int: int = int.from_bytes(pad_key_t, BYTEORDER)

    # Calculate the padding size based on the padded size, padding key,
    # and maximum padding percentage
    total_pad_size: int = (
        padded_size * pad_key_t_int * max_pad_size_percent //
        (pad_key_t_int * max_pad_size_percent + PAD_KEY_SPACE * 100)
    )

    # If debugging is enabled, log detailed information about
    # the padding calculation
    if DEBUG:
        unpadded_size: int = padded_size - total_pad_size
        percent_of_unpadded: float = (total_pad_size * 100) / unpadded_size

        log_d('getting total_pad_size')
        log_d(f'pad_key_t_int:                {pad_key_t_int}')
        log_d(f'pad_key_t_int/PAD_KEY_SPACE:  '
              f'{pad_key_t_int / PAD_KEY_SPACE}')
        log_d(f'padded_size:     {format_size(padded_size)}')
        log_d(f'total_pad_size:  {format_size(total_pad_size)}, '
              f'{round(percent_of_unpadded, 1)}% of unpadded_size')
        log_d(f'unpadded_size:   {format_size(unpadded_size)}')

    return total_pad_size


def get_header_footer_pad_sizes(
    total_pad_size: int,
    pad_key_hf: bytes,
) -> tuple[int, int]:
    """
    Calculates the sizes of the header and footer pads based on the
    given total padding size and key.

    The sizes of the header and footer pads are derived from the total
    pad size and the integer value of the padding key. The header pad
    size is calculated using the modulus operation, and the footer pad
    size is determined by subtracting the header pad size from the
    total pad size.

    +—————————————————+—————————————————+
    | header_pad_size | footer_pad_size |
    +—————————————————+—————————————————+
    |          total_pad_size           |
    +———————————————————————————————————+

    Args:
        total_pad_size (int): The total size of the pad to be used for
            calculating the header and footer pad sizes. This value
            must be a positive integer.
        pad_key_hf (bytes): The key in byte format that will be
            converted to an integer for pad size calculations. The
            length of this byte key should be appropriate for the
            intended use.

    Returns:
        tuple[int, int]: A tuple containing two values:
            - header_pad_size (int): The size of the header pad in bytes.
            - footer_pad_size (int): The size of the footer pad in bytes.

    Note:
        The sizes of the pads are calculated based on the remainder of
        the integer obtained from the byte key divided by
        (total_pad_size + 1).
    """

    # Convert the padding key from bytes to an integer
    pad_key_hf_int: int = int.from_bytes(pad_key_hf, BYTEORDER)

    # Calculate the size of the header pad using the modulus operation
    header_pad_size: int = pad_key_hf_int % (total_pad_size + 1)

    # Calculate the size of the footer pad by subtracting the header pad
    # size from the total pad size
    footer_pad_size: int = total_pad_size - header_pad_size

    # If debugging is enabled, log detailed information about the padding sizes
    if DEBUG:
        log_d('getting header_pad_size and footer_pad_size')
        log_d(f'pad_key_hf_int:   {pad_key_hf_int}')

        if total_pad_size:
            header_percent: float = (header_pad_size * 100) / total_pad_size
            footer_percent: float = (footer_pad_size * 100) / total_pad_size

            log_d(f'header_pad_size:  {format_size(header_pad_size)}, '
                  f'{round(header_percent, 1)}% of total_pad_size')
            log_d(f'footer_pad_size:  {format_size(footer_pad_size)}, '
                  f'{round(footer_percent, 1)}% of total_pad_size')
        else:
            log_d(f'header_pad_size:  {format_size(header_pad_size)}')
            log_d(f'footer_pad_size:  {format_size(footer_pad_size)}')

    # Return the sizes of the header and footer pads as a tuple
    return header_pad_size, footer_pad_size


def handle_padding(
    pad_size: int,
    action: ActionID,
    output_data_size: int,
) -> bool:
    """
    Handles padding operations based on the specified action.

    This function performs different operations depending on the value
    of `action`. If the action is ENCRYPT or ENCRYPT_EMBED, it writes
    random data chunks of size `RW_CHUNK_SIZE` to a target until the
    given pad size is reached. If the action is DECRYPT or
    EXTRACT_DECRYPT, it seeks to a specified position in the data.

    Args:
        pad_size (int): The total size of the padding to be handled.
        action (ActionID): The action to be performed (ENCRYPT or
            ENCRYPT_EMBED for writing data, DECRYPT or EXTRACT_DECRYPT
            for seeking).
        output_data_size (int): The total size of the output data, used
            for progress calculation.

    Returns:
        bool: True if the operation was successful, False otherwise.

    Notes:
        - The function uses `token_bytes` to generate random data
          chunks.
        - Progress is printed at intervals defined by
          `MIN_PROGRESS_INTERVAL`.
        - This function relies on global variables INT_D, FLOAT_D,
          and BIO_D, where INT_D['written_sum'] tracks the amount of
          data written, FLOAT_D['last_progress_time'] is used for
          progress tracking, and BIO_D['IN'] is the input stream for
          seeking.
    """

    # Check if the action is to write data
    if action in (ENCRYPT, ENCRYPT_EMBED):
        # Calculate the number of complete chunks and remaining bytes to write
        num_complete_chunks: int = pad_size // RW_CHUNK_SIZE
        num_remaining_bytes: int = pad_size % RW_CHUNK_SIZE

        # Write the full chunks of random data
        for _ in range(num_complete_chunks):

            # Generate a random data chunk of size RW_CHUNK_SIZE
            chunk: bytes = token_bytes(RW_CHUNK_SIZE)

            # Attempt to write the chunk; return None if it fails
            if not write_data(chunk):
                return False

            # Update the cumulative size of written data
            INT_D['written_sum'] += len(chunk)

            # Check if it's time to print progress
            if monotonic() - \
                    FLOAT_D['last_progress_time'] >= MIN_PROGRESS_INTERVAL:

                # Print the progress of the operation
                log_progress(output_data_size)

                # Update the last progress time
                FLOAT_D['last_progress_time'] = monotonic()

        # If there is remaining data to write, handle it
        if num_remaining_bytes:

            # Generate a random data chunk of the remaining size
            chunk = token_bytes(num_remaining_bytes)

            # Attempt to write the remaining chunk; return None if it fails
            if not write_data(chunk):
                return False

            # Update the cumulative size of written data
            INT_D['written_sum'] += len(chunk)

            # Check if it's time to print progress again
            if monotonic() - \
                    FLOAT_D['last_progress_time'] >= MIN_PROGRESS_INTERVAL:

                # Print the progress of the operation
                log_progress(output_data_size)

                # Update the last progress time
                FLOAT_D['last_progress_time'] = monotonic()

    else:  # If the action is to seek (DECRYPT or EXTRACT_DECRYPT)
        # Attempt to seek to the specified position; return None if it fails
        if not seek_position(BIO_D['IN'], pad_size, SEEK_CUR):
            return False

    return True


# Perform encryption and decryption
# --------------------------------------------------------------------------- #


def init_nonce_counter() -> None:
    """
    Initialize the nonce counter for the ChaCha20 encryption algorithm.

    This function sets the nonce counter to its initial value (0)
    to prepare for encryption operations. The nonce counter is
    crucial for ensuring the uniqueness of the nonce in the
    ChaCha20 algorithm, which helps to prevent key and nonce reuse
    and maintain the security of the encryption process.

    This function can be called multiple times, and each time
    it will reset the nonce counter to 0.

    If the DEBUG flag is enabled, the initialization of the nonce
    counter will be logged for debugging purposes.

    Returns:
        None
    """
    init_value = 0

    INT_D['nonce_counter'] = init_value

    if DEBUG:
        log_d(f'nonce counter initialized to {init_value}')


def get_incremented_nonce() -> bytes:
    """
    Get the incremented nonce value for the ChaCha20 encryption
    algorithm.

    This function increments the current nonce counter stored in the
    INT_D dictionary and returns the incremented nonce as a byte
    sequence. The nonce is crucial for ensuring the uniqueness of the
    nonce in the ChaCha20 algorithm, which helps to prevent key and
    nonce reuse and maintain the security of the encryption process.

    The nonce counter is incremented by 1 each time this function is
    called. If the DEBUG flag is enabled, the incrementing of the nonce
    counter will be logged for debugging purposes.

    Returns:
        bytes: The incremented nonce value as a byte sequence of size
               NONCE_SIZE, represented in the specified byte order
               (BYTEORDER).
    """
    INT_D['nonce_counter'] += 1

    if DEBUG:
        incremented_counter: int = INT_D['nonce_counter']
        log_d(f'nonce counter incremented to {incremented_counter}')

    incremented_nonce: bytes = \
        INT_D['nonce_counter'].to_bytes(NONCE_SIZE, BYTEORDER)

    return incremented_nonce


def encrypt_decrypt(input_data: bytes) -> bytes:
    """
    Encrypt or decrypt a data chunk using the ChaCha20 cipher.

    This function increments the nonce counter by calling the
    `get_incremented_nonce` function to generate a nonce based
    on the current counter value. It then uses the ChaCha20 cipher
    to encrypt or decrypt the provided input data. The same function
    is used for both encryption and decryption, as ChaCha20 is a
    symmetric stream cipher.

    Args:
        input_data (bytes): The data to be encrypted or decrypted. This
                            should be provided as a byte string.

    Returns:
        bytes: The encrypted or decrypted output data,
               also as a byte string.

    Note:
        Ensure that the nonce counter is properly managed to avoid nonce
        reuse, which can compromise the security of the encryption.
        The nonce must be unique for each encryption operation with the
        same key.
    """

    # Retrieve the incremented nonce value as queried by ChaCha20-IETF
    nonce: bytes = get_incremented_nonce()

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
        log_d(f'data chunk encrypted/decrypted:\n'
              f'    chunk size:  {format_size(chunk_size)} \n'
              f'    nonce used:  {nonce.hex()}')

    return output_data


# Handle MAC
# --------------------------------------------------------------------------- #


def init_mac() -> None:
    """
    Initializes the MAC (Message Authentication Code) hash object
    using the BLAKE2 algorithm.

    This function sets up the hash object with a specified digest size
    and key, and initializes the message sum for MAC calculations.
    It also logs the initialization if the DEBUG flag is set.

    Returns:
        None
    """
    ANY_D['mac_hash_obj'] = blake2b(
        digest_size=MAC_TAG_SIZE,
        key=BYTES_D['mac_key'],
    )
    INT_D['mac_message_sum'] = 0

    if DEBUG:
        log_d('MAC hash object initialized')


def update_mac(chunk: bytes) -> None:
    """
    Updates the MAC (Message Authentication Code) hash object with the
    given data chunk.

    This function takes a byte chunk, updates the MAC hash object with
    it, and increments the total message size. If the DEBUG flag is set,
    it logs the size of the chunk that was added to the MAC.

    Args:
        chunk (bytes): The data chunk to be added to the MAC.

    Returns:
        None
    """
    ANY_D['mac_hash_obj'].update(chunk)

    chunk_size: int = len(chunk)

    INT_D['mac_message_sum'] += chunk_size

    if DEBUG:
        log_d(f'MAC updated with {format_size(chunk_size)} chunk')


def handle_mac_tag(action: ActionID, mac_message_size: int) -> bool:
    """
    Handles the MAC (Message Authentication Code) tag for integrity
    verification.

    This function calculates the MAC tag based on the current state of
    the MAC hash object. Depending on the specified action, it either
    writes a MAC tag (for encryption actions) or verifies a MAC tag (for
    decryption actions). It also checks if the provided
    `mac_message_size` matches the accumulated message size.

    Args:
        action (ActionID): The action to perform (e.g., encryption or
                           decryption). This should be one of the defined
                           action identifiers.
        mac_message_size (int): The expected size of the MAC message.

    Returns:
        bool: True if the operation was successful, False otherwise.

    Note:
        This function relies on global variables ANY_D, BOOL_D, INT_D,
        and BIO_D, where ANY_D['mac_hash_obj'] is the MAC hash object,
        BOOL_D['set_fake_mac'] indicates whether to use a fake MAC tag,
        INT_D['written_sum'] tracks the amount of data written, and
        BIO_D['IN'] is the input stream for reading data.
    """

    # Handle the MAC tag for integrity verification
    if DEBUG:
        log_d('handling MAC tag')

    calculated_mac_tag: bytes = ANY_D['mac_hash_obj'].digest()

    if DEBUG:
        log_d(f'calculated MAC tag:\n    {calculated_mac_tag.hex()}')

    if action in (ENCRYPT, ENCRYPT_EMBED):  # Encryption actions
        fake_mac_tag: bytes = token_bytes(MAC_TAG_SIZE)

        if DEBUG:
            log_d(f'fake MAC tag:\n    {fake_mac_tag.hex()}')

        # Determine whether to use a fake MAC tag
        if BOOL_D['set_fake_mac']:
            mac_tag: bytes = fake_mac_tag
        else:
            mac_tag = calculated_mac_tag

        if DEBUG:
            log_d(f'MAC tag to write:\n    {mac_tag.hex()}')

        # Write the MAC tag to the output
        if not write_data(mac_tag):
            return False

        if DEBUG:
            log_d('MAC tag written')

        INT_D['written_sum'] += len(mac_tag)
    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
        retrieved_mac_tag: Optional[bytes] = \
            read_data(BIO_D['IN'], MAC_TAG_SIZE)

        if retrieved_mac_tag is None:
            BOOL_D['auth_fail'] = True

            log_w('integrity/authenticity check:')
            log_w('\r    [FAIL]')
            log_w('released plaintext can\'t be trusted!')
            return False

        if DEBUG:
            log_d(f'retrieved MAC tag:\n    {retrieved_mac_tag.hex()}')

        # Compare the calculated MAC tag with the retrieved MAC tag
        if compare_digest(calculated_mac_tag, retrieved_mac_tag):
            if DEBUG:
                log_d('calculated_mac_tag is equal to retrieved_mac_tag')

            log_i('integrity/authenticity check:\n    [ OK ]')
        else:
            BOOL_D['auth_fail'] = True

            if DEBUG:
                log_d('calculated_mac_tag is not equal to retrieved_mac_tag')

            log_w('integrity/authenticity check:')
            log_w('\r    [FAIL]')
            log_w('released plaintext can\'t be trusted!')

    mac_message_sum: int = INT_D['mac_message_sum']

    if mac_message_size != mac_message_sum:
        log_e(f'mac_message_size ({mac_message_size}) != '
              f'mac_message_sum ({mac_message_sum})')
        return False

    if DEBUG:
        log_d(f'MAC message size handled: {format_size(mac_message_sum)}')
        log_d('handling MAC tag completed')

    return True


# Set custom settings for actions
# ENCRYPT, DECRYPT, ENCRYPT_EMBED, EXTRACT_DECRYPT
# --------------------------------------------------------------------------- #


def set_custom_settings(action: ActionID) -> None:
    """
    Sets the custom settings for the application based on the specified
    action.

    This function configures the Argon2 time cost, maximum padding size
    percentage, and whether to set a fake MAC tag, depending on whether
    custom settings are enabled.

    If custom settings are enabled:
        - The Argon2 time cost is retrieved from the custom
          configuration.
        - The maximum padding size percentage is retrieved from the
          custom configuration.
        - If the action is ENCRYPT or ENCRYPT_EMBED, it checks whether
          to set a fake MAC tag.

    If custom settings are not enabled, default values are used for
    these settings.

    The function logs the settings for debugging purposes if the DEBUG
    flag is set. It also modifies global dictionaries to store the
    settings.

    Args:
        action (ActionID): The action that triggered the setting of
            custom settings. This determines which custom settings to
            apply. Actions ENCRYPT and ENCRYPT_EMBED require specific
            custom values.

    Returns:
        None
    """

    # Check if custom settings are enabled
    is_custom_enabled: bool = is_custom_settings()
    log_i(f'use custom settings: {is_custom_enabled}')

    # Initialize default values for settings
    argon2_time_cost: int = DEFAULT_ARGON2_TIME_COST
    max_pad_size_percent: int = DEFAULT_MAX_PAD_SIZE_PERCENT
    should_set_fake_mac: bool = False

    # If custom settings are enabled, retrieve custom values
    if is_custom_enabled:
        # Log a warning if the action requires specific custom values
        if action in (ENCRYPT, ENCRYPT_EMBED):
            log_w('decryption will require the same [11] and [12] values!')

        # Retrieve custom Argon2 time cost and maximum padding size percentage
        argon2_time_cost = get_argon2_time_cost()
        max_pad_size_percent = get_max_pad_size_percent()

        # Check if a fake MAC tag should be set for specific actions
        if action in (ENCRYPT, ENCRYPT_EMBED):
            should_set_fake_mac = is_fake_mac()

    # Log the settings if custom settings is enabled
    if is_custom_enabled:
        log_i(f'time cost: {argon2_time_cost:,}')
        log_i(f'max padding size, %: {max_pad_size_percent:,}')

        if action in (ENCRYPT, ENCRYPT_EMBED):
            log_i(f'set fake MAC tag: {should_set_fake_mac}')

    # Log the settings if debugging is enabled
    if DEBUG and not is_custom_enabled:
        log_d(f'time cost: {argon2_time_cost:,}')
        log_d(f'max padding size, %: {max_pad_size_percent:,}')

        if action in (ENCRYPT, ENCRYPT_EMBED):
            log_d(f'set fake MAC tag: {should_set_fake_mac}')

    # Store the settings in the global `INT_D` dictionary
    INT_D['argon2_time_cost'] = argon2_time_cost
    INT_D['max_pad_size_percent'] = max_pad_size_percent

    # If the action requires it, store the fake MAC tag setting
    if action in (ENCRYPT, ENCRYPT_EMBED):
        BOOL_D['set_fake_mac'] = should_set_fake_mac


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
    Orchestrates the encryption/decryption and embedding/extracting
    process based on the specified action.

    This function retrieves the necessary input parameters for the
    encryption and embedding process by calling the
    `encrypt_and_embed_input` function. If the input retrieval is
    successful, it then calls the `encrypt_and_embed_handler`
    function to perform the actual operation (encryption, decryption,
    embedding, or extraction).

    Args:
        action (ActionID): An integer indicating the action to perform,
            which determines the type of operation (e.g., encryption,
            decryption, embedding, extraction).

    Returns:
        bool: True if the encryption and embedding operation was
              successful, False if the operation was canceled, failed,
              or if input retrieval was unsuccessful.

    Notes:
        - If the input retrieval fails (returns None), the function will
          return False immediately.
        - The function calls `collect()` to perform any necessary
          cleanup or memory management before proceeding with the
          encryption and embedding process.
    """

    # Retrieve input parameters for the encryption and embedding process
    input_values: Optional[tuple[
        int,
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[bytes],
    ]] = encrypt_and_embed_input(action)

    # If input retrieval fails, return False
    if input_values is None:
        return False

    # Perform cleanup or memory management before proceeding
    collect()

    # Unpack the retrieved values for further processing
    # Size of the input file
    in_file_size: int = input_values[0]

    # Starting position for the operation
    start_pos: Optional[int] = input_values[1]

    # Ending position for the operation
    end_pos: Optional[int] = input_values[2]

    # Size of the unpadded cryptoblob, if applicable
    unpadded_size: Optional[int] = input_values[3]

    # Processed comments to be encrypted, if applicable
    processed_comments: Optional[bytes] = input_values[4]

    # Call the handler function to perform the action
    success: bool = encrypt_and_embed_handler(
        action,
        in_file_size,
        start_pos,
        end_pos,
        unpadded_size,
        processed_comments,
    )

    # Return the success status of the operation
    return success


def encrypt_and_embed_input(
    action: ActionID
) -> Optional[tuple[
    int,
    Optional[int],
    Optional[int],
    Optional[int],
    Optional[bytes],
]]:
    """
    Collect input parameters for the encryption and embedding process
    based on the specified action.

    This function handles the collection of user input data, validates
    the size of the input file, and determines the necessary parameters
    for encryption or embedding. It sets up the output file and
    calculates the start and end positions for the operation.
    Additionally, it manages any required salts and comments for the
    process.

    Args:
        action (ActionID): An integer indicating the action to perform,
            which affects how input is processed (e.g., ENCRYPT for
            encryption, DECRYPT for decryption, etc).

    Returns:
        Optional[tuple]: A tuple containing the following elements if
            successful:
            - in_file_size (int): The size of the input file.
            - start_pos (Optional[int]): The starting position for the
              operation, or None if not applicable.
            - end_pos (Optional[int]): The ending position for the
              operation, or None if not applicable.
            - unpadded_size (Optional[int]): The size of the unpadded
              cryptoblob, or None if not applicable.
            - processed_comments (Optional[bytes]): The processed
              comments to be encrypted, or None if not applicable.

        Returns None if the input retrieval fails or if the input file
        does not meet the required conditions.

    Notes:
        - The function logs various information during its execution for
          debugging purposes.
        - It handles different actions (e.g., creating new files,
          checking sizes) based on the provided action ID.
    """

    # 0. Initialize variables
    # ----------------------------------------------------------------------- #

    start_pos: Optional[int] = None
    end_pos: Optional[int] = None
    unpadded_size: Optional[int] = None
    processed_comments: Optional[bytes] = None

    # 1. Set custom settings based on the action
    # ----------------------------------------------------------------------- #

    set_custom_settings(action)

    # 2. Get input file path and size
    # ----------------------------------------------------------------------- #

    in_file_path: str
    in_file_size: int

    # Retrieve the input file path, size, and file descriptor
    in_file_path, in_file_size, BIO_D['IN'] = get_input_file(action)

    # Log the input file path and size
    log_i(f'path: {in_file_path!r}; size: {format_size(in_file_size)}')

    # 3. Retrieve and verify additional sizes
    # ----------------------------------------------------------------------- #

    # Handle encryption actions (ENCRYPT, ENCRYPT_EMBED)
    if action in (ENCRYPT, ENCRYPT_EMBED):
        # Calculate the size of unpadded cryptoblob
        unpadded_size = in_file_size + MIN_VALID_UNPADDED_SIZE

        max_total_pad_size: int = \
            unpadded_size * INT_D['max_pad_size_percent'] // 100

        max_padded_size: int = unpadded_size + max_total_pad_size

        # Debug logging for calculated sizes
        if DEBUG:
            log_d(f'unpadded_size:       {format_size(unpadded_size)}')
            log_d(f'max_total_pad_size:  {format_size(max_total_pad_size)}')
            log_d(f'max_padded_size:     {format_size(max_padded_size)}')

    # Handle decryption actions (DECRYPT, EXTRACT_DECRYPT) and validate
    # input file size
    else:
        if in_file_size < MIN_VALID_UNPADDED_SIZE:
            if action == DECRYPT:
                log_e(f'input file is too small (min valid cryptoblob size '
                      f'is {format_size(MIN_VALID_UNPADDED_SIZE)})')
            else:  # action == EXTRACT_DECRYPT
                log_e(f'incorrect start/end positions (min valid cryptoblob '
                      f'size is {format_size(MIN_VALID_UNPADDED_SIZE)})')
            return None

    # 4. Get processed comments for their further encryption
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):
        processed_comments = get_processed_comments()

    # 5. Retrieve the output file path, size, and file descriptor
    # ----------------------------------------------------------------------- #

    out_file_path: str
    out_file_size: int

    # Set up output file based on the action
    if action in (ENCRYPT, DECRYPT):  # New file creation
        out_file_path, BIO_D['OUT'] = get_output_file_new(action)
        log_i(f'new file {out_file_path!r} created')

    elif action == ENCRYPT_EMBED:  # Existing file handling for encryption
        out_file_path, out_file_size, BIO_D['OUT'] = \
            get_output_file_exist(
                in_file_path,
                max_padded_size,
                action,
        )
        max_start_pos: int = out_file_size - max_padded_size
        log_i(f'path: {out_file_path!r}')

    else:  # action == EXTRACT_DECRYPT, new file creation for decryption
        out_file_path, BIO_D['OUT'] = get_output_file_new(action)
        max_start_pos = in_file_size - MIN_VALID_UNPADDED_SIZE
        log_i(f'new file {out_file_path!r} created')

    # Log the size of the output file if applicable
    if action == ENCRYPT_EMBED:
        log_i(f'size: {format_size(out_file_size)}')

    # 6. Get positions for embedding/extraction
    # ----------------------------------------------------------------------- #

    # Get the starting position for the operation
    if action in (ENCRYPT_EMBED, EXTRACT_DECRYPT):
        start_pos = get_start_position(max_start_pos, no_default=True)
        log_i(f'start position: {start_pos} (offset: {start_pos:,} B)')

    # Get the ending position for extraction
    if action == EXTRACT_DECRYPT:
        end_pos = get_end_position(
            min_pos=start_pos + MIN_VALID_UNPADDED_SIZE,
            max_pos=in_file_size,
            no_default=True,
        )
        log_i(f'end position: {end_pos} (offset: {end_pos:,} B)')

    # 7. Set file pointers to the specified positions
    # ----------------------------------------------------------------------- #

    # Seek to the start position in the output file if encrypting
    if action == ENCRYPT_EMBED:
        if not seek_position(BIO_D['OUT'], start_pos):
            return None

    # Seek to the start position in the input file if decrypting
    if action == EXTRACT_DECRYPT:
        if not seek_position(BIO_D['IN'], start_pos):
            return None

    # 8. Get salts: need for handling IKM and for performing Argon2
    # ----------------------------------------------------------------------- #

    if not get_salts(in_file_size, end_pos, action):
        return None

    # 9. Get the Argon2 password for key derivation from IKM digests
    # ----------------------------------------------------------------------- #

    get_argon2_password()

    # 10. Trigger garbage collection to free up memory
    # ----------------------------------------------------------------------- #

    collect()

    # 11. Ask user confirmation for proceeding
    # ----------------------------------------------------------------------- #

    if action == ENCRYPT_EMBED:
        if not proceed_request(PROCEED_OVERWRITE):
            log_i('stopped by user request')
            return None

    # 12. Return the retrieved parameters for further processing
    # ----------------------------------------------------------------------- #

    return (
        in_file_size,
        start_pos,
        end_pos,
        unpadded_size,
        processed_comments,
    )


def encrypt_and_embed_handler(
    action: ActionID,
    in_file_size: int,
    start_pos: Optional[int],
    end_pos: Optional[int],
    unpadded_size: Optional[int],
    processed_comments: Optional[bytes],
) -> bool:
    """
    Handles the encryption/embedding or decryption/extraction process
    based on the specified action.

    This function performs the necessary steps to encrypt or decrypt
    data, including managing padding, calculating MAC tags, and writing
    or reading data to/from files. It also handles processed comments
    and ensures data integrity through MAC verification.

    The function follows these steps:
    1. Derives cryptographic keys required for the operation.
    2. Initializes the nonce counter and MAC hash object for the current
       action.
    3. Determines the padding size based on the action and input
       parameters.
    4. Prepares the header and footer padding sizes.
    5. Collects unused resources to free memory.
    6. Calculates the sizes of the cryptoblob and contents based on the
       action.
    7. Logs the sizes for debugging purposes if DEBUG mode is enabled.
    8. Reads and writes Argon2 salt, handling processed comments based
       on the action.
    9. Processes the main content in chunks, encrypting or decrypting as
       necessary.
    10. Updates the MAC hash with the processed data.
    11. Handles footer padding and writes BLAKE2 salt if applicable.
    12. Verifies the integrity/authenticity of the data using the MAC
        tag.
    13. Returns True if the operation was successful, or False if any
        step fails.

    Args:
        action (ActionID): An integer indicating the action to perform
            (e.g., ENCRYPT for encryption, ENCRYPT_EMBED for embedding,
            DECRYPT for decryption, EXTRACT_DECRYPT for extraction).
        in_file_size (int): The size of the input file.
        start_pos (Optional[int]): The starting position for the
            operation (used in embedding and extraction).
        end_pos (Optional[int]): The ending position for the operation
            (used in extraction).
        unpadded_size (Optional[int]): The size of the cryptoblob,
            excluding padding, if applicable.
        processed_comments (Optional[bytes]): The processed comments to
            be encrypted/embedded. Can be None for decryption actions,
            if processed_comments as bytes have not yet been obtained
            (decrypted).

    Returns:
        bool: True if the operation was successful, False if it failed
              at any point. Logs error messages if any step fails.

    Notes:
        - The function logs various information during its execution for
          debugging purposes.
        - It manages both the encryption and decryption processes based
          on the action parameter.
        - The function ensures data integrity by comparing MAC tags
          during decryption.
        - Global variables such as BYTES_D, INT_D, and DEBUG are used
          within the function to manage state and configuration.
        - Utilizes cryptographic algorithms including ChaCha20, Argon2,
          and BLAKE2.
        - The function may raise exceptions for critical failures, which
          should be handled by the calling code.
        - The function is designed to handle large files efficiently by
          processing them in chunks.
    """

    # Derive keys needed for padding/encryption/authentication
    # ----------------------------------------------------------------------- #

    if not derive_keys():
        return False

    # Initialize values
    # ----------------------------------------------------------------------- #

    # Initialize ChaCha20 nonce counter for the current action
    init_nonce_counter()

    # Initialize MAC for the current action
    init_mac()

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

    # Determine padding sizes and padded size
    # ----------------------------------------------------------------------- #

    total_pad_size: int
    header_pad_size: int
    footer_pad_size: int
    padded_size: int

    # Determine total padding size based on the action
    if action in (ENCRYPT, ENCRYPT_EMBED):  # Encryption actions
        total_pad_size = get_pad_size_from_unpadded(
            unpadded_size,
            BYTES_D['pad_key_t'],
            INT_D['max_pad_size_percent'],
        )
        padded_size = unpadded_size + total_pad_size
    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
        if action == DECRYPT:
            padded_size = in_file_size
        else:  # action == EXTRACT_DECRYPT
            padded_size = end_pos - start_pos

        total_pad_size = get_pad_size_from_padded(
            padded_size,
            BYTES_D['pad_key_t'],
            INT_D['max_pad_size_percent'],
        )

    # Calculate header and footer padding sizes
    header_pad_size, footer_pad_size = get_header_footer_pad_sizes(
        total_pad_size,
        BYTES_D['pad_key_hf'],
    )

    # Convert sizes to bytes for further authentication
    # ----------------------------------------------------------------------- #

    try:
        header_pad_size_bytes: bytes = \
            header_pad_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)
    except OverflowError:
        log_e(f'header pad size is too big: {format_size(header_pad_size)}')
        return False

    try:
        footer_pad_size_bytes: bytes = \
            footer_pad_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)
    except OverflowError:
        log_e(f'footer pad size is too big: {format_size(header_pad_size)}')
        return False

    try:
        padded_size_bytes: bytes = \
            padded_size.to_bytes(SIZE_BYTES_SIZE, BYTEORDER)
    except OverflowError:
        log_e(f'cryptoblob size is too big: {format_size(padded_size)}')
        return False

    if DEBUG:
        log_d(f'header_pad_size_bytes:  {header_pad_size_bytes.hex()}')
        log_d(f'footer_pad_size_bytes:  {footer_pad_size_bytes.hex()}')
        log_d(f'padded_size_bytes:      {padded_size_bytes.hex()}')

    # Update MAC with salts and sizes
    # ----------------------------------------------------------------------- #

    # Update MAC with salts
    update_mac(BYTES_D['argon2_salt'])
    update_mac(BYTES_D['blake2_salt'])

    # Update MAC with the sizes as a byte strings
    update_mac(header_pad_size_bytes)
    update_mac(footer_pad_size_bytes)
    update_mac(padded_size_bytes)

    # Clean up sensitive data from memory
    # ----------------------------------------------------------------------- #

    del (
        BYTES_D['argon2_password'],
        BYTES_D['pad_key_t'],
        BYTES_D['pad_key_hf'],
        BYTES_D['mac_key'],
    )

    # Trigger garbage collection to free up memory
    collect()

    # Calculate, log, and validate sizes
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('calculating additional sizes')

    # Determine the size of the payload file contents to be processed
    if action in (ENCRYPT, ENCRYPT_EMBED):
        contents_size: int = in_file_size
    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
        contents_size = \
            padded_size - total_pad_size - MIN_VALID_UNPADDED_SIZE

    # Calculate the MAC message size
    mac_message_size: int = (SALTS_SIZE + SIZE_BYTES_SIZE * 3 +
                             PROCESSED_COMMENTS_SIZE + contents_size)

    # Calculate the output data size based on the action
    if action in (ENCRYPT, ENCRYPT_EMBED):
        out_data_size: int = \
            contents_size + total_pad_size + MIN_VALID_UNPADDED_SIZE
    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
        out_data_size = contents_size

    # Debug logging for sizes
    if DEBUG:
        log_d(f'payload file contents size:  {format_size(contents_size)}')
        log_d(f'output data size:            {format_size(out_data_size)}')

    # Validate contents size (for decryption actions)
    if contents_size < 0:
        log_e('invalid combination of input values')
        return False

    # Write argon2_salt if encrypting
    # ----------------------------------------------------------------------- #

    log_i('reading, writing')

    if action in (ENCRYPT, ENCRYPT_EMBED):
        if DEBUG:
            log_d('writing argon2_salt')

        if not write_data(BYTES_D['argon2_salt']):
            return False

        INT_D['written_sum'] += len(BYTES_D['argon2_salt'])

        if DEBUG:
            log_d('argon2_salt written')

    # Handle header padding
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('handling header padding')

    if action in (ENCRYPT, ENCRYPT_EMBED):
        h_pad_start_pos: int = BIO_D['OUT'].tell()

    # Write or skip header_pad
    if not handle_padding(header_pad_size, action, out_data_size):
        return False

    if action in (ENCRYPT, ENCRYPT_EMBED):
        h_pad_end_pos: int = BIO_D['OUT'].tell()

    if DEBUG:
        log_d('handling header padding completed')

    # Handle comments based on the action type
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('handling comments')

    enc_processed_comments: Optional[bytes]  # Encrypted processed_comments

    if action in (ENCRYPT, ENCRYPT_EMBED):
        enc_processed_comments = encrypt_decrypt(processed_comments)

        update_mac(enc_processed_comments)

        if not write_data(enc_processed_comments):
            return False

        INT_D['written_sum'] += len(enc_processed_comments)

    else:  # DECRYPT, EXTRACT_DECRYPT
        enc_processed_comments = \
            read_data(BIO_D['IN'], PROCESSED_COMMENTS_SIZE)

        if enc_processed_comments is None:
            return False

        update_mac(enc_processed_comments)

        # Get decrypted processed_comments
        processed_comments = encrypt_decrypt(enc_processed_comments)

        decoded_comments: Optional[str] = \
            decode_processed_comments(processed_comments)

        log_i(f'comments:\n    {[decoded_comments]}')

    if DEBUG:
        log_d('handling comments completed')

    # Handle contents of the payload file based on the action type
    # ----------------------------------------------------------------------- #

    if DEBUG:
        log_d('handling payload file contents')

    # Calculate the number of complete chunks and remaining bytes
    num_complete_chunks: int = contents_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = contents_size % RW_CHUNK_SIZE

    # Process complete chunks
    for _ in range(num_complete_chunks):
        if not file_chunk_handler(action, RW_CHUNK_SIZE, out_data_size):
            return False

    # Process any remaining bytes
    if num_remaining_bytes:
        if not file_chunk_handler(action, num_remaining_bytes, out_data_size):
            return False

    if DEBUG:
        log_d('handling payload file contents completed')

        if action in (ENCRYPT, ENCRYPT_EMBED):
            log_d('encryption completed')
        else:
            log_d('decryption completed')

        enc_sum: int = INT_D['enc_sum']
        enc_chunk_count: int = INT_D['enc_chunk_count']

        if action in (ENCRYPT, ENCRYPT_EMBED):  # Encryption actions
            log_d(f'total encrypted with ChaCha20: '
                  f'{enc_chunk_count} chunks, {format_size(enc_sum)}')
        else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
            log_d(f'total decrypted with ChaCha20: '
                  f'{enc_chunk_count} chunks, {format_size(enc_sum)}')

    # Log progress for decryption actions
    if action in (DECRYPT, EXTRACT_DECRYPT):
        log_progress(out_data_size)

    # Handle the MAC tag for integrity/authenticity verification
    # ----------------------------------------------------------------------- #

    if not handle_mac_tag(action, mac_message_size):
        return False

    # Handle footer padding
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):
        if DEBUG:
            log_d('handling footer padding')

        f_pad_start_pos: int = BIO_D['OUT'].tell()

        # Write or skip footer_pad
        if not handle_padding(footer_pad_size, action, out_data_size):
            return False

        f_pad_end_pos: int = BIO_D['OUT'].tell()

        if DEBUG:
            log_d('handling footer padding completed')

    # Write blake2_salt if encrypting
    # ----------------------------------------------------------------------- #

    if action in (ENCRYPT, ENCRYPT_EMBED):
        if DEBUG:
            log_d('writing blake2_salt')

        if not write_data(BYTES_D['blake2_salt']):
            return False

        INT_D['written_sum'] += len(BYTES_D['blake2_salt'])

        if DEBUG:
            log_d('blake2_salt written')

        log_progress(out_data_size)

    # Validate the total written size against the expected output size
    # ----------------------------------------------------------------------- #

    if INT_D['written_sum'] != out_data_size:
        written_sum: int = INT_D['written_sum']
        log_e(f'written data size ({format_size(written_sum)}) does not '
              f'equal expected size ({format_size(out_data_size)})')
        return False

    # Synchronize data to disk if necessary
    # ----------------------------------------------------------------------- #

    if action == ENCRYPT_EMBED:
        log_i('syncing output data to disk')
        fsync_start_time: float = monotonic()

        if not fsync_written_data():
            return False

        fsync_end_time: float = monotonic()
        log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    # Log progress and locations
    # ----------------------------------------------------------------------- #

    # Log the location of the cryptoblob in the container if encrypting
    if action == ENCRYPT_EMBED:
        end_pos = BIO_D['OUT'].tell()
        log_w('cryptoblob location is important for its further extraction!')
        log_i(f'remember cryptoblob location in container:\n'
              f'    [{start_pos}:{end_pos}]')

    # Log padding locations if encrypting
    if action in (ENCRYPT, ENCRYPT_EMBED):
        h_pad_size: str = format_size(header_pad_size)
        f_pad_size: str = format_size(footer_pad_size)

        log_i(f'location of padding in output file (may be ignored):\n'
              f'    [{h_pad_start_pos}:{h_pad_end_pos}] — {h_pad_size}\n'
              f'    [{f_pad_start_pos}:{f_pad_end_pos}] — {f_pad_size}')

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

    # Return the success status of the operation
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

        # Calculate max start position
        max_start_pos = out_file_size - in_file_size

        log_i(f'path: {out_file_path!r}')

    else:  # action EXTRACT
        # For extraction, create a new output file
        out_file_path, BIO_D['OUT'] = get_output_file_new(action)

        # Set max start position for extraction
        max_start_pos = in_file_size

        log_i(f'new file {out_file_path!r} created')

    if action == EMBED:
        # Log the size of the output file for embedding
        log_i(f'size: {format_size(out_file_size)}')

    # Get the starting position for embedding or extraction
    start_pos = get_start_position(max_start_pos, no_default=True)
    log_i(f'start position: {start_pos} (offset: {start_pos:,} B)')

    if action == EMBED:
        # For embedding, set message size to input file size
        message_size = in_file_size
        end_pos = start_pos + message_size  # Calculate end position
        log_i(f'end position: {end_pos} (offset: {end_pos:,} B)')

        # Prompt user for confirmation before proceeding
        if not proceed_request(PROCEED_OVERWRITE):
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

        # Calculate message size to retrieve
        message_size = end_pos - start_pos
        log_i(f'message size to retrieve: {message_size} B')

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
          RW_CHUNK_SIZE.
        - The function computes a checksum using the BLAKE2 hashing
          algorithm and logs the checksum and the position of the
          embedded or extracted message.
        - If action EMBED is performed, it ensures that the output data is
          synchronized after writing.
    """

    # Seek to the start position in the appropriate container
    if action == EMBED:
        if not seek_position(BIO_D['OUT'], start_pos):
            return False  # Return False if seeking fails

    else:  # action == EXTRACT
        if not seek_position(BIO_D['IN'], start_pos):
            return False

    log_i('reading, writing')

    # Initialize the BLAKE2 hash object for checksum calculation
    hash_obj: Any = blake2b(digest_size=CHECKSUM_SIZE)

    # Record the start time for performance measurement
    FLOAT_D['start_time'] = monotonic()
    FLOAT_D['last_progress_time'] = monotonic()

    INT_D['written_sum'] = 0  # Initialize the total bytes written counter

    # Calculate the number of complete chunks and remaining bytes
    num_complete_chunks: int = message_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = message_size % RW_CHUNK_SIZE

    # Read and write complete chunks of data
    for _ in range(num_complete_chunks):
        message_chunk: Optional[bytes] = read_data(BIO_D['IN'], RW_CHUNK_SIZE)

        if message_chunk is None:
            return False  # Return False if reading fails

        if not write_data(message_chunk):
            return False  # Return False if writing fails

        hash_obj.update(message_chunk)  # Update the checksum with the chunk

        INT_D['written_sum'] += len(message_chunk)

        # Log progress at defined intervals
        if monotonic() - \
                FLOAT_D['last_progress_time'] >= MIN_PROGRESS_INTERVAL:
            log_progress(message_size)
            FLOAT_D['last_progress_time'] = monotonic()

    # Write any remaining bytes that do not fit into a full chunk
    if num_remaining_bytes:
        message_chunk = read_data(BIO_D['IN'], num_remaining_bytes)

        if message_chunk is None:
            return False

        if not write_data(message_chunk):
            return False

        # Update the checksum with the last chunk
        hash_obj.update(message_chunk)

        INT_D['written_sum'] += len(message_chunk)

    # Log the final progress after writing all data
    log_progress(message_size)

    # Validate the total written size against the expected output size
    if INT_D['written_sum'] != message_size:
        written_sum: int = INT_D['written_sum']
        log_e(f'written data size ({format_size(written_sum)}) does not '
              f'equal expected size ({format_size(message_size)})')
        return False

    if action == EMBED:
        log_i('syncing output data to disk')
        fsync_start_time: float = monotonic()

        # Synchronize the output data to ensure all changes are flushed
        if not fsync_written_data():
            return False  # Return False if synchronization fails

        fsync_end_time: float = monotonic()
        log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    # Calculate the checksum of the written data
    message_checksum: str = hash_obj.hexdigest()

    # Get the current position in the output container
    end_pos: int = BIO_D['OUT'].tell()

    if action == EMBED:
        log_w('message location is important for its further extraction!')

        # Log the location of the embedded message in the container
        log_i(f'remember message location in container:\n'
              f'    [{start_pos}:{end_pos}]')

    # Log the checksum of the message
    log_i(f'message checksum:\n    {message_checksum}')

    # Return True if the operation was successful
    return True


# Perform action CREATE_W_RANDOM
# --------------------------------------------------------------------------- #


def create_with_random(action: ActionID) -> bool:
    """
    Creates a file of a specified size with random data.

    Args:
        action (ActionID): An integer representing the action to be
                           performed.

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
    log_i(f'new file {out_file_path!r} created')

    # Get the size of the newly created output file
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

    # Log the start of the random data writing process
    log_i('writing random data')

    # Record the start time for performance measurement
    FLOAT_D['start_time'] = monotonic()
    FLOAT_D['last_progress_time'] = monotonic()

    INT_D['written_sum'] = 0  # Initialize the total bytes written counter

    # Calculate the number of complete chunks and remaining bytes to write
    num_complete_chunks: int = out_file_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = out_file_size % RW_CHUNK_SIZE

    # Write complete chunks of random data
    for _ in range(num_complete_chunks):
        # Generate a chunk of random data
        chunk: bytes = token_bytes(RW_CHUNK_SIZE)

        if not write_data(chunk):
            return False

        INT_D['written_sum'] += len(chunk)

        # Log progress at defined intervals
        if monotonic() - \
                FLOAT_D['last_progress_time'] >= MIN_PROGRESS_INTERVAL:
            log_progress(out_file_size)
            FLOAT_D['last_progress_time'] = monotonic()

    # Write any remaining bytes that do not fit into a full chunk
    if num_remaining_bytes:
        # Generate the last chunk of random data
        chunk = token_bytes(num_remaining_bytes)

        # Write the remaining bytes to the output file
        if not write_data(chunk):
            return False  # Return False if writing fails

        INT_D['written_sum'] += len(chunk)

    # Log the final progress after writing all data
    log_progress(out_file_size)

    # Validate the total written size against the expected output size
    if INT_D['written_sum'] != out_file_size:
        written_sum: int = INT_D['written_sum']
        log_e(f'written data size ({format_size(written_sum)}) does not '
              f'equal expected size ({format_size(out_file_size)})')
        return False

    # Return True if all data was written successfully
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
        action (ActionID): The action code that determines the start
                           position and data size.

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

    # Return the success status of the overwrite operation
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
        - If the output file size is zero or if the calculated data size
          is zero, the function will log a message and return None.
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
    log_i(f'data size to write: {format_size(data_size)}')  # Log the data size

    # Prompt the user for confirmation before proceeding
    if not proceed_request(PROCEED_OVERWRITE):
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
        - The function writes data in chunks defined by `RW_CHUNK_SIZE`
          and handles any remaining data that does not fit into a full
          chunk.
        - Progress is logged during the write operation, and the time
          taken to synchronize the file is also logged.
    """

    # Seek to the specified start position in the output file
    if not seek_position(BIO_D['OUT'], start_pos):
        return False  # Return False if seeking fails

    log_i('writing random data')

    # Record the start time for performance measurement
    FLOAT_D['start_time'] = monotonic()
    FLOAT_D['last_progress_time'] = monotonic()

    INT_D['written_sum'] = 0  # Initialize the total bytes written counter

    # Calculate the number of complete chunks and remaining bytes to write
    num_complete_chunks: int = data_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = data_size % RW_CHUNK_SIZE

    # Write complete chunks of random data
    for _ in range(num_complete_chunks):
        # Generate a chunk of random data
        chunk: bytes = token_bytes(RW_CHUNK_SIZE)

        if not write_data(chunk):  # Write the chunk to the output file
            return False  # Return False if writing fails

        INT_D['written_sum'] += len(chunk)  # Update the total written bytes

        # Log progress at defined intervals
        if monotonic() - \
                FLOAT_D['last_progress_time'] >= MIN_PROGRESS_INTERVAL:
            log_progress(data_size)
            FLOAT_D['last_progress_time'] = monotonic()

    # Write any remaining bytes that do not fit into a full chunk
    if num_remaining_bytes:
        # Generate the last chunk of random data
        chunk = token_bytes(num_remaining_bytes)

        if not write_data(chunk):
            return False

        INT_D['written_sum'] += len(chunk)

    # Log the final progress after writing all data
    log_progress(data_size)

    # Validate the total written size against the expected output size
    if INT_D['written_sum'] != data_size:
        written_sum: int = INT_D['written_sum']
        log_e(f'written data size ({format_size(written_sum)}) does not '
              f'equal expected size ({format_size(data_size)})')
        return False

    log_i('syncing output data to disk')

    fsync_start_time: float = monotonic()

    # Synchronize the file to ensure all changes are flushed to disk
    if not fsync_written_data():
        return False  # Return False if synchronization fails

    fsync_end_time: float = monotonic()

    # Log the time taken for fsync
    log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    return True  # Return True if the overwrite operation was successful


# Misc
# --------------------------------------------------------------------------- #


def file_chunk_handler(
    action: ActionID,
    chunk_size: int,
    out_data_size: int,
) -> bool:
    """
    Processes a chunk of data by reading, encrypting or decrypting,
    writing, and logging progress.

    This function reads a chunk of data from the input source, applies
    encryption or decryption, writes the processed chunk to the output
    destination, and updates the Message Authentication Code (MAC).
    It also logs the progress at specified intervals.

    Args:
        action (ActionID): The action to perform on the data chunk.
        chunk_size (int): The size of the data chunk to be processed.
        out_data_size (int): The total size of the output data, used for
                             progress logging.

    Returns:
        bool: True if the chunk was processed successfully, False
              otherwise.

    Notes:
        - The function updates the MAC based on the action being
          performed (encryption or decryption).
        - Progress is logged at intervals defined by
          MIN_PROGRESS_INTERVAL.
        - The function handles both encryption and decryption actions,
          updating the MAC accordingly.
    """
    in_chunk: Optional[bytes] = read_data(BIO_D['IN'], chunk_size)

    if in_chunk is None:
        return False

    out_chunk: bytes = encrypt_decrypt(in_chunk)

    if not write_data(out_chunk):
        return False

    INT_D['written_sum'] += len(out_chunk)

    # Log progress at intervals
    if monotonic() - \
            FLOAT_D['last_progress_time'] >= MIN_PROGRESS_INTERVAL:
        log_progress(out_data_size)
        FLOAT_D['last_progress_time'] = monotonic()

    # Update MAC with the encrypted chunk
    if action in (ENCRYPT, ENCRYPT_EMBED):
        update_mac(out_chunk)
    else:  # Decryption actions (DECRYPT, EXTRACT_DECRYPT)
        update_mac(in_chunk)

    return True


def perform_file_action(action: ActionID) -> None:
    """
    Executes the specified action based on the provided action
    identifier.

    This function performs the following tasks:
        - Sets a flag indicating that an action is currently ongoing.
        - Executes the action corresponding to the provided action
          identifier.
        - Cleans up resources and performs necessary actions after the
          action is executed.
        - Logs the completion status of the action.

    Args:
        action (ActionID): The identifier for the action to be performed.

    Returns:
        None
    """
    ANY_D['action_is_ongoing'] = None

    success: bool = FILE_ACTION_MAP[action](action)

    post_action_clean_up(action, success)

    if success:
        log_i('action completed')


def post_action_clean_up(action: ActionID, success: bool) -> None:
    """
    Cleans up resources and performs necessary actions after a specified
    action.

    This function performs the following tasks:
    1. Closes any open input and output files if they exist in the
       `BIO_D` dictionary.
    2. Evaluates the success of the action. If the action was not
       successful or if an authentication failure occurred, it checks
       if the provided action is related to creating a *new* output file
       and offers to remove the output file path.
    3. Clears the global dictionaries: `ANY_D`, `BIO_D`, `INT_D`,
       `BOOL_D`, and `BYTES_D`.
    4. Collects any remaining resources or performs additional cleanup
       by calling the `collect` function.

    Args:
        action (ActionID): An integer representing the action that was
                           performed (e.g., ENCRYPT, DECRYPT).
        success (Optional[bool]): A boolean indicating whether the
                                  action was successful.

    Returns:
        None
    """
    if 'IN' in BIO_D:
        close_file(BIO_D['IN'])

    if 'OUT' in BIO_D:
        close_file(BIO_D['OUT'])

        if not success or 'auth_fail' in BOOL_D:
            if action not in (EMBED, ENCRYPT_EMBED, OVERWRITE_W_RANDOM):
                remove_output_path()

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
    - If the first argument is '--debug', it sets the debug mode to True
      and logs a warning message.
    - If any other arguments are provided, an error is logged, and the
      program exits.

    Returns:
        bool: True if debug mode is enabled, False otherwise.
    """
    debug_enabled: bool

    if not argv[1:]:
        debug_enabled = False
    elif argv[1:] == ['--debug']:
        debug_enabled = True
        log_w('debug mode enabled! Sensitive data will be displayed!')
    else:
        log_e(f'invalid command line options: {argv[1:]}')
        exit(1)

    return debug_enabled


def signal_handler(signum: int, frame: Optional[FrameType]) -> NoReturn:
    """
    Handles incoming signals by determining the current state of the
    application.

    This function is called when a signal is received. It checks if an
    action is ongoing and prints an appropriate message before exiting
    the program with a status code.

    Args:
        signum (int): The signal number that was received.
        frame (Optional[FrameType]): The current stack frame
                                     (not used in this implementation).

    Raises:
        NoReturn: This function does not return; it exits the program.
    """
    print()

    message: str = f'caught signal {signum}'

    # Check if an action is currently ongoing
    if 'action_is_ongoing' in ANY_D:
        # Print an error message and exit with status code 1
        log_e(message)
        exit(1)
    else:
        # Print an informational message and exit with status code 0
        log_i(message)
        exit(0)


def main() -> NoReturn:
    """
    Main entry point for the application.

    This function initializes the application, sets up a signal handler
    for interrupt signals (SIGINT), and enters an infinite loop to
    process user actions. It prompts the user to select an action and
    executes the corresponding action. The application continues running
    until the user chooses to exit.

    Returns:
        NoReturn: This function does not return a value; it runs
                  indefinitely until the application is exited.

    Note:
        A signal handler is set up to gracefully handle SIGINT (e.g.,
        when the user presses Ctrl+C), allowing for a clean exit from
        the application.
    """
    signal(SIGINT, signal_handler)

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


# ANSI escape codes for terminal text formatting
BOL: str = '\x1b[1m'  # Bold text
ERR: str = '\x1b[1;97;101m'  # Bold white text, red background
WAR: str = '\x1b[1;93;40m'  # Bold yellow text, black background
RES: str = '\x1b[0m'  # Reset formatting to default

# Adjust ANSI codes for Windows platform, which does not support them
if platform == 'win32':
    BOL = ERR = WAR = RES = ''


# Version of the application
APP_VERSION: Final[str] = '0.18.0'

# Information string for the application
APP_INFO: Final[str] = f"""tird v{APP_VERSION}
    A tool for encrypting files and hiding encrypted data.
    Homepage: https://github.com/hakavlad/tird"""

# Debug information string for the Python version
APP_DEBUG_INFO: Final[str] = f'Python version {version}'

# Warnings related to the application usage
APP_WARNINGS: Final[tuple[str, ...]] = (
    'The author does not have a background in cryptography.',
    'The code has 0% test coverage.',
    'tird has not been independently audited.',
    'tird is ineffective in a compromised environment; executing it in such '
    'cases may cause disastrous data leaks.',
    'tird is unlikely to be effective when used with short and predictable '
    'keys.',
    'Sensitive data may leak into swap space.',
    'tird does not erase its sensitive data from memory after use.',
    'tird always releases unverified plaintext, violating The Cryptographic '
    'Doom Principle.',
    'tird doesn\'t sort digests of keyfiles and passphrases in constant-time.',
    'Padding sizes depend on secret values.',
    'Padding contents are never authenticated; authentication only applies to '
    'the ciphertext, salts, and certain sizes.',
    'Overwriting file contents does not guarantee secure destruction of data '
    'on the media.',
    'You cannot prove to an adversary that your random data does not contain '
    'encrypted information.',
    'tird protects data, not the user; it cannot prevent torture if you are '
    'under suspicion.',
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
[00] Select an option [0-9]:{RES} """


# Constants for action types
EXIT: Final[ActionID] = 0  # Exit
INFO: Final[ActionID] = 1  # Info & Warnings
ENCRYPT: Final[ActionID] = 2  # Encrypt
DECRYPT: Final[ActionID] = 3  # Decrypt
EMBED: Final[ActionID] = 4  # Embed
EXTRACT: Final[ActionID] = 5  # Extract
ENCRYPT_EMBED: Final[ActionID] = 6  # Encrypt & Embed
EXTRACT_DECRYPT: Final[ActionID] = 7  # Extract & Decrypt
CREATE_W_RANDOM: Final[ActionID] = 8  # Create w/ random
OVERWRITE_W_RANDOM: Final[ActionID] = 9  # Overwrite w/ random

# Dictionary mapping user input to actions/descriptions
ACTIONS: Final[dict[str, tuple[ActionID, str]]] = {
    '0': (EXIT, """action #0:
    exit application"""),

    '1': (INFO, """action #1:
    display info and warnings"""),

    '2': (ENCRYPT, """action #2:
    encrypt file contents and comments;
    write cryptoblob to new file"""),

    '3': (DECRYPT, """action #3:
    decrypt file; display decrypted comments
    and write decrypted contents to new file"""),

    '4': (EMBED, """action #4:
    embed file contents (no encryption):
    write input file contents over output file contents"""),

    '5': (EXTRACT, """action #5:
    extract file contents (no decryption) to new file"""),

    '6': (ENCRYPT_EMBED, """action #6:
    encrypt file contents and comments;
    write cryptoblob over container"""),

    '7': (EXTRACT_DECRYPT, """action #7:
    extract and decrypt cryptoblob;
    display decrypted comments and
    write decrypted contents to new file"""),

    '8': (CREATE_W_RANDOM, """action #8:
    create file of specified size with random data"""),

    '9': (OVERWRITE_W_RANDOM, """action #9:
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

# Tuples representing true and false boolean answers,
# including default false options
TRUE_BOOL_ANSWERS: Final[tuple[str, ...]] = ('Y', 'y', '1')
FALSE_BOOL_ANSWERS: Final[tuple[str, ...]] = ('N', 'n', '0')
DEFAULT_FALSE_BOOL_ANSWERS: Final[tuple[str, ...]] = ('', 'N', 'n', '0')

# Constants for proceed_request() function
PROCEED_OVERWRITE: Final[Literal[1, 2]] = 1
PROCEED_REMOVE: Final[Literal[1, 2]] = 2

# Size in bytes for processed comments;
# comments are padded or truncated to this size
PROCESSED_COMMENTS_SIZE: Final[int] = 512

# Invalid UTF-8 byte constant that separates comments from random data
# UTF-8 strings cannot contain the byte 0xFF
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
RW_CHUNK_SIZE: Final[int] = 128 * K

# Default values for custom options
DEFAULT_ARGON2_TIME_COST: Final[int] = 4
DEFAULT_MAX_PAD_SIZE_PERCENT: Final[int] = 20

# BLAKE2 constants
PERSON_SIZE: Final[int] = 16
PERSON_KEYFILE: Final[bytes] = \
    b'K' * PERSON_SIZE  # 0x4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b
PERSON_PASSPHRASE: Final[bytes] = \
    b'P' * PERSON_SIZE  # 0x50505050505050505050505050505050
IKM_DIGEST_SIZE: Final[int] = 64
MAC_KEY_SIZE: Final[int] = 64
MAC_TAG_SIZE: Final[int] = MAC_KEY_SIZE
CHECKSUM_SIZE: Final[int] = 32

# Defines the byte size of the byte string that specifies
# the length of the data being passed to the MAC function.
SIZE_BYTES_SIZE: Final[int] = 8  # Supports sizes up to 2^64-1

# Padding constants
PAD_KEY_SIZE: Final[int] = 16
PAD_KEY_SPACE: Final[int] = 256 ** PAD_KEY_SIZE
MAX_PAD_SIZE_PERCENT_LIMIT: Final[int] = 10 ** 20

# Argon2 constants
ARGON2_MEM: Final[int] = 512 * M  # Memory size for Argon2 in bytes
ARGON2_TAG_SIZE: Final[int] = PAD_KEY_SIZE * 2 + ENC_KEY_SIZE + MAC_KEY_SIZE

# Minimum valid size for cryptoblob in bytes
MIN_VALID_UNPADDED_SIZE: Final[int] = \
    SALTS_SIZE + PROCESSED_COMMENTS_SIZE + MAC_TAG_SIZE

# Check if debug mode is enabled via command line arguments
DEBUG: Final[bool] = cli_handler()


# Start the application
# --------------------------------------------------------------------------- #


if __name__ == '__main__':
    main()
