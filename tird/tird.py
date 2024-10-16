#!/usr/bin/env python3
"""
A tool for encrypting files and hiding encrypted data.

Dependencies:
- PyCryptodome: for data encryption.
- PyNaCl: for hashing and authentication.

SPDX-License-Identifier: CC0-1.0
"""

from gc import collect
from getpass import getpass
from hmac import compare_digest
from os import fsync, path, remove, urandom, walk
from signal import SIGINT, signal
from sys import argv, exit, platform, version
from time import monotonic
from typing import Any, BinaryIO, Final, Literal, NoReturn, Optional

from Cryptodome.Cipher import ChaCha20
from nacl.hashlib import blake2b
from nacl.pwhash import argon2id

# pylint: disable=consider-using-with
# pylint: disable=invalid-name
# pylint: disable=broad-exception-caught
# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-many-lines
# pylint: disable=too-many-locals
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-statements


# Functions for logging
# --------------------------------------------------------------------------- #


def log_d(debug_message: str) -> None:
    """Logs a message at the Debug level."""
    print(f'{ITA}D: {debug_message}{RES}')


def log_i(info_message: str) -> None:
    """Logs a message at the Info level."""
    print(f'{ITA}I: {info_message}{RES}')


def log_w(warning_message: str) -> None:
    """Logs a message at the Warning level."""
    print(f'{WAR}W: {warning_message}{RES}')


def log_e(error_message: str) -> None:
    """Logs a message at the Error level."""
    print(f'{ERR}E: {error_message}{RES}')


# Handle files: open, seek, read etc.
# --------------------------------------------------------------------------- #


def open_file(
    file_path: str,
    access_mode: Literal['rb', 'wb', 'rb+']
) -> Optional[BinaryIO]:
    """
    Opens a file in the specified mode and returns the file object.

    Args:
        file_path (str): The path to the file.
        access_mode (str): The mode in which to open the file.

    Returns:
        Optional[BinaryIO]: The file object if successful, None otherwise.
    """
    if DEBUG:
        log_d(f'opening file "{file_path}" in mode "{access_mode}"')

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
        file_path (str): The path to the file whose size is to be retrieved.

    Returns:
        Optional[int]: The size of the file in bytes if successful, None
            otherwise.
    """
    try:
        with open(file_path, 'rb') as file_obj:
            # Move to the end of the file
            file_size: int = file_obj.seek(0, 2)
            return file_size
    except Exception as error:
        log_e(f'{error}')
        return None


def seek_position(
    file_obj: BinaryIO,
    offset: int,
    whence: Literal[0, 1, 2] = 0
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
        whence (Literal[0, 1, 2]): The reference point for the offset.
            It can be one of the following:
            - 0: Beginning of the file (default)
            - 1: Current file position
            - 2: End of the file

    Returns:
        bool: True if the seek operation was successful, False otherwise.
    """
    if DEBUG:
        log_d(f'move to position {offset} in {file_obj}')

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
    try:
        data: bytes = file_obj.read(data_size)
    except OSError as error:
        log_e(f'{error}')
        return None

    if len(data) < data_size:
        log_e(f'the read data size ({len(data)} B) is less than '
              f'expected ({data_size} B)')
        return None

    return data


def write_data(data: bytes) -> bool:
    """
    Writes bytes to the global output file.

    Attempts to write the provided bytes to the output file associated
    with the global `bio_d['OUT']`.

    Args:
        data (bytes): Bytes to write.

    Returns:
        bool: True if written successfully, False otherwise.
    """
    try:
        out_file_obj: BinaryIO = bio_d['OUT']
        out_file_obj.write(data)
        return True
    except OSError as error:
        log_e(f'{error}')
        return False


def fsync_data() -> bool:
    """
    Flushes the global output file buffer and synchronizes to disk.

    Flushes the output buffer of the file associated with the global
    `bio_d['OUT']` and synchronizes its state to disk using the `fsync`
    method.

    Returns:
        bool: True if flushed and synchronized successfully,
              False otherwise.
    """
    try:
        # Get the output file object from the global `bio_d` dictionary
        out_file_obj: BinaryIO = bio_d['OUT']

        # Flush the output buffer
        out_file_obj.flush()

        # Synchronize the file to disk
        fsync(out_file_obj.fileno())
        return True
    except OSError as error:
        log_e(f'{error}')
        return False


# Handle user input
# --------------------------------------------------------------------------- #


def select_action() -> int:
    """
    Prompts the user to select an action from a predefined menu.

    Displays the menu and descriptions for each action, using global
    ACTIONS dictionary. Returns the selected action number (0-9) if
    a valid option is chosen.

    Returns:
        int: Selected action number (0-9).
    """
    while True:
        try:
            # Prompt the user to input an action number and remove any
            # leading/trailing whitespace
            user_input: str = input(MENU).strip()
        except EOFError:
            # Handle end-of-file error gracefully
            print()
            log_e('EOFError')
            continue

        # Check if the entered action is valid
        if user_input in ACTIONS:
            # Get the description of the action
            action_description: str = ACTIONS[user_input][1]

            # Log the action description
            log_i(action_description)

            # Retrieve the action number associated with the user input
            action: int = ACTIONS[user_input][0]

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
    prompt: str = f'{BOL}[02] Use custom settings? (Y/N, default=N):{RES} '

    # Start an infinite loop to get user input
    while True:
        try:
            user_input: str = input(prompt).strip()
        except EOFError:
            print()
            log_e('EOFError')
            continue

        # Check if the input indicates not to use custom settings
        if user_input in ('', 'N', 'n', '0'):
            # Return False if the user chooses not to use custom settings
            return False

        # Check if the input indicates to use custom settings
        if user_input in ('Y', 'y', '1'):
            # Return True if the user chooses to use custom settings
            return True

        log_e('invalid value; valid values are: Y, y, 1, N, n, 0')


def get_argon2_time_cost() -> int:
    """
    Prompts the user to input the Argon2 time cost.

    Asks the user for the Argon2 time cost value, using global
    formatting variables. The function will continue to prompt the user
    until a valid integer is provided. Returns the default value if the
    user provides an empty input or the default value. Ensures the input
    is a valid integer within the specified range (1 to OPSLIMIT_MAX).

    Returns:
        int: The Argon2 time cost value provided by the user or the default.
    """
    while True:
        try:
            # Get user input and remove any leading/trailing whitespace
            user_input: str = input(
                f'    {BOL}[03] Argon2 time cost (default'
                f'={DEFAULT_ARGON2_TIME_COST}):{RES} ').strip()
        except EOFError:
            print()
            log_e('EOFError')
            continue

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
    Ensures the input is a valid integer in the range [0;
    MAX_PAD_SIZE_PERCENT_LIMIT].

    Returns:
        int: The maximum padding size percentage provided by the user
             or the default.
    """
    while True:
        try:
            # Get user input and remove any leading/trailing whitespace
            user_input: str = input(
                f'    {BOL}[04] Max padding size, % (default'
                f'={DEFAULT_MAX_PAD_SIZE_PERCENT}):{RES} ').strip()
        except EOFError:
            print()
            log_e('EOFError')
            continue

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
    prompt: str = f'    {BOL}[05] Set fake MAC tag? (Y/N, default=N):{RES} '

    # Start an infinite loop to get user input
    while True:
        try:
            # Get user input and remove any leading/trailing whitespace
            user_input: str = input(prompt).strip()
        except EOFError:
            print()
            log_e('EOFError')
            continue

        # Check if the input indicates not to set a fake MAC tag
        if user_input in ('', 'N', 'n', '0'):
            # Return False if the user chooses not to set a fake MAC tag
            return False

        # Check if the input indicates to set a fake MAC tag
        if user_input in ('Y', 'y', '1'):
            # Return True if the user chooses to set a fake MAC tag
            return True

        # Log an error message for invalid input
        log_e('invalid value; valid values are: Y, y, 1, N, n, 0')


def get_input_file(action: int) -> tuple[str, int, BinaryIO]:
    """
    Prompts the user for an input file based on the specified action.

    Determines the type of input file required based on the provided
    action, using global formatting variables. Prompts the user to enter
    the file path, validates the input, and returns the file path, its
    size, and the file object.

    Args:
        action (int): Action determining the type of input file.

    Returns:
        tuple: Input file path, size, and file object.
    """
    # Dictionary mapping actions to corresponding prompt messages
    action_prompts: dict[int, str] = {
        2: 'File to encrypt',
        3: 'File to decrypt',
        4: 'File to embed',
        5: 'Container',
        6: 'File to encrypt and embed',
        7: 'Container'
    }

    # Get the prompt message based on the action provided
    prompt_message: Optional[str] = action_prompts.get(action)

    # Start an infinite loop to get a valid input file path
    while True:
        try:
            # Prompt the user for the input file path
            in_file_path: str = input(f'{BOL}[06] {prompt_message}:{RES} ')
        except EOFError:
            print()
            log_e('EOFError')
            continue

        # Check if the input file path is empty
        if not in_file_path:
            log_e('input file path is not specified')
            continue  # Prompt the user again

        # Log the real path if in DEBUG mode
        if DEBUG:
            log_d(f'real path: "{path.realpath(in_file_path)}"')

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


def get_output_file_new(action: int) -> tuple[str, BinaryIO]:
    """
    Prompts the user for a new output file path and creates the file.

    Determines the prompt based on the provided action, using global
    formatting variables. Prompts the user to enter the file path,
    validates the input, and returns the file path and file object.

    Args:
        action (int): Action being performed (2, 3, 5, 7, or 8).

    Returns:
        tuple: Output file path and file object.
    """
    # Determine the prompt message based on the action provided
    if action == 2:
        prompt_message: str = 'Output (encrypted) file'
    elif action in (3, 7):
        prompt_message = 'Output (decrypted) file'
    else:  # For actions 5 and 8
        prompt_message = 'Output file'

    # Start an infinite loop to get a valid output file path
    while True:
        try:
            # Prompt the user for the output file path
            out_file_path: str = input(f'{BOL}[07] {prompt_message}:{RES} ')
        except EOFError:
            print()
            log_e('EOFError')
            continue

        # Check if the input file path is empty
        if not out_file_path:
            log_e('output file path is not specified')
            continue  # Prompt the user again

        # Check if the file already exists
        if path.exists(out_file_path):
            # Log an error message
            log_e(f'file "{out_file_path}" already exists')
            continue  # Prompt the user again

        # Log the real path if in DEBUG mode
        if DEBUG:
            log_d(f'real path: "{path.realpath(out_file_path)}"')

        # Attempt to open the output file in binary write mode
        out_file_obj: Optional[BinaryIO] = open_file(out_file_path, 'wb')

        # Check if the file object was created successfully
        if out_file_obj is not None:
            # Return the valid file path and object
            return out_file_path, out_file_obj


def get_output_file_exist(
    in_file_path: str,
    min_out_size: int,
    action: int
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
        action (int): Action type.

    Returns:
        tuple: Output file path, size, and file object.
    """
    # Determine the prompt message based on the action provided
    if action in (4, 6):
        prompt_message: str = 'File to overwrite (container)'
    else:  # For action 9
        prompt_message = 'File to overwrite'

    # Start an infinite loop to get a valid output file path
    while True:
        try:
            # Prompt the user for the output file path
            out_file_path: str = input(f'{BOL}[07] {prompt_message}:{RES} ')
        except EOFError:
            print()
            log_e('EOFError')
            continue

        # Check if the input file path is empty
        if not out_file_path:
            log_e('output file path is not specified')
            continue

        # Check if the output file path is the same as the input file path
        if out_file_path == in_file_path:
            log_e('input and output files must not be at the same path')
            continue

        # Log the real path if in DEBUG mode
        if DEBUG:
            log_d(f'real path: "{path.realpath(out_file_path)}"')

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
    prompt_message: str = f'{BOL}[08] Output file size in bytes:{RES} '

    while True:
        try:
            # Get user input and strip any leading/trailing whitespace
            user_input: str = input(prompt_message).strip()
        except EOFError:
            print()
            log_e('EOFError')
            continue

        # Check if the user input is empty
        if not user_input:
            # Log error for empty input
            log_e('output file size is not specified')
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
        no_default (bool): If True, the user must provide a start position.

    Returns:
        int: A valid start position within the specified range.
    """
    while True:
        # Prompt the user for the start position and remove any
        # leading/trailing whitespace
        if no_default:
            try:
                user_input: str = input(
                    f'{BOL}[09] Start position, valid values '
                    f'are [0; {max_start_pos}]:{RES} ').strip()
            except EOFError:
                print()
                log_e('EOFError')
                continue

            # Check if the input is empty
            if not user_input:
                log_e('start position is not specified')
                continue
        else:
            try:
                user_input = input(
                    f'{BOL}[09] Start position, valid values '
                    f'are [0; {max_start_pos}], default=0:{RES} ').strip()
            except EOFError:
                print()
                log_e('EOFError')
                continue

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
        no_default (bool): If True, the user must provide an end position.

    Returns:
        int: A valid end position within the specified range.
    """
    while True:
        # Prompt the user for the end position and remove any
        # leading/trailing whitespace
        if no_default:
            try:
                user_input: str = input(
                    f'{BOL}[10] End position, valid values '
                    f'are [{min_pos}; {max_pos}]:{RES} ').strip()
            except EOFError:
                print()
                log_e('EOFError')
                continue
        else:
            try:
                user_input = input(
                    f'{BOL}[10] End position, valid values are [{min_pos}; '
                    f'{max_pos}], default={max_pos}:{RES} ').strip()
            except EOFError:
                print()
                log_e('EOFError')
                continue

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


def get_processed_comments() -> bytes:
    """
    Prompts the user for comments and processes them according to
    specified rules.

    The function requests comments from the user, utilizing global
    formatting variables.
    - If the input is empty, it generates random bytes.
    - If the input is not empty but shorter than
      PROCESSED_COMMENTS_SIZE, it appends a special separator byte and
      fills the remaining space with random bytes.
    - If the input exceeds PROCESSED_COMMENTS_SIZE, it truncates the
      input.

    Processed comments of standard length are needed for their further
    encryption, they are part of the plaintext.

    Returns:
        bytes: A byte representation of the comments or random bytes.
    """
    # Get raw comments
    while True:
        try:
            raw_comments: str = input(
                f'{BOL}[11] Comments (optional, up '
                f'to {PROCESSED_COMMENTS_SIZE} B):{RES} ')
            break
        except EOFError:
            print()
            log_e('EOFError')
            continue

    raw_comments_size: int = len(raw_comments)

    # Handle raw comments to get processed comments

    # Case 1: No comments provided
    if not raw_comments_size:
        if bool_d['set_fake_mac']:
            # Generate random bytes if the fake MAC option is enabled
            processed_comments: bytes = urandom(PROCESSED_COMMENTS_SIZE)
        else:
            # Continuously generate random bytes until a valid comment is
            # obtained. This ensures that the generated bytes do not decode
            # into a meaningful UTF-8 string.
            while True:
                processed_comments = urandom(PROCESSED_COMMENTS_SIZE)

                if decode_processed_comments(processed_comments) is None:
                    # Approximately 99.164% chance of success
                    # if PROCESSED_COMMENTS_SIZE=512
                    break

    # Case 2: Comments are provided and are within the valid size
    elif raw_comments_size <= PROCESSED_COMMENTS_SIZE:
        # Convert comments to bytes
        raw_comments_bytes: bytes = raw_comments.encode()

        # Construct processed_comments by appending a separator and random
        # bytes: append a special separator byte, fill the remaining space
        # with random bytes, ensure the total size does not exceed
        # PROCESSED_COMMENTS_SIZE.
        processed_comments = b''.join([
            raw_comments_bytes,
            INVALID_UTF8_BYTE,
            urandom(PROCESSED_COMMENTS_SIZE)
        ])[:PROCESSED_COMMENTS_SIZE]

    # Case 3: Comments exceed the maximum allowed size
    else:
        # Log a warning about truncation
        log_w(f'comments size: {raw_comments_size} B; '
              f'comments will be truncated!')

        # Sanitize comments to prevent potential UnicodeDecodeError
        sanitized_comments: str = raw_comments.encode(
        )[:PROCESSED_COMMENTS_SIZE].decode('utf-8', 'ignore')

        # Convert sanitized comments to bytes
        sanitized_comments_bytes: bytes = sanitized_comments.encode()

        # Truncate to the maximum size
        processed_comments = sanitized_comments_bytes[:PROCESSED_COMMENTS_SIZE]

    # Debug logging for comments and processed_comments
    if DEBUG:
        log_d(f'raw_comments: {[raw_comments]}, size: {raw_comments_size} B')
        log_d(f'processed_comments: {[processed_comments]}, '
              f'size: {len(processed_comments)} B')

    # Decode the comments for logging purposes
    comments_decoded: Optional[str] = \
        decode_processed_comments(processed_comments)
    log_i(f'comments will be shown as: {[comments_decoded]}')

    # Return the processed comments as bytes
    return processed_comments


def get_ikm_digest_list() -> list[bytes]:
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
    # List to store the digests of keying material
    ikm_digest_list: list[bytes] = []

    while True:
        try:
            # Prompt for the keyfile path
            keyfile_path: str = \
                input(f'{BOL}[12] Keyfile path (optional):{RES} ')
        except EOFError:
            print()
            log_e('EOFError')
            continue

        if not keyfile_path:
            # Exit the loop if the user does not enter a path
            break

        if not path.exists(keyfile_path):
            # Log error if the keyfile path does not exist
            log_e(f'file "{keyfile_path}" does not exist')
            log_e('keyfile NOT accepted')
            # Move to the next iteration of the loop
            continue

        if DEBUG:
            # Log the real path of the file
            log_d(f'real path: "{path.realpath(keyfile_path)}"')

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
                log_w('no files found in this directory; '
                      'no keyfiles to accept!')
            else:
                # Add the digests to the main list
                ikm_digest_list.extend(digest_list)

                # Log the number of accepted files
                log_i(f'{len(digest_list)} keyfiles have been accepted')

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

    if DEBUG:
        log_w('entered passphrases will be displayed!')

    while True:
        try:
            # Prompt for the first passphrase
            passphrase_1: bytes = getpass(
                f'{BOL}[13] Passphrase (optional):{RES} '
            ).encode()[:PASSPHRASE_SIZE_LIMIT]
        except EOFError:
            print()
            log_e('EOFError')
            log_e('passphrase NOT accepted')
            continue

        if not passphrase_1:
            break  # Exit the loop if the user does not enter a passphrase

        if DEBUG:
            # Log the entered passphrase
            log_d(f'passphrase (encoded): {passphrase_1!r}')

            # Log the length of the passphrase
            log_d(f'passphrase length: {len(passphrase_1)} B')

        try:
            # Prompt for confirming the passphrase
            passphrase_2: bytes = getpass(
                f'{BOL}[13] Confirm passphrase:{RES} '
            ).encode()[:PASSPHRASE_SIZE_LIMIT]
        except EOFError:
            print()
            log_e('EOFError')
            log_e('passphrase NOT accepted')
            continue

        if DEBUG:
            # Log the confirmed passphrase
            log_d(f'passphrase (encoded): {passphrase_2!r}')

            # Log the length of the confirmed passphrase
            log_d(f'passphrase length: {len(passphrase_2)} B')

        if compare_digest(passphrase_1, passphrase_2):
            # Log acceptance of the passphrase
            log_i('passphrase accepted')

            # Get the digest of the passphrase
            passphrase_digest: bytes = get_passphrase_digest(passphrase_1)

            # Add the digest to the list
            ikm_digest_list.append(passphrase_digest)
        else:
            # Log error if confirmation fails
            log_e('passphrase confirmation failed; passphrase NOT accepted')

        del passphrase_1, passphrase_2  # Clear variables
        collect()  # Garbage collection

    return ikm_digest_list  # Return the list of digests


def proceed_request(proceed_type: int) -> bool:
    """
    Prompts the user to confirm whether to proceed with an action.

    The prompt message and default behavior depend on the value of the
    `proceed_type` parameter:
    - If `proceed_type` is 1, the prompt warns that the output file
      contents will be partially overwritten, and the default is to not
      proceed.
    - If `proceed_type` is 2, the prompt informs that the next step is
      to remove the output file path, and the default is to proceed.

    Args:
        proceed_type (int): An integer value that determines the prompt
                            message and default behavior.

    Returns:
        bool: True if the user confirms to proceed, False otherwise.
    """
    # Check the action type to determine the appropriate prompt message
    if proceed_type == 1:
        log_w('output file contents will be partially overwritten!')

        # Prompt for action type 1
        prompt_message: str = f'{BOL}[14] Proceed? (Y/N):{RES} '
    else:
        log_i('next it\'s offered to remove the output file path')

        # Prompt for action type 2
        prompt_message = f'{BOL}[14] Proceed? (Y/N, default=Y):{RES} '

    while True:
        try:
            # Get user input and strip any leading/trailing whitespace
            user_input: str = input(prompt_message).strip()
        except EOFError:
            print()
            log_e('EOFError')
            continue

        # Check if the user wants to proceed (affirmative response)
        if user_input in ('Y', 'y', '1'):
            return True

        # If no input is given and proceed_type is 2, default to proceeding
        if not user_input and proceed_type == 2:
            return True

        # Check if the user wants to cancel (negative response)
        if user_input in ('N', 'n', '0'):
            return False

        # Log an error message for invalid input
        log_e('invalid value; valid values are: Y, y, 1, N, n, 0')


# Handle various things to perform actions
# --------------------------------------------------------------------------- #


def set_custom_settings(action: int) -> None:
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
        - If the action is 2 or 6, it checks whether to set a fake
          MAC tag.

    If custom settings are not enabled, default values are used for
    these settings.

    The function logs the settings for debugging purposes if the DEBUG
    flag is set. It also modifies global dictionaries to store the
    settings.

    Args:
        action (int): The action that triggered the setting of custom settings.
                      This determines which custom settings to apply.
                      Actions 2 and 6 require specific custom values.

    Returns:
        None: This function does not return a value.
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
        if action in (2, 6):
            log_w('decryption will require the same custom values!')

        # Retrieve custom Argon2 time cost and maximum padding size percentage
        argon2_time_cost = get_argon2_time_cost()
        max_pad_size_percent = get_max_pad_size_percent()

        # Check if a fake MAC tag should be set for specific actions
        if action in (2, 6):
            should_set_fake_mac = is_fake_mac()

    # Log the settings if custom settings is enabled
    if is_custom_enabled:
        log_i(f'Argon2 time cost: {argon2_time_cost}')
        log_i(f'max padding size, %: {max_pad_size_percent}')

        if action in (2, 6):
            log_i(f'set fake MAC tag: {should_set_fake_mac}')

    # Log the settings if debugging is enabled
    if DEBUG and not is_custom_enabled:
        log_d(f'Argon2 time cost: {argon2_time_cost}')
        log_d(f'max padding size, %: {max_pad_size_percent}')

        if action in (2, 6):
            log_d(f'set fake MAC tag: {should_set_fake_mac}')

    # Store the settings in the global `int_d` dictionary
    int_d['argon2_time_cost'] = argon2_time_cost
    int_d['max_pad_size_percent'] = max_pad_size_percent

    # If the action requires it, store the fake MAC tag setting
    if action in (2, 6):
        bool_d['set_fake_mac'] = should_set_fake_mac


def get_salts(input_size: int, end_pos: int, action: int) -> bool:
    """
    Retrieves and generates salts for cryptographic operations based
    on the specified action.

    Depending on the action provided, the function either generates
    new salts or reads existing salts from a cryptoblob. For actions
    2 and 6, new salts are generated using random bytes. For actions
    3 and 7, the function reads salts from the beginning and end of
    the cryptoblob.

    Args:
        input_size (int): The size of the input data, used to determine
                          positions for reading salts.
        end_pos (int): The end position in the cryptoblob, used for
                       calculating the footer salt position.
        action (int): The action that determines how salts are handled.
                      Actions 2 and 6 generate new salts, while actions
                      3 and 7 read existing salts.

    Returns:
        bool: True if salts were successfully retrieved or generated,
              False otherwise.
    """
    # Log the start of salt handling if debugging is enabled
    if DEBUG:
        log_d('salt handling...')

    # Check if the action requires generating new salts
    if action in (2, 6):
        # Generate random salts for BLAKE2b and Argon2
        blake2_salt: bytes = urandom(ONE_SALT_SIZE)
        argon2_salt: bytes = urandom(ONE_SALT_SIZE)

        # Create header salt by combining the first halves of both salts
        header_salt: bytes = b''.join([
            blake2_salt[:ONE_SALT_HALF_SIZE],
            argon2_salt[:ONE_SALT_HALF_SIZE]
        ])

        # Create footer salt by combining the last halves of both salts
        footer_salt: bytes = b''.join([
            blake2_salt[-ONE_SALT_HALF_SIZE:],
            argon2_salt[-ONE_SALT_HALF_SIZE:]
        ])
    else:
        # Read the salts from the cryptoblob for actions 3 and 7
        read_data_result: Optional[bytes] = read_data(
            bio_d['IN'], SALTS_HALF_SIZE)

        # Return False if reading the header salt fails
        if read_data_result is None:
            return False

        # Store the header salt
        header_salt = read_data_result

        # Log that the header salt has been read if debugging is enabled
        if DEBUG:
            log_d('header_salt has been read')
            log_positions()

        # Save the current position in the cryptoblob
        current_pos: int = bio_d['IN'].tell()

        # Determine the new position based on the action
        if action == 3:
            new_pos: int = input_size - SALTS_HALF_SIZE
        else:  # action == 7
            new_pos = end_pos - SALTS_HALF_SIZE

        # Move to the position for reading the footer salt
        if not seek_position(bio_d['IN'], new_pos):
            return False

        # Log the current position before reading the footer salt
        if DEBUG:
            log_d('current position: before footer_salt')
            log_positions()

        # Read the footer salt from the cryptoblob
        read_data_result = read_data(bio_d['IN'], SALTS_HALF_SIZE)

        # Return False if reading the footer salt fails
        if read_data_result is None:
            return False

        # Store the footer salt
        footer_salt = read_data_result

        # Log that the footer salt has been read if debugging is enabled
        if DEBUG:
            log_d('footer_salt has been read')
            log_positions()

        # Move back to the previously saved position
        if not seek_position(bio_d['IN'], current_pos):
            return False

        # Log that we have returned to the position after reading
        # the header salt
        if DEBUG:
            log_d('returned to the position after header_salt')
            log_positions()

        # Combine header and footer salts to create BLAKE2b and Argon2 salts
        blake2_salt = b''.join([
            header_salt[:ONE_SALT_HALF_SIZE],
            footer_salt[:ONE_SALT_HALF_SIZE]
        ])

        argon2_salt = b''.join([
            header_salt[-ONE_SALT_HALF_SIZE:],
            footer_salt[-ONE_SALT_HALF_SIZE:]
        ])

    # Store the generated or retrieved salts in the global `bytes_d` dictionary
    bytes_d['blake2_salt'] = blake2_salt
    bytes_d['argon2_salt'] = argon2_salt
    bytes_d['header_salt'] = header_salt
    bytes_d['footer_salt'] = footer_salt

    # Log the salts if debugging is enabled
    if DEBUG:
        log_d(f'blake2_salt: {blake2_salt.hex()}')
        log_d(f'argon2_salt: {argon2_salt.hex()}')
        log_d(f'header_salt: {header_salt.hex()}')
        log_d(f'footer_salt: {footer_salt.hex()}')
        log_d('salt handling is completed')

    return True


def blake2b_keyfile_digest(
    file_obj: BinaryIO,
    file_size: int,
) -> Optional[bytes]:
    """
    Computes the BLAKE2b digest of a keyfile using the specified salt.

    This function reads the contents of the provided file in chunks and
    updates the BLAKE2b hash object with the data read. The final digest
    is returned as a byte string.

    Args:
        file_obj (BinaryIO): A file-like object to read data from.
        file_size (int): The total size of the file in bytes.

    Returns:
        Optional[bytes]: The computed BLAKE2b digest as a byte string,
                         or None if an error occurs during reading.
    """
    # Create a BLAKE2b hash object with
    # the specified digest size, person, and salt
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        person=PERSON_KEYFILE,
        salt=bytes_d['blake2_salt']
    )

    # Calculate the number of complete chunks and remaining bytes to r/w
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

    # Compute the final BLAKE2b digest
    keyfile_digest: bytes = hash_obj.digest()

    # Return the computed digest
    return keyfile_digest


def get_keyfile_digest(file_path: str) -> Optional[bytes]:
    """
    Calculates the BLAKE2b digest of the keyfile at the given file path.

    Args:
        file_path (str): The path to the keyfile.

    Returns:
        Optional[bytes]: The BLAKE2b digest of the keyfile, or None if
                         an error occurs.
    """
    # Get the size of the file at the specified path
    file_size: Optional[int] = get_file_size(file_path)

    # If the file size could not be determined, return None
    if file_size is None:
        return None

    # Log the file path and its size for informational purposes
    log_i(f'path: "{file_path}"; size: {format_size(file_size)}')
    log_i('hashing the keyfile...')

    # Open the file in binary read mode
    file_obj: Optional[BinaryIO] = open_file(file_path, 'rb')

    # If the file could not be opened, return None
    if file_obj is None:
        return None

    # Calculate the BLAKE2b digest of the keyfile
    file_digest: Optional[bytes] = blake2b_keyfile_digest(file_obj, file_size)

    # Close the file after reading
    close_file(file_obj)

    # If the digest could not be computed, return None
    if file_digest is None:
        return None

    # Log the computed digest if debugging is enabled
    if DEBUG:
        log_d(f'digest:\n    {file_digest.hex()}')

    # Return the computed BLAKE2b keyfile digest
    return file_digest


def get_keyfile_digest_list(directory_path: str) -> Optional[list[bytes]]:
    """
    Scans the specified directory for keyfiles and computes their
    BLAKE2b digests.

    This function traverses the directory at the given path, collects
    the paths of all files, and computes their BLAKE2b digests using
    the `blake2b_keyfile_digest` function. It logs the process and
    handles any errors that occur during file access.

    Args:
        directory_path (str): The path to the directory to scan for keyfiles.

    Returns:
        Optional[list]: A list of BLAKE2b digests for the keyfiles found
                        in the directory, or None if an error occurs.
                        If no files are found, an empty list is returned.
    """
    def walk_error_handler(error: Any) -> None:
        """Handle walk error by logging the error and raising an exception."""
        log_e(f'{error}')
        raise PermissionError

    # ----------------------------------------------------------------------- #

    # Log the start of the directory scanning process
    log_i(f'scanning the directory "{directory_path}"')

    # Initialize a list to store the paths of found keyfiles
    file_path_list: list[str] = []

    try:
        # Traverse the directory and collect file paths
        for root, _, files in walk(directory_path, onerror=walk_error_handler):
            for file_name in files:
                # Construct the full file path and add it to the list
                full_file_path: str = path.join(root, file_name)
                file_path_list.append(full_file_path)
    except PermissionError:
        # Return None if a exception is raised during directory traversal
        return None

    # Get the number of files found
    file_count: int = len(file_path_list)

    # Log the number of files found
    log_i(f'found {file_count} files')

    # If no files are found, return an empty list
    if not file_count:
        return []

    # ----------------------------------------------------------------------- #

    # Initialize a list to store file information (path and size)
    file_info_list: list[tuple[str, int]] = []

    # Initialize a variable to keep track of the total size of files
    total_size: int = 0

    # Iterate over the collected file paths to get their sizes
    for full_file_path in file_path_list:
        if DEBUG:
            log_d(f'getting the size of "{full_file_path}" '
                  f'(real path: "{path.realpath(full_file_path)}")')

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

    # Log the details of each found file
    for file_info in file_info_list:
        full_file_path, file_size = file_info
        log_i(f'- path: "{full_file_path}"; size: {format_size(file_size)}')

    # Log the total number of files found and their combined size
    log_i(f'total size: {format_size(total_size)}')

    # ----------------------------------------------------------------------- #

    # Log the start of the hashing process for the files
    log_i(f'hashing files in the directory "{directory_path}"')

    # Initialize a list to store the computed digests
    digest_list: list[bytes] = []

    # Iterate over the file information to compute digests
    for file_info in file_info_list:
        full_file_path, file_size = file_info

        if DEBUG:
            log_d(f'hashing "{full_file_path}"')

        # Open the file for reading in binary mode
        file_obj: Optional[BinaryIO] = open_file(full_file_path, 'rb')

        # If the file cannot be opened, return None
        if file_obj is None:
            return None

        # Compute the BLAKE2b digest of the keyfile
        file_digest: Optional[bytes] = \
            blake2b_keyfile_digest(file_obj, file_size)

        # Close the file after reading
        close_file(file_obj)

        # If the digest could not be computed, return None
        if file_digest is None:
            return None

        if DEBUG:
            log_d(f'digest:\n    {file_digest.hex()}')

        # Add the computed digest to the list
        digest_list.append(file_digest)

    # Return the list of computed digests
    return digest_list


def get_passphrase_digest(passphrase: bytes) -> bytes:
    """
    Computes the BLAKE2b digest of the provided passphrase.

    This function takes a passphrase in bytes, updates the BLAKE2b hash
    object with the passphrase, and returns the resulting digest. The
    digest is computed using a specific salt and personalization string.

    Args:
        passphrase (bytes): The passphrase to be hashed, provided as
                            a byte string.

    Returns:
        bytes: The BLAKE2b digest of the passphrase as a byte string.
    """
    # Create a BLAKE2b hash object with the specified
    # digest size, personalization, and salt
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        person=PERSON_PASSPHRASE,
        salt=bytes_d['blake2_salt']
    )

    # Update the hash object with the provided passphrase
    hash_obj.update(passphrase)

    # Compute the final digest of the passphrase
    digest: bytes = hash_obj.digest()

    if DEBUG:
        log_d(f'passphrase digest:\n    {digest.hex()}')

    return digest


def get_argon2_password() -> None:
    """
    Computes the Argon2 password from the input keying material.

    This function retrieves a list of keying material digests using the
    `get_ikm_digest_list` function. It logs the completion of the keying
    material entry process and checks if any digests were retrieved. If
    no digests are available, a warning is logged.

    The function sorts the digest list and computes the Argon2 password
    using the BLAKE2b hash function. The resulting digest is stored
    in the global `bytes_d` dictionary under the key 'argon2_password'.

    Debug information is logged throughout the process if the DEBUG flag
    is set, including the sorted digests and the final Argon2 password
    digest.

    Returns:
        None: This function does not return a value. The computed Argon2
        password digest is stored in the global `bytes_d` dictionary.
    """
    # Retrieve the list of keying material digests
    digest_list: list[bytes] = get_ikm_digest_list()

    # Log the completion of the keying material entry process
    log_i('entering keying material is completed')

    # Check if any digests were retrieved and log a warning if not
    if not digest_list:
        log_w('no keyfile or passphrase specified!')

    # Log debug information if enabled
    if DEBUG:
        log_d('user input is complete')
        log_positions()

    # Sort the digest list
    digest_list.sort()

    # Log sorted digests if debugging is enabled
    if DEBUG and digest_list:
        log_d('sorted digests of keying material items:')
        for digest in digest_list:
            log_d(f'{digest.hex()}')

    # Create a BLAKE2b hash object for computing the Argon2 password
    hash_obj: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        salt=bytes_d['blake2_salt']
    )

    # Update the hash object with each digest in the sorted list
    for digest in digest_list:
        hash_obj.update(digest)

    # Store the computed Argon2 password in the global `bytes_d` dictionary
    bytes_d['argon2_password'] = hash_obj.digest()

    # Log the final Argon2 password digest if debugging is enabled
    if DEBUG:
        argon2_password: bytes = bytes_d['argon2_password']
        log_d(f'argon2_password:\n    {argon2_password.hex()}')


def derive_keys() -> bool:
    """
    Derives cryptographic keys using the Argon2 Memory-Hard Function.

    This function computes the encryption, padding, and MAC keys from
    the Argon2 password stored in the global `bytes_d` dictionary. It
    uses the Argon2 key derivation function with specified parameters
    such as salt, time cost, and memory limit. The derived keys are then
    stored back into the `bytes_d` dictionary.

    The function logs the process, including the time taken to derive
    the keys and the values of the derived keys if the DEBUG flag is
    enabled.

    Returns:
        bool: True if the keys were successfully derived, False if an
              error occurred during the key derivation process.
    """
    log_i('deriving one-time keys...')

    start_time: float = monotonic()

    try:
        argon2_tag: bytes = argon2id.kdf(
            size=ARGON2_TAG_SIZE,
            password=bytes_d['argon2_password'],
            salt=bytes_d['argon2_salt'],
            opslimit=int_d['argon2_time_cost'],
            memlimit=ARGON2_MEM
        )
    except RuntimeError as e:
        log_e(f'{e}')
        # Return False if an error occurred
        return False

    end_time: float = monotonic()

    # Split the derived key material into individual keys
    # enc_key || pad_key ||  mac_key = argon2_tag
    enc_key: bytes = argon2_tag[:ENC_KEY_SIZE]
    pad_key: bytes = argon2_tag[ENC_KEY_SIZE:ENC_KEY_SIZE + PAD_KEY_SIZE]
    mac_key: bytes = argon2_tag[-MAC_KEY_SIZE:]

    # If debugging is enabled, log the derived keys and key material
    if DEBUG:
        log_d(f'argon2_tag:\n    {argon2_tag.hex()}')
        log_d(f'enc_key:\n    {enc_key.hex()}')
        log_d(f'pad_key:\n    {pad_key.hex()}')
        log_d(f'mac_key:\n    {mac_key.hex()}')

    # Log the time taken to derive the keys
    log_i(f'keys derived in {round(end_time - start_time, 1)}s')

    # Store the derived keys back into the global `bytes_d` dictionary
    bytes_d['enc_key'] = enc_key
    bytes_d['pad_key'] = pad_key
    bytes_d['mac_key'] = mac_key

    # Return True to indicate successful key derivation
    return True


def encrypt_decrypt(input_data: bytes) -> bytes:
    """
    Encrypts or decrypts a data chunk using the ChaCha20 cipher.

    This function increments the nonce counter, generates a nonce based
    on the current counter value, and then uses the ChaCha20 cipher to
    encrypt or decrypt the provided input data. The output is returned
    as a byte string.

    Args:
        input_data (bytes): The data to be encrypted or decrypted. This
                            should be provided as a byte string.

    Returns:
        bytes: The encrypted or decrypted output data,
               also as a byte string.
    """
    # Increment the nonce counter for the encryption/decryption process
    int_d['nonce_counter'] += 1

    # Get the current value of the nonce counter
    current_nonce_counter: int = int_d['nonce_counter']

    # Generate a nonce from the current nonce counter
    nonce: bytes = current_nonce_counter.to_bytes(NONCE_SIZE, BYTEORDER)

    # Create a ChaCha20 cipher object with the encryption key and nonce
    chacha20_cipher: Any = ChaCha20.new(key=bytes_d['enc_key'], nonce=nonce)

    # Encrypt or decrypt the input data using the cipher
    output_data: bytes = chacha20_cipher.encrypt(input_data)

    # Log the nonce counter and nonce if debugging is enabled
    if DEBUG:
        log_d(f'nonce counter: {current_nonce_counter}, nonce: {nonce.hex()}')

    return output_data


def pad_from_ciphertext(
    ciphertext_size: int,
    pad_key1_bytes: bytes,
    max_pad_size_percent: int
) -> int:
    """
    Calculates the padding size based on the ciphertext size and a
    padding key.

    This function computes the total padding size to be applied to the
    ciphertext based on the provided parameters. The padding size is
    determined by the size of the ciphertext, a padding key converted
    from bytes to an integer, and a maximum padding size percentage.

    Args:
        ciphertext_size (int): The size of the ciphertext in bytes. This
            value is used to calculate the total padding size.

        pad_key1_bytes (bytes): A byte string representing the first
            padding key. This key is converted to an integer to influence
            the padding size calculation.

        max_pad_size_percent (int): The maximum percentage of the
            ciphertext size that can be used for padding. This value must
            not be negative.

    Returns:
        int: The calculated padding size in bytes.
    """
    # Convert the padding key from bytes to an integer
    pad_key1_int: int = int.from_bytes(pad_key1_bytes, BYTEORDER)

    # Calculate the padding size based on
    # the ciphertext size, padding key, and max padding percentage
    pad_size: int = ciphertext_size * max_pad_size_percent * pad_key1_int // (
        PAD_KEY_SPACE * 100)

    # If debugging is enabled, log detailed information
    # about the padding calculation
    if DEBUG:
        log_d('getting total pad size...')
        log_d(f'pad_key1_bytes:             {pad_key1_bytes.hex()}')
        log_d(f'pad_key1_int:               {pad_key1_int}')
        log_d(f'pad_key1_int/PAD_KEY_SPACE: {pad_key1_int/PAD_KEY_SPACE}')
        log_d(f'ciphertext_size:            {format_size(ciphertext_size)} B')
        log_d(f'pad_size:                   {format_size(pad_size)}')
        log_d(f'pad_size/ciphertext_size:   {pad_size/ciphertext_size}')

    # Return the calculated padding size
    return pad_size


def pad_from_padded_ciphertext(
    padded_ciphertext_size: int,
    pad_key1_bytes: bytes,
    max_pad_size_percent: int
) -> int:
    """
    Calculates the padding size based on the padded ciphertext size and
    the padding key.

    This function computes the padding size that can be applied to the
    padded ciphertext (ciphertext size plus padding size) using the
    specified padding key and maximum padding percentage. The padding
    size is calculated based on the size of the padded ciphertext and
    the value of the padding key converted to an integer.

    Args:
        padded_ciphertext_size (int): The size of the padded ciphertext
            in bytes. This parameter is used to calculate the total padding
            size.

        pad_key1_bytes (bytes): A byte string representing the first
            padding key. This key is converted to an integer to influence
            the padding size calculation.

        max_pad_size_percent (int): The maximum percentage of the padded
            ciphertext size that can be used for padding. This value must
            not be negative.

    Returns:
        int: The calculated padding size in bytes.
    """
    # Convert the padding key from bytes to an integer
    pad_key1_int: int = int.from_bytes(pad_key1_bytes, BYTEORDER)

    # Calculate the padding size based on the padded ciphertext size,
    # padding key, and maximum padding percentage
    pad_size: int = \
        padded_ciphertext_size * pad_key1_int * max_pad_size_percent // (
            pad_key1_int * max_pad_size_percent + PAD_KEY_SPACE * 100)

    # If debugging is enabled, log detailed information about
    # the padding calculation
    if DEBUG:
        log_d('getting total pad size...')
        log_d(f'pad_key1_bytes:             {pad_key1_bytes.hex()}')
        log_d(f'pad_key1_int:               {pad_key1_int}')
        log_d(f'pad_key1_int/PAD_KEY_SPACE: {pad_key1_int / PAD_KEY_SPACE}')
        log_d(f'padded_ciphertext_size:     '
              f'{format_size(padded_ciphertext_size)}')
        log_d(f'pad_size:                   {format_size(pad_size)}')

        ciphertext_size: int = padded_ciphertext_size - pad_size

        log_d(f'ciphertext_size:            {format_size(ciphertext_size)}')
        log_d(f'pad_size/ciphertext_size:   {pad_size / ciphertext_size}')

    # Return the calculated padding size
    return pad_size


def header_footer_pads(
    pad_size: int,
    pad_key2_bytes: bytes
) -> tuple[int, int]:
    """
    Calculates the sizes of the header and footer pads based on the
    given total pad size and key.

    Args:
        pad_size (int): The total size of the pad to be used for
            calculating the header and footer pad sizes.
        pad_key2_bytes (bytes): The key in byte format that will be
            converted to an integer for pad size calculations.

    Returns:
        tuple: A tuple containing two values:
            - header_pad_size (int): The size of the header pad.
            - footer_pad_size (int): The size of the footer pad.

    Notes:
        - The sizes of the pads are calculated based on the remainder
          of the integer obtained from the byte key divided by
          (pad_size + 1).
    """
    # Convert the padding key from bytes to an integer
    pad_key2_int: int = int.from_bytes(pad_key2_bytes, BYTEORDER)

    # Calculate the size of the header pad using the modulus operation
    header_pad_size: int = pad_key2_int % (pad_size + 1)

    # Calculate the size of the footer pad by subtracting the header pad
    # size from the total pad size
    footer_pad_size: int = pad_size - header_pad_size

    # If debugging is enabled, log detailed information about the padding sizes
    if DEBUG:
        log_d('getting sizes of header_pad and footer_pad...')
        log_d(f'pad_key2_bytes:   {pad_key2_bytes.hex()}')
        log_d(f'pad_key2_int:     {pad_key2_int}')
        log_d(f'header_pad_size:  {format_size(header_pad_size)}')
        log_d(f'footer_pad_size:  {format_size(footer_pad_size)}')

    # Return the sizes of the header and footer pads as a tuple
    return header_pad_size, footer_pad_size


def handle_padding(
    pad_size: int,
    action: int,
    written_sum: int,
    start_time: float,
    last_progress_time: float,
    output_data_size: int
) -> Optional[tuple[int, float]]:
    """
    Handles padding operations based on the specified action.

    This function performs different operations depending on the value
    of `action`. If the action is 2 or 6, it writes random data chunks
    of size `RW_CHUNK_SIZE` to a target until the total padding size is
    reached. If the action is 3 or 7, it seeks to a specified position
    in the data.

    Args:
        pad_size (int): The total size of the padding to be handled.
        action (int): The action to be performed (2 or 6 for writing
            data, 3 or 7 for seeking).
        written_sum (int): The cumulative size of written data so far.
        start_time (float): The start time of the operation, used for
            progress tracking.
        last_progress_time (float): The last time the progress was printed,
            used to control print frequency.
        output_data_size (int): The total size of the output data, used
            for progress calculation.

    Returns:
        Optional[tuple]: A tuple containing:
            - written_sum (int): The updated cumulative size of written data.
            - last_progress_time (float): The updated last progress time.
        Returns None if an error occurs during writing or seeking
            operations.

    Notes:
        - The function uses `urandom` to generate random data chunks.
        - Progress is printed at intervals defined by `MIN_PROGRESS_INTERVAL`.
    """
    # Check if the action is to write data (2 or 6)
    if action in (2, 6):
        # Calculate the number of complete chunks and remaining bytes to write
        num_complete_chunks: int = pad_size // RW_CHUNK_SIZE
        num_remaining_bytes: int = pad_size % RW_CHUNK_SIZE

        # Write the full chunks of random data
        for _ in range(num_complete_chunks):
            # Generate a random data chunk of size RW_CHUNK_SIZE
            chunk: bytes = urandom(RW_CHUNK_SIZE)

            # Attempt to write the chunk; return None if it fails
            if not write_data(chunk):
                return None

            # Update the cumulative size of written data
            written_sum += len(chunk)

            # Check if it's time to print progress
            if monotonic() - last_progress_time >= MIN_PROGRESS_INTERVAL:
                # Print the progress of the operation
                log_progress(written_sum, output_data_size, start_time)
                # Update the last print time
                last_progress_time = monotonic()

        # If there is remaining data to write, handle it
        if num_remaining_bytes:
            # Generate a random data chunk of the remaining size
            chunk = urandom(num_remaining_bytes)

            # Attempt to write the remaining chunk; return None if it fails
            if not write_data(chunk):
                return None

            # Update the cumulative size of written data
            written_sum += len(chunk)

            # Check if it's time to print progress again
            if monotonic() - last_progress_time >= MIN_PROGRESS_INTERVAL:
                # Print the progress of the operation
                log_progress(written_sum, output_data_size, start_time)
                # Update the last print time
                last_progress_time = monotonic()
    else:  # If the action is to seek (3 or 7)
        # Attempt to seek to the specified position; return None if it fails
        if not seek_position(bio_d['IN'], pad_size, 1):
            return None

    # Return the updated cumulative size of written data
    # and the last progress time
    return written_sum, last_progress_time


def decode_processed_comments(processed_comments: bytes) -> Optional[str]:
    """
    Decodes a byte string of processed comments
    into a UTF-8 string.

    This function takes a byte string containing processed comments and
    attempts to decode it into a UTF-8 string. If the byte string
    contains an invalid UTF-8 byte sequence, the function will return
    None. The function also ignores any comments that appear after the
    first occurrence of an invalid UTF-8 byte.

    Args:
        processed_comments (bytes): The byte string containing
            processed_comments to be decoded.

    Returns:
        Optional[str]: The decoded UTF-8 string if successful, or None
            if decoding fails due to invalid UTF-8 byte sequences.

    Notes:
        - The function uses the `partition` method to split the input
          byte string at the first occurrence of `INVALID_UTF8_BYTE`,
          discarding any comments that follow.
        - If the input byte string is valid UTF-8, it will be returned
          as a string.
        - If a `UnicodeDecodeError` occurs during decoding, None is
          returned.
    """
    # Split the input byte string at the first occurrence of INVALID_UTF8_BYTE
    # and keep only the part before it
    processed_comments_part: bytes = \
        processed_comments.partition(INVALID_UTF8_BYTE)[0]

    try:
        # Attempt to decode the byte string into a UTF-8 string
        decoded_comments: Optional[str] = \
            processed_comments_part.decode('utf-8')
    except UnicodeDecodeError:
        decoded_comments = None

    # Return the decoded comments or None if decoding failed
    return decoded_comments


def format_size(size: int) -> str:
    """
    Converts a size in bytes to a human-readable string representation.

    This function takes an integer representing a size in bytes and
    converts it into a more readable format, displaying the size in
    bytes along with its equivalent in EiB, PiB, TiB, GiB, MiB, or KiB,
    depending on the size.

    Args:
        size (int): The size in bytes to be converted.

    Returns:
        str: A string representation of the size, including the original
             size in bytes and its equivalent in EiB, PiB, TiB, GiB, MiB,
             or KiB, as appropriate.
    """
    formatted_size: str

    if size >= E:
        formatted_size = f'{size} B, {round(size / E, 1)} EiB'
    elif size >= P:
        formatted_size = f'{size} B, {round(size / P, 1)} PiB'
    elif size >= T:
        formatted_size = f'{size} B, {round(size / T, 1)} TiB'
    elif size >= G:
        formatted_size = f'{size} B, {round(size / G, 1)} GiB'
    elif size >= M:
        formatted_size = f'{size} B, {round(size / M, 1)} MiB'
    elif size >= K:
        formatted_size = f'{size} B, {round(size / K, 1)} KiB'
    else:
        formatted_size = f'{size} B'

    return formatted_size


def log_progress(
    written_sum: int,
    total_data_size: int,
    start_time: float
) -> None:
    """
    Logs the progress of a data writing operation.

    This function calculates and logs the amount of data written, the
    percentage of completion, the elapsed time since the start of the
    operation, and the average writing speed in MiB/s. If no data has
    been written, it logs a message indicating that 0 bytes have
    been written.

    Args:
        written_sum (int): The total amount of data written so far,
                           in bytes.
        total_data_size (int): The total size of the data to be written,
                               in bytes.
        start_time (float): The start time of the writing operation,
                            measured in seconds since an arbitrary point in
                            time.

    Returns:
        None: This function does not return a value;
              it logs progress information.
    """
    # Check if the total data size is zero to avoid division by zero
    if not total_data_size:
        log_i('written 0 B')  # Log that no data has been written
        return

    # Calculate the elapsed time since the start of the operation
    elapsed_time: float = monotonic() - start_time

    # Calculate the percentage of data written
    percentage: float = written_sum / total_data_size * 100

    # Format the amount of data written for logging
    formatted_written: str = format_size(written_sum)

    # Round the elapsed time to one decimal place for logging
    rounded_elapsed_time: float = round(elapsed_time, 1)

    # If elapsed time is greater than zero, log detailed progress
    if elapsed_time > 0:
        # Calculate the average writing speed in MiB/s
        average_speed: float = round(written_sum / M / elapsed_time, 1)

        # Log the detailed progress information
        log_i(f'written {formatted_written}, '
              f'{round(percentage, 1)}% in '
              f'{rounded_elapsed_time}s, avg '
              f'{average_speed} MiB/s')
    else:
        # Log progress without average speed if elapsed time is zero
        log_i(f'written {formatted_written}, '
              f'{round(percentage, 1)}% in '
              f'{rounded_elapsed_time}s')


def log_positions() -> None:
    """
    Logs the current positions of input and output streams.

    This function retrieves and logs the current position of the output
    stream and, if available, the input stream. It provides useful
    information for debugging and tracking the state of the streams.
    """
    # Retrieve the current position of the output stream
    out_pos: int = bio_d['OUT'].tell()

    # Check if the input stream is available in the global `bio_d` dictionary
    if 'IN' in bio_d:
        # Retrieve the current position of the input stream
        in_pos: int = bio_d['IN'].tell()

        # Log the current positions of both input and output streams
        log_d(f'current positions: input={in_pos}, output={out_pos}')
    else:
        # Log the current position of the output stream only
        log_d(f'current position: output={out_pos}')


def remove_out_path() -> None:
    """
    Removes the output file path specified in the global `bio_d`
    dictionary if the user confirms the action.

    This function checks if the user wants to proceed with removing the
    output file. If confirmed, it attempts to delete the file associated
    with the output stream in the global `bio_d` dictionary. It logs the
    outcome of the operation, including any errors that may occur during
    the removal process.

    Returns:
        None: This function does not return a value; it performs file
              removal and logs the result.
    """
    # Check if the user confirms the action to proceed with removal
    if proceed_request(proceed_type=2):
        # Get the name of the output file
        out_file_name: str = bio_d['OUT'].name

        try:
            # Attempt to remove the output file path
            remove(out_file_name)
            log_i(f'path "{out_file_name}" has been removed')
        except Exception as error:
            log_e(f'{error}')
            log_w(f'failed to remove path "{out_file_name}"!')
    else:
        log_i('output file path is NOT removed')


# Perform actions: high-level functions
# --------------------------------------------------------------------------- #


def encrypt_and_embed(action: int) -> bool:
    """
    Orchestrates the encryption/decryption and embedding/extracting
    process based on the specified action.

    This function retrieves the necessary input parameters for the
    encryption and embedding process by calling the
    `encrypt_and_embed_input` function. If the input retrieval is
    successful, it then calls the `encrypt_and_embed_handler`
    function to perform the actual operation (encryption, decryption,
    encryption and embedding, decryption and extraction).

    Args:
        action (int): An integer indicating the action to perform.

    Returns:
        bool: True if the encryption and embedding operation was
              successful, False if the operation was canceled or failed.

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
        Optional[bytes]
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

    # Size of the ciphertext, if applicable
    ciphertext_size: Optional[int] = input_values[3]

    # Processed comments to be encrypted, if applicable
    processed_comments: Optional[bytes] = input_values[4]

    # Call the handler function to perform the action
    success: bool = encrypt_and_embed_handler(
        action,
        in_file_size,
        start_pos,
        end_pos,
        ciphertext_size,
        processed_comments
    )

    # Return the success status of the operation
    return success


def encrypt_and_embed_input(
    action: int
) -> Optional[tuple[
    int,
    Optional[int],
    Optional[int],
    Optional[int],
    Optional[bytes]
]]:
    """
    Retrieves input parameters for the encryption and embedding process
    based on the specified action.

    This function handles the input file retrieval, validates the file
    size, and determines the necessary parameters for encryption or
    embedding. It sets up the output file and calculates the start and
    end positions for the operation. Additionally, it manages any
    required salts and comments for the process.

    Args:
        action (int): An integer indicating the action to perform, which
                      affects how input is processed.

    Returns:
        Optional[tuple]: A tuple containing the following elements if
            successful:
            - in_file_size (int): The size of the input file.
            - start_pos (Optional[int]): The starting position for the
              operation.
            - end_pos (Optional[int]): The ending position for the
              operation.
            - ciphertext_size (Optional[int]): The size of the
              ciphertext, if applicable.
            - processed_comments (Optional[bytes]): The processed
              comments to be encrypted, if applicable.

        Returns None if the input retrieval fails or if the input file
        does not meet the required conditions.

    Notes:
        - The function logs various information during its execution
          for debugging purposes.
        - It handles different actions (e.g., creating new files,
          checking sizes) based on the provided action code.
    """
    # Initialize variables for start and end positions, ciphertext size,
    # and processed comments
    start_pos: Optional[int] = None
    end_pos: Optional[int] = None
    ciphertext_size: Optional[int] = None
    processed_comments: Optional[bytes] = None

    # Set custom settings based on the action
    set_custom_settings(action)

    in_file_path: str
    in_file_size: int
    out_file_path: str
    out_file_size: int

    # Retrieve the input file path, size, and file descriptor
    in_file_path, in_file_size, bio_d['IN'] = get_input_file(action)

    # Log the input file path and size
    log_i(f'path: "{in_file_path}"; size: {format_size(in_file_size)}')

    # Handle encryption actions (2, 6)
    if action in (2, 6):
        # Calculate the size of the ciphertext including processed comments
        ciphertext_size = in_file_size + PROCESSED_COMMENTS_SIZE

        # Determine the minimum and maximum sizes for the cryptoblob
        min_cryptoblob_size: int = in_file_size + MIN_VALID_CRYPTOBLOB_SIZE
        max_pad: int = \
            ciphertext_size * int_d['max_pad_size_percent'] // 100 - 1
        max_pad = max(0, max_pad)
        max_cryptoblob_size: int = max_pad + min_cryptoblob_size

        # Debug logging for calculated sizes
        if DEBUG:
            log_d(f'ciphertext_size: {ciphertext_size}')
            log_d(f'min_cryptoblob_size: {min_cryptoblob_size}')
            log_d(f'max_pad: {max_pad}')
            log_d(f'max_cryptoblob_size: {max_cryptoblob_size}')

    # Handle decryption actions (3, 7) and validate input file size
    if action in (3, 7):
        if in_file_size < MIN_VALID_CRYPTOBLOB_SIZE:
            if action == 3:
                log_e(f'input file is too small (min valid cryptoblob size '
                      f'is {MIN_VALID_CRYPTOBLOB_SIZE} bytes)')
            else:  # action == 7
                log_e(f'incorrect start/end positions (min valid cryptoblob '
                      f'size is {MIN_VALID_CRYPTOBLOB_SIZE} B)')
            return None

    # Set up output file based on the action
    if action in (2, 3):  # New file creation for encryption
        out_file_path, bio_d['OUT'] = get_output_file_new(action)
        log_i(f'new file "{out_file_path}" has been created')

    elif action == 6:  # Existing file handling for encryption
        out_file_path, out_file_size, bio_d['OUT'] = \
            get_output_file_exist(in_file_path, max_cryptoblob_size, action)
        max_start_pos: int = out_file_size - max_cryptoblob_size
        log_i(f'path: "{out_file_path}"')

    else:  # action == 7, new file creation for decryption
        out_file_path, bio_d['OUT'] = get_output_file_new(action)
        max_start_pos = in_file_size - MIN_VALID_CRYPTOBLOB_SIZE
        log_i(f'new file "{out_file_path}" has been created')

    # Log the size of the output file if applicable
    if action == 6:
        log_i(f'size: {format_size(out_file_size)}')

    # Get the starting position for the operation
    if action in (6, 7):
        start_pos = get_start_position(max_start_pos, no_default=True)
        log_i(f'start position: {start_pos}')

    # Get the ending position for the operation if decrypting
    if action == 7:
        end_pos = get_end_position(
            min_pos=start_pos + MIN_VALID_CRYPTOBLOB_SIZE,
            max_pos=in_file_size,
            no_default=True
        )
        log_i(f'end position: {end_pos}')

    # Retrieve processed comments for embedding if encrypting
    if action in (2, 6):
        processed_comments = get_processed_comments()

    # Seek to the start position in the output file if encrypting
    if action == 6:
        if not seek_position(bio_d['OUT'], start_pos):
            return None
    # Seek to the start position in the input file if decrypting
    if action == 7:
        if not seek_position(bio_d['IN'], start_pos):
            return None

    # Debug logging for pointer positions if applicable
    if DEBUG and action in (6, 7):
        log_d('pointers set to start positions')
        log_positions()

    # Retrieve salts needed for the operation
    if not get_salts(in_file_size, end_pos, action):
        return None

    # Get the Argon2 password for key derivation
    get_argon2_password()

    # Trigger garbage collection to free up memory
    collect()

    # Check if the user has requested to stop the operation
    if action == 6:
        if not proceed_request(proceed_type=1):
            log_i('stopped by user request')
            return None

    # Return the retrieved parameters for further processing
    return (
        in_file_size,
        start_pos,
        end_pos,
        ciphertext_size,
        processed_comments)


def encrypt_and_embed_handler(
    action: int,
    in_file_size: int,
    start_pos: Optional[int],
    end_pos: Optional[int],
    ciphertext_size: Optional[int],
    processed_comments: Optional[bytes]
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
    8. Reads and writes header salts, handling processed comments based
       on the action.
    9. Processes the main content in chunks, encrypting or decrypting as
       necessary.
    10. Updates the MAC hash with the processed data.
    11. Handles footer padding and writes the footer salt if applicable.
    12. Verifies the integrity/authenticity of the data using the MAC
        tag.
    13. Returns True if the operation was successful, or False if any
        step fails.

    Args:
        action (int): An integer indicating the action to perform
                      (e.g., encryption or decryption).
        in_file_size (int): The size of the input data.
        start_pos (Optional[int]): The starting position for the
                                   operation.
        end_pos (Optional[int]): The ending position for the operation
                                 (used in decryption).
        ciphertext_size (Optional[int]): The size of the ciphertext,
                                         if applicable.
        processed_comments (Optional[bytes]): The processed comments to
                                              be encrypted/embedded.

    Returns:
        bool: True if the operation was successful, False if it failed
              at any point.

    Notes:
        - The function logs various information during its execution for
          debugging purposes.
        - It manages both the encryption and decryption processes based
          on the action parameter.
        - The function ensures data integrity by comparing MAC tags
          during decryption.
    """
    # Derive keys needed for encryption/decryption
    if not derive_keys():
        return False

    # Initialize ChaCha20 nonce counter for the current action
    int_d['nonce_counter'] = NONCE_COUNTER_INIT_VALUE

    # Initialize MAC for the current action using BLAKE2b hash function
    mac_hash_obj: Any = \
        blake2b(digest_size=MAC_TAG_SIZE, key=bytes_d['mac_key'])

    # Determine padding size
    # ----------------------------------------------------------------------- #

    # Retrieve the padding key from the global `bytes_d` dictionary
    pad_key: bytes = bytes_d['pad_key']

    # Split the padding key into two halves for use in padding calculation
    pad_key1: bytes = pad_key[:PAD_KEY_SIZE // 2]
    pad_key2: bytes = pad_key[-PAD_KEY_SIZE // 2:]

    # Determine padding size based on the action (encryption or decryption)
    if action in (2, 6):  # Encryption actions
        pad_size: int = pad_from_ciphertext(
            ciphertext_size,
            pad_key1,
            int_d['max_pad_size_percent']
        )
    else:  # Decryption actions (3, 7)
        if action == 3:
            padded_ciphertext_size: int = \
                in_file_size - SALTS_SIZE - MAC_TAG_SIZE
        else:  # action == 7
            padded_ciphertext_size = \
                end_pos - start_pos - SALTS_SIZE - MAC_TAG_SIZE

        pad_size = pad_from_padded_ciphertext(
            padded_ciphertext_size,
            pad_key1,
            int_d['max_pad_size_percent']
        )

    header_pad_size: int
    footer_pad_size: int

    # Calculate header and footer padding sizes
    header_pad_size, footer_pad_size = header_footer_pads(pad_size, pad_key2)

    # Collect garbage
    # ----------------------------------------------------------------------- #

    # Clean up sensitive data from memory
    del pad_key, pad_key1, pad_key2
    del bytes_d['argon2_password'], bytes_d['pad_key'], bytes_d['mac_key']

    # Trigger garbage collection to free up memory
    collect()

    # Calculate sizes
    # ----------------------------------------------------------------------- #

    # Calculate the size of the cryptoblob based on the action
    if action in (2, 6):
        cryptoblob_size: int = \
            in_file_size + pad_size + MIN_VALID_CRYPTOBLOB_SIZE
    elif action == 3:
        cryptoblob_size = in_file_size
    else:  # action == 7
        cryptoblob_size = end_pos - start_pos

    # Determine the size of the contents to be processed
    if action in (2, 6):
        contents_size: int = in_file_size
    else:  # Decryption actions (3, 7)
        contents_size = cryptoblob_size - pad_size - MIN_VALID_CRYPTOBLOB_SIZE

    # Calculate the output data size based on the action
    if action in (2, 6):
        out_data_size: int = \
            contents_size + pad_size + MIN_VALID_CRYPTOBLOB_SIZE
    else:  # Decryption actions (3, 7)
        out_data_size = contents_size

    # Debug logging for sizes
    if DEBUG:
        log_d(f'contents size: {format_size(contents_size)}')
        log_d(f'cryptoblob size: {format_size(cryptoblob_size)}')
        log_d(f'output data size: {format_size(out_data_size)}')

    # Validate contents size
    if contents_size < 0:
        log_e('invalid combination of input values')
        return False

    # Start timing the operation
    start_time: float = monotonic()
    last_progress_time: float = start_time

    # Initialize the total written bytes counter
    written_sum: int = 0

    # Write header_salt
    # ----------------------------------------------------------------------- #

    log_i('reading, writing...')

    # Retrieve salts for header and footer
    header_salt: bytes = bytes_d['header_salt']
    footer_salt: bytes = bytes_d['footer_salt']

    # Update MAC with header and footer salts
    mac_hash_obj.update(header_salt)
    mac_hash_obj.update(footer_salt)

    # Write header salt if encrypting
    if action in (2, 6):
        if DEBUG:
            log_d('writing header_salt...')

        if not write_data(header_salt):
            return False

        written_sum += len(header_salt)

        if DEBUG:
            log_d('header_salt is written')
            log_positions()

    # ----------------------------------------------------------------------- #

    # Handle header padding
    if DEBUG:
        log_d('handling header padding...')

    rnd_pad_pos0: int = bio_d['OUT'].tell()

    handle_padding_res: Optional[tuple[int, float]] = handle_padding(
        header_pad_size, action, written_sum, start_time,
        last_progress_time, out_data_size)

    if handle_padding_res is None:
        return False

    written_sum, last_progress_time = handle_padding_res

    rnd_pad_pos1: int = bio_d['OUT'].tell()

    if DEBUG:
        log_d('handling header padding is completed')
        log_positions()

    # ----------------------------------------------------------------------- #

    # Handle comments based on the action
    if DEBUG:
        log_d('handling comments...')

    if action in (3, 7):  # Decryption actions
        processed_comments = read_data(bio_d['IN'], PROCESSED_COMMENTS_SIZE)

        if processed_comments is None:
            return False
    try:
        # Encrypt or decrypt the comments
        processed_comments_out: bytes = encrypt_decrypt(processed_comments)
    except OverflowError as error:  # Handle nonce counter overflow
        log_e(f'{error}')
        return False

    if DEBUG:
        log_d('processed_comments found in plain and encrypted forms')

    # Write encrypted comments if encrypting
    if action in (2, 6):
        if not write_data(processed_comments_out):
            return False

        written_sum += len(processed_comments_out)

        if DEBUG:
            log_d(f'encrypted comments '
                  f'(size={len(processed_comments_out)}) is written')
    else:  # Decryption actions (3, 7)
        decoded_comments: Optional[str] = \
            decode_processed_comments(processed_comments_out)
        log_i(f'comments: {[decoded_comments]}')

    # Update MAC with comments
    if action in (2, 6):
        mac_hash_obj.update(processed_comments_out)
    else:  # Decryption actions (3, 7)
        mac_hash_obj.update(processed_comments)

    if DEBUG:
        log_d('handling comments is completed')
        log_positions()

    # ----------------------------------------------------------------------- #

    # Handle the main contents of the file based on the action
    if DEBUG:
        if action in (2, 6):
            log_d('handling input file contents...')
        else:  # Decryption actions (3, 7)
            log_d('writing output file contents...')

    # Calculate the number of complete chunks and remaining bytes
    num_complete_chunks: int = contents_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = contents_size % RW_CHUNK_SIZE

    # Process complete chunks
    for _ in range(num_complete_chunks):
        in_chunk: Optional[bytes] = read_data(bio_d['IN'], RW_CHUNK_SIZE)

        if in_chunk is None:
            return False

        try:
            out_chunk: bytes = encrypt_decrypt(in_chunk)
        except OverflowError as error:
            log_e(f'{error}')
            return False

        if not write_data(out_chunk):
            return False

        written_sum += len(out_chunk)

        # Log progress at intervals
        if monotonic() - last_progress_time >= MIN_PROGRESS_INTERVAL:
            log_progress(written_sum, out_data_size, start_time)
            last_progress_time = monotonic()

        if DEBUG:
            log_d(f'contents chunk (size={len(out_chunk)}) is written')
            log_positions()

        # Update MAC with the processed chunk
        if action in (2, 6):
            mac_hash_obj.update(out_chunk)
        else:  # Decryption actions (3, 7)
            mac_hash_obj.update(in_chunk)

    # Process any remaining bytes
    if num_remaining_bytes:
        in_chunk = read_data(bio_d['IN'], num_remaining_bytes)

        if in_chunk is None:
            return False

        try:
            out_chunk = encrypt_decrypt(in_chunk)
        except OverflowError as error:
            log_e(f'{error}')
            return False

        if not write_data(out_chunk):
            return False

        written_sum += len(out_chunk)

        # Log progress for the last chunk
        if monotonic() - last_progress_time >= MIN_PROGRESS_INTERVAL:
            log_progress(written_sum, out_data_size, start_time)
            last_progress_time = monotonic()

        if DEBUG:
            log_d(f'contents chunk (size={len(out_chunk)}) is written')

        # Update MAC with the last processed chunk
        if action in (2, 6):
            mac_hash_obj.update(out_chunk)
        else:  # Decryption actions (3, 7)
            mac_hash_obj.update(in_chunk)

    if DEBUG:
        log_d('handling input file contents is completed')

        if action in (2, 6):
            log_d('encryption is completed')

        log_positions()

    if action in (3, 7):
        log_i('decryption is completed')

    # ----------------------------------------------------------------------- #

    # Handle the MAC tag for integrity verification
    if DEBUG:
        log_d('handling MAC tag...')

    calculated_mac_tag: bytes = mac_hash_obj.digest()

    if DEBUG:
        log_d(f'calculated MAC tag:\n    {calculated_mac_tag.hex()}')

    if action in (2, 6):  # Encryption actions
        fake_mac_tag: bytes = urandom(MAC_TAG_SIZE)

        if DEBUG:
            log_d(f'fake MAC tag:\n    {fake_mac_tag.hex()}')

        # Determine whether to use a fake MAC tag
        if bool_d['set_fake_mac']:
            mac_tag: bytes = fake_mac_tag
        else:
            mac_tag = calculated_mac_tag

        if DEBUG:
            log_d(f'MAC tag to write:\n    {mac_tag.hex()}')

        # Write the MAC tag to the output
        if not write_data(mac_tag):
            return False

        if DEBUG:
            log_d('MAC tag is written')

        written_sum += len(mac_tag)
    else:  # Decryption actions (3, 7)
        retrieved_mac_tag: Optional[bytes] = \
            read_data(bio_d['IN'], MAC_TAG_SIZE)

        if retrieved_mac_tag is None:
            bool_d['auth_fail'] = True

            log_w('integrity/authenticity verification failed!')
            return False

        if DEBUG:
            log_d(f'retrieved MAC tag:\n    {retrieved_mac_tag.hex()}')

        # Compare the calculated MAC tag with the retrieved MAC tag
        if compare_digest(calculated_mac_tag, retrieved_mac_tag):
            if DEBUG:
                log_d('calculated_mac_tag is equal to retrieved_mac_tag')

            log_i('integrity/authenticity verification: OK')
        else:
            bool_d['auth_fail'] = True

            if DEBUG:
                log_d('calculated_mac_tag is not equal to retrieved_mac_tag')

            log_w('integrity/authenticity verification failed!')

    if DEBUG:
        log_d('handling MAC tag is completed')
        log_positions()

    # ----------------------------------------------------------------------- #

    # Handle footer padding
    if DEBUG:
        log_d('handling footer padding...')

    rnd_pad_pos2: int = bio_d['OUT'].tell()

    handle_padding_res = handle_padding(
        footer_pad_size, action, written_sum,
        start_time, last_progress_time, out_data_size
    )

    if handle_padding_res is None:
        return False

    written_sum, last_progress_time = handle_padding_res

    rnd_pad_pos3: int = bio_d['OUT'].tell()

    if DEBUG:
        log_d('handling footer padding is completed')
        log_positions()

    # ----------------------------------------------------------------------- #

    # Write footer salt if encrypting
    if action in (2, 6):
        if DEBUG:
            log_d('writing footer_salt...')

        if not write_data(footer_salt):
            return False

        written_sum += len(footer_salt)

        log_progress(written_sum, out_data_size, start_time)

        if DEBUG:
            log_d('footer_salt is written')
            log_positions()

    # Validate the total written size against the expected output size
    if written_sum != out_data_size:
        log_e(f'written data size ({format_size(written_sum)}) does not '
              f'match the expected size ({format_size(out_data_size)})')
        return False

    # ----------------------------------------------------------------------- #

    # Synchronize data to disk if necessary
    if action == 6:
        log_i('syncing output data to disk...')
        fsync_start_time: float = monotonic()

        if not fsync_data():
            return False

        fsync_end_time: float = monotonic()
        log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    # ----------------------------------------------------------------------- #

    # Log the location of the cryptoblob in the container if encrypting
    if action == 6:
        end_pos = bio_d['OUT'].tell()
        log_i(f'remember the location of the cryptoblob in the container:\n'
              f'    [{start_pos}:{end_pos}]')

    # Log progress for decryption actions
    if action in (3, 7):
        log_progress(written_sum, out_data_size, start_time)

    # Log padding locations if encrypting
    if action in (2, 6):
        log_i(f'padding location in the output file:\n'
              f'    [{rnd_pad_pos0}:{rnd_pad_pos1}] — '
              f'{format_size(rnd_pad_pos1 - rnd_pad_pos0)}\n'
              f'    [{rnd_pad_pos2}:{rnd_pad_pos3}] — '
              f'{format_size(rnd_pad_pos3 - rnd_pad_pos2)}')

    return True


def embed(action: int) -> bool:
    """
    Handles the embedding or extraction of a message based on the
    specified action.

    This function orchestrates the process of embedding or extracting a
    message by first retrieving the necessary input parameters
    (start position and message size) through the `embed_input`
    function. If the input retrieval is successful, it then calls the
    `embed_handler` function to perform the actual operation.

    Args:
        action (int): An integer indicating the action to perform.
                      - 4: Embed data into an existing output file.
                      - 5: Extract data from the container.

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


def embed_input(action: int) -> Optional[tuple[int, int]]:
    """
    Prepares the input file and determines the start and message sizes
    for embedding or extracting.

    This function retrieves the input file based on the specified
    action, logs relevant information about the file, and calculates the
    start position and message size for either embedding or extracting.
    It supports two actions: embedding data into an existing output file
    (action 4) or extracting data from the container into a new file
    (action 5).

    Args:
        action (int): An integer indicating the action to perform.
                      - 4: Embed data into an existing output file.
                      - 5: Extract data from the container into a new
                           file.

    Returns:
        Optional[tuple]: A tuple containing the start position (int) and
                         the message size (int) if successful, or None
                         if the operation was canceled by the user.

    Notes:
        - The function logs the path and size of the input file.
        - For action 4, it retrieves the output file and its size,
          and calculates the maximum starting position for embedding.
        - For action 5, it creates a new output file and sets the
          maximum starting position accordingly for extraction.
        - The function prompts the user for confirmation if action 4
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
    in_file_path, in_file_size, bio_d['IN'] = get_input_file(action)

    # Log the path and size of the input file
    log_i(f'path: "{in_file_path}"; size: {format_size(in_file_size)}')

    if action == 4:
        # For embedding, retrieve the existing output file and its size
        out_file_path, out_file_size, bio_d['OUT'] = get_output_file_exist(
            in_file_path, in_file_size, action)

        # Calculate max start position
        max_start_pos = out_file_size - in_file_size

        log_i(f'path: "{out_file_path}"')

    else:  # action 5 for extraction
        # For extraction, create a new output file
        out_file_path, bio_d['OUT'] = get_output_file_new(action)

        # Set max start position for extraction
        max_start_pos = in_file_size - 1

        log_i(f'new file "{out_file_path}" has been created')

    if action == 4:
        # Log the size of the output file for embedding
        log_i(f'size: {format_size(out_file_size)}')

    # Get the starting position for embedding or extraction
    start_pos = get_start_position(max_start_pos, no_default=True)

    log_i(f'start position: {start_pos}')

    if action == 4:
        # For embedding, set message size to input file size
        message_size = in_file_size
        end_pos = start_pos + message_size  # Calculate end position
        log_i(f'end position: {end_pos}')

        # Prompt user for confirmation before proceeding
        if not proceed_request(proceed_type=1):
            log_i('stopped by user request\n')
            return None
    else:
        # For extraction, calculate end position and message size
        end_pos = get_end_position(
            min_pos=start_pos,
            max_pos=in_file_size,
            no_default=True
        )
        log_i(f'end position: {end_pos}')

        # Calculate message size to retrieve
        message_size = end_pos - start_pos
        log_i(f'message size to retrieve: {message_size} B')

    # Return the start position and message size
    return start_pos, message_size


def embed_handler(action: int, start_pos: int, message_size: int) -> bool:
    """
    Handles the embedding or extraction of a message in a specified
    container.

    This function reads data from an input source, writes it to an
    output destination, and computes a checksum of the written data.
    It supports two actions: embedding data into a container (action 4)
    or extracting data from the container into a new file (action 5).
    The function also manages progress reporting and synchronization of
    the output data.

    Args:
        action (int): An integer indicating the action to perform.
                      - 4: Embed data into the output container.
                      - 5: Extract data from the container into a new
                           file.
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
        - The function computes a checksum using the BLAKE2b hashing
          algorithm and logs the checksum and the position of the
          embedded or extracted message.
        - If action 4 is performed, it ensures that the output data is
          synchronized after writing.
    """
    # Log current positions if DEBUG is enabled
    if DEBUG:
        log_positions()

    # Seek to the start position in the appropriate container
    if action == 4:
        if not seek_position(bio_d['OUT'], start_pos):
            return False  # Return False if seeking fails

    else:  # action 5 for extraction
        if not seek_position(bio_d['IN'], start_pos):
            return False  # Return False if seeking fails

    # Log positions after seeking if DEBUG is enabled
    if DEBUG:
        log_positions()

    log_i('reading, writing...')  # Log the start of the read/write process

    # Initialize the BLAKE2b hash object for checksum calculation
    hash_obj: Any = blake2b(digest_size=EMBED_DIGEST_SIZE)

    # Record the start time for performance measurement
    start_time: float = monotonic()
    last_progress_time: float = start_time  # Initialize last progress time

    written_sum: int = 0  # Initialize the total bytes written counter

    # Calculate the number of complete chunks and remaining bytes
    num_complete_chunks: int = message_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = message_size % RW_CHUNK_SIZE

    # Read and write complete chunks of data
    for _ in range(num_complete_chunks):
        message_chunk: Optional[bytes] = read_data(bio_d['IN'], RW_CHUNK_SIZE)

        if message_chunk is None:
            return False  # Return False if reading fails

        if not write_data(message_chunk):
            return False  # Return False if writing fails

        hash_obj.update(message_chunk)  # Update the checksum with the chunk

        written_sum += len(message_chunk)  # Update the total written bytes

        # Log progress at defined intervals
        if monotonic() - last_progress_time >= MIN_PROGRESS_INTERVAL:
            log_progress(written_sum, message_size, start_time)  # Log progress
            last_progress_time = monotonic()  # Update last progress time

    # Write any remaining bytes that do not fit into a full chunk
    if num_remaining_bytes:
        message_chunk = read_data(bio_d['IN'], num_remaining_bytes)

        if message_chunk is None:
            return False  # Return False if reading fails

        if not write_data(message_chunk):
            return False  # Return False if writing fails

        # Update the checksum with the last chunk
        hash_obj.update(message_chunk)

        written_sum += len(message_chunk)  # Update the total written bytes

    # Log positions after writing if DEBUG is enabled
    if DEBUG:
        log_positions()

    # Log the final progress after writing all data
    log_progress(written_sum, message_size, start_time)

    # Validate the total written size against the expected output size
    if written_sum != message_size:
        log_e(f'written data size ({format_size(written_sum)}) does not '
              f'match the expected size ({format_size(message_size)})')
        return False

    if action == 4:
        log_i('syncing output data to disk...')
        fsync_start_time: float = monotonic()

        # Synchronize the output data to ensure all changes are flushed
        if not fsync_data():
            return False  # Return False if synchronization fails

        fsync_end_time: float = monotonic()
        log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    # Calculate the checksum of the written data
    message_checksum: str = hash_obj.hexdigest()

    # Get the current position in the output container
    end_pos: int = bio_d['OUT'].tell()

    if action == 4:
        # Log the location of the embedded message in the container
        log_i(f'remember the location of the message in the container:\n'
              f'    [{start_pos}:{end_pos}]')

    # Log the checksum of the message
    log_i(f'message checksum:\n    {message_checksum}')

    # Return True if the operation was successful
    return True


def create_with_random(action: int) -> bool:
    """
    Creates a file of a specified size with random data.

    Args:
        action (int): An integer representing the action to be performed.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    # Initialize the output file and retrieve its size based on the action
    out_file_size: int = create_with_random_input(action)

    # Write random data to the newly created file
    success: bool = create_with_random_handler(out_file_size)

    # Return the success status of the operation
    return success


def create_with_random_input(action: int) -> int:
    """
    Initializes a new output file based on the specified action and
    returns its size.

    This function creates a new output file, logs a creation message,
    and retrieves the size of the newly created file in bytes.

    Args:
        action (int): The action code that determines the output file.

    Returns:
        int: The size of the newly created output file in bytes.
    """
    # Create a new output file and retrieve its path
    out_file_path: str

    out_file_path, bio_d['OUT'] = get_output_file_new(action)

    # Log the creation of the new file
    log_i(f'new file "{out_file_path}" has been created')

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
        out_file_size (int): The total size of data to be written in bytes.

    Returns:
        bool: True if all data was written successfully, False otherwise.
    """
    # Log the start of the random data writing process
    log_i('writing random data...')

    # Record the start time for performance measurement
    start_time: float = monotonic()
    last_progress_time: float = start_time  # Initialize last progress time

    written_sum: int = 0  # Initialize the total bytes written counter

    # Calculate the number of complete chunks and remaining bytes to write
    num_complete_chunks: int = out_file_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = out_file_size % RW_CHUNK_SIZE

    # Write complete chunks of random data
    for _ in range(num_complete_chunks):
        # Generate a chunk of random data
        chunk: bytes = urandom(RW_CHUNK_SIZE)

        # Write the chunk to the output file
        if not write_data(chunk):
            return False  # Return False if writing fails

        written_sum += len(chunk)  # Update the total written bytes

        # Log progress at defined intervals
        if monotonic() - last_progress_time >= MIN_PROGRESS_INTERVAL:
            log_progress(written_sum, out_file_size, start_time)
            last_progress_time = monotonic()

    # Write any remaining bytes that do not fit into a full chunk
    if num_remaining_bytes:
        # Generate the last chunk of random data
        chunk = urandom(num_remaining_bytes)

        # Write the remaining bytes to the output file
        if not write_data(chunk):
            return False  # Return False if writing fails

        written_sum += len(chunk)  # Update the total written bytes

    # Log the final progress after writing all data
    log_progress(written_sum, out_file_size, start_time)

    # Validate the total written size against the expected output size
    if written_sum != out_file_size:
        log_e(f'written data size ({format_size(written_sum)}) does not '
              f'match the expected size ({format_size(out_file_size)})')
        return False

    # Return True if all data was written successfully
    return True


def overwrite_with_random(action: int) -> bool:
    """
    Overwrites part of the output file with random data.

    This function takes an action code as input, retrieves the
    corresponding start position and data size, and then overwrites the
    specified range of data with random bytes.

    Args:
        action (int): The action code that determines the start position
                      and data size.

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


def overwrite_with_random_input(action: int) -> Optional[tuple[int, int]]:
    """
    Prepares to overwrite a specified range of an output file with
    random data.

    This function retrieves the output file's path and size based on the
    provided action. It then determines the start and end positions for
    the overwrite operation. If the specified range is valid and the
    user confirms the action, it returns the start position and the size
    of the data to be written.

    Args:
        action (int): An integer representing the action to be performed,
                      which influences the output file retrieval process.

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
    out_file_path, out_file_size, bio_d['OUT'] = get_output_file_exist(
        in_file_path='',
        min_out_size=0,
        action=action
    )

    # Log the output file path and size
    log_i(f'path: "{out_file_path}"; size: {format_size(out_file_size)}')

    # Check if the output file size is zero
    if not out_file_size:
        log_i('nothing to do')  # Log that there is nothing to do
        return None  # Return None if there is nothing to overwrite

    # Get the starting position for the overwrite operation
    start_pos: int = get_start_position(
        max_start_pos=out_file_size,
        no_default=False
    )
    log_i(f'start position: {start_pos}')  # Log the starting position

    # Check if the starting position is equal to the output file size
    if start_pos == out_file_size:
        log_i('nothing to do')
        # Return None if the starting position is at the end of the file
        return None

    # Get the ending position for the overwrite operation
    end_pos: int = get_end_position(
        min_pos=start_pos,
        max_pos=out_file_size,
        no_default=False
    )
    log_i(f'end position: {end_pos}')  # Log the ending position

    # Calculate the size of the data to be written
    data_size: int = end_pos - start_pos
    log_i(f'data size to write: {format_size(data_size)}')  # Log the data size

    # Check if the data size is zero
    if not data_size:
        log_i('nothing to do')  # Log that there is nothing to do
        return None  # Return None if there is no data to write

    # Prompt the user for confirmation before proceeding
    if not proceed_request(proceed_type=1):
        log_i('stopped by user request')  # Log that the operation was canceled
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
    # Log the current positions of the input and output streams
    # if DEBUG is enabled
    if DEBUG:
        log_positions()

    # Seek to the specified start position in the output file
    if not seek_position(bio_d['OUT'], start_pos):
        return False  # Return False if seeking fails

    # Log the position after seeking if DEBUG is enabled
    if DEBUG:
        log_positions()

    log_i('writing random data...')  # Log the start of the writing process

    # Record the start time for performance measurement
    start_time: float = monotonic()
    last_progress_time: float = start_time  # Initialize last progress time

    written_sum: int = 0  # Initialize the total bytes written counter

    # Calculate the number of complete chunks and remaining bytes to write
    num_complete_chunks: int = data_size // RW_CHUNK_SIZE
    num_remaining_bytes: int = data_size % RW_CHUNK_SIZE

    # Write complete chunks of random data
    for _ in range(num_complete_chunks):
        # Generate a chunk of random data
        chunk: bytes = urandom(RW_CHUNK_SIZE)

        if not write_data(chunk):  # Write the chunk to the output file
            return False  # Return False if writing fails

        written_sum += len(chunk)  # Update the total written bytes

        # Log progress at defined intervals
        if monotonic() - last_progress_time >= MIN_PROGRESS_INTERVAL:
            log_progress(written_sum, data_size, start_time)  # Log progress
            last_progress_time = monotonic()  # Update last progress time

    # Write any remaining bytes that do not fit into a full chunk
    if num_remaining_bytes:
        # Generate the last chunk of random data
        chunk = urandom(num_remaining_bytes)

        if not write_data(chunk):  # Write the remaining bytes
            return False  # Return False if writing fails

        written_sum += len(chunk)  # Update the total written bytes

    # Log the position after writing if DEBUG is enabled
    if DEBUG:
        log_positions()

    # Log the final progress after writing all data
    log_progress(written_sum, data_size, start_time)

    # Validate the total written size against the expected output size
    if written_sum != data_size:
        log_e(f'written data size ({format_size(written_sum)}) does not '
              f'match the expected size ({format_size(data_size)})')
        return False

    log_i('syncing output data to disk...')

    fsync_start_time: float = monotonic()  # Record the start time for fsync

    # Synchronize the file to ensure all changes are flushed to disk
    if not fsync_data():
        return False  # Return False if synchronization fails

    fsync_end_time: float = monotonic()  # Record the end time for fsync

    # Log the time taken for fsync
    log_i(f'synced in {round(fsync_end_time - fsync_start_time, 1)}s')

    return True  # Return True if the overwrite operation was successful


# signal_handler() and main()
# --------------------------------------------------------------------------- #


def signal_handler(signum: Any, frame: Any) -> NoReturn:
    """
    Handles incoming signals by determining the current state of the
    application.

    This function is called when a signal is received. It checks if an
    action is ongoing and prints an appropriate message before exiting
    the program with a status code.

    Args:
        signum (Any): The signal number that was received.
        frame (Any): The current stack frame
                     (not used in this implementation).

    Raises:
        NoReturn: This function does not return; it exits the program.
    """
    print()
    # Check if an action is currently ongoing
    if 'action_is_ongoing' in bool_d:
        # Print an error message and exit with status code 1
        log_e(f'caught signal {signum}')
        exit(1)
    else:
        # Print an informational message and exit with status code 0
        log_i(f'caught signal {signum}')
        exit(0)


def main() -> NoReturn:
    """
    Main entry point for the application.

    This function initializes the application, sets up signal handling
    for interrupts, and enters an infinite loop to process user actions.
    It handles various actions based on user input, including
    encryption, embedding, and file management. The function also
    manages logging for different levels of information, including debug
    messages.

    The main loop performs the following tasks:
        - Checks for ongoing actions and clears the corresponding flag.
        - Prompts the user to select an action.
        - Executes the selected action, which may include:
            - Exiting the application.
            - Logging information and warnings.
            - Performing encryption and embedding operations.
            - Creating or overwriting files with random data.
        - Closes any open input or output files.
        - Offers to remove the output file if an error occurs during
          processing.
        - Clears global dictionaries after each action.
        - Collects any remaining resources or performs cleanup.

    Returns:
        NoReturn: This function does not return a value; it runs
                  indefinitely until the application is exited.

    Notes:
        - The function handles signals for graceful termination on SIGINT.
        - Debug messages are logged if the DEBUG flag is enabled.
        - The function relies on several external functions and variables.
    """
    # Set up signal handling for graceful termination on SIGINT
    signal(SIGINT, signal_handler)

    # Log a message if debug mode is enabled
    if DEBUG:
        log_w('debug messages enabled!')

    # Enter an infinite loop to process user actions
    while True:
        # Check if an action is ongoing and clear the flag
        if 'action_is_ongoing' in bool_d:
            del bool_d['action_is_ongoing']

        # Prompt the user to select an action
        action: int = select_action()

        # Set the flag indicating that an action is ongoing
        bool_d['action_is_ongoing'] = True

        # Initialize success status for the action
        success: Optional[bool] = None

        # Handle the selected action
        if not action:
            exit()  # Exit the application

        elif action == 1:
            log_i(INFO)  # Log general information

            # Log any warnings
            for warning in WARNINGS:
                log_w(warning)

            # Log debug information if debug mode is enabled
            if DEBUG:
                log_d(DEBUG_INFO)

        elif action in (2, 3, 6, 7):
            # Perform encryption and embedding operations
            success = encrypt_and_embed(action)

        elif action in (4, 5):
            # Handle embedding or extraction of data
            success = embed(action)

        elif action == 8:
            # Create a file with random data
            success = create_with_random(action)

        else:  # action == 9
            # Overwrite a file with random data
            success = overwrite_with_random(action)

        # Close any open input files
        if 'IN' in bio_d:
            close_file(bio_d['IN'])

        # Close any open output files
        if 'OUT' in bio_d:
            close_file(bio_d['OUT'])

        # If certain actions were performed, check for errors
        if action in (2, 3, 5, 7, 8):
            # Offer to remove the output file path if something went wrong
            if not success or 'auth_fail' in bool_d:
                if 'OUT' in bio_d:
                    remove_out_path()

        # Clear global dictionaries
        bio_d.clear()
        int_d.clear()
        bool_d.clear()
        bytes_d.clear()

        # Collect any remaining resources or perform cleanup
        collect()

        # Log completion of the action if successful
        if success:
            log_i('action is completed')


# Define constants
# --------------------------------------------------------------------------- #


# Version of the application
APP_VERSION: Final[str] = '0.17.0'

# Information string for the application
INFO: Final[str] = f"""tird v{APP_VERSION}
    A tool for encrypting files and hiding encrypted data.
    Homepage: https://github.com/hakavlad/tird"""

# Debug information string for the Python version
DEBUG_INFO: Final[str] = f"""Python version {version}"""

# Warnings related to the application usage
WARNINGS: Final[tuple[str, ...]] = (
    "The author does not have a background in cryptography.",
    "tird has not been independently audited.",
    "tird is unlikely to be effective when used in a compromised environment.",
    "tird is unlikely to be effective when used with short and "
    "predictable keys.",
    "Sensitive data may leak into swap space.",
    "tird does not erase sensitive data from memory after use.",
    "tird always releases unverified plaintext, "
    "violating The Cryptographic Doom Principle.",
    "Padding is not used to create a MAC tag (only ciphertext and salt "
    "will be authenticated).",
    "tird doesn't sort digests of keyfiles and passphrases in constant-time.",
    "Overwriting file contents does not guarantee secure destruction "
    "of the data on the media.",
    "You cannot prove to an adversary that your random-looking data does "
    "not contain encrypted data.",
    "Development is not complete; there may be backward compatibility "
    "issues in the future."
)

# ANSI escape codes for terminal text formatting
BOL: str = '\033[1m'  # Bold text
ITA: str = '\033[3m'  # Italic text
ERR: str = '\033[1;3;97;101m'  # Bold italic white text, red background
WAR: str = '\033[1;3;93;40m'  # Bold italic yellow text, black background
RES: str = '\033[0m'  # Reset formatting to default

# Adjust ANSI codes for Windows platform, which does not support them
if platform == 'win32':
    BOL = ITA = ERR = WAR = RES = ''

# Menu string for user options
MENU: Final[str] = f"""{BOL}
                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & Warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & Embed   7. Extract & Decrypt
    8. Create w/ random  9. Overwrite w/ random
    ———————————————————————————————————————————
[01] Select an option [0-9]:{RES} """


# Descriptions for each action in the menu
A0_DESCRIPTION: Final[str] = """action #0:\n\
    exit the application"""

A1_DESCRIPTION: Final[str] = """action #1:\n\
    displaying info and warnings"""

A2_DESCRIPTION: Final[str] = """action #2:\n\
    encrypt file contents and comments;\n\
    write the cryptoblob to a new file"""

A3_DESCRIPTION: Final[str] = """action #3:\n\
    decrypt a file;\n\
    display the decrypted comments and\n\
    write the decrypted contents to a new file"""

A4_DESCRIPTION: Final[str] = """action #4:\n\
    embed file contents (no encryption):\n\
    write input file contents over output file contents"""

A5_DESCRIPTION: Final[str] = """action #5:\n\
    extract file contents (no decryption) to a new file"""

A6_DESCRIPTION: Final[str] = """action #6:\n\
    encrypt file contents and comments;\n\
    write the cryptoblob over a container"""

A7_DESCRIPTION: Final[str] = """action #7:\n\
    extract and decrypt cryptoblob;\n\
    display the decrypted comments and\n\
    write the decrypted contents to a new file"""

A8_DESCRIPTION: Final[str] = """action #8:\n\
    create a file of the specified size with random data"""

A9_DESCRIPTION: Final[str] = """action #9:\n\
    overwrite file contents with random data"""

# Dictionary mapping user input to action descriptions
ACTIONS: Final[dict[str, tuple[int, str]]] = {
    '0': (0, A0_DESCRIPTION),
    '1': (1, A1_DESCRIPTION),
    '2': (2, A2_DESCRIPTION),
    '3': (3, A3_DESCRIPTION),
    '4': (4, A4_DESCRIPTION),
    '5': (5, A5_DESCRIPTION),
    '6': (6, A6_DESCRIPTION),
    '7': (7, A7_DESCRIPTION),
    '8': (8, A8_DESCRIPTION),
    '9': (9, A9_DESCRIPTION)
}

# Global dictionaries
bio_d: Final[dict[Literal['IN', 'OUT'], BinaryIO]] = {}
int_d: Final[dict[str, int]] = {}
bool_d: Final[dict[str, bool]] = {}
bytes_d: Final[dict[str, bytes]] = {}

# Size constants for data representation
K: Final[int] = 2 ** 10  # KiB
M: Final[int] = 2 ** 20  # MiB
G: Final[int] = 2 ** 30  # GiB
T: Final[int] = 2 ** 40  # TiB
P: Final[int] = 2 ** 50  # PiB
E: Final[int] = 2 ** 60  # EiB

# Invalid UTF-8 byte constant
INVALID_UTF8_BYTE: Final[bytes] = b'\xff'

# Minimum interval for progress updates
MIN_PROGRESS_INTERVAL: Final[float] = 5.0

# Byte order for data representation
BYTEORDER: Final[Literal['big', 'little']] = 'little'

PROCESSED_COMMENTS_SIZE: Final[int] = 512

# Passphrases will be truncated to this value
PASSPHRASE_SIZE_LIMIT: Final[int] = 1023

# Maximum size limit for random output file
RAND_OUT_FILE_SIZE_LIMIT: Final[int] = E

# Salt constants for cryptographic operations
ONE_SALT_HALF_SIZE: Final[int] = 8
ONE_SALT_SIZE: Final[int] = ONE_SALT_HALF_SIZE * 2
SALTS_HALF_SIZE: Final[int] = ONE_SALT_HALF_SIZE * 2
SALTS_SIZE: Final[int] = ONE_SALT_SIZE * 2

# ChaCha20 constants
ENC_KEY_SIZE: Final[int] = 32  # 256-bit key size for encryption
NONCE_SIZE: Final[int] = 12  # 96-bit nonce size for ChaCha20
NONCE_COUNTER_INIT_VALUE: Final[int] = 0  # Initial value for nonce counter

# Chunk size for reading and writing data during encryption and decryption
# operations. Changing this value breaks backward compatibility, as it
# defines the size of the data that can be encrypted with a single nonce.
RW_CHUNK_SIZE: Final[int] = 128 * K

# Default values for custom options
DEFAULT_ARGON2_TIME_COST: Final[int] = 4
DEFAULT_MAX_PAD_SIZE_PERCENT: Final[int] = 20

# BLAKE2b constants
PERSON_SIZE: Final[int] = 16
PERSON_KEYFILE: Final[bytes] = b'K' * PERSON_SIZE
PERSON_PASSPHRASE: Final[bytes] = b'P' * PERSON_SIZE
IKM_DIGEST_SIZE: Final[int] = 64
MAC_KEY_SIZE: Final[int] = 64
MAC_TAG_SIZE: Final[int] = MAC_KEY_SIZE
EMBED_DIGEST_SIZE: Final[int] = 32

# Padding constants
PAD_KEY_HALF_SIZE: Final[int] = 16
PAD_KEY_SIZE: Final[int] = PAD_KEY_HALF_SIZE * 2
PAD_KEY_SPACE: Final[int] = int(256 ** PAD_KEY_HALF_SIZE)
MAX_PAD_SIZE_PERCENT_LIMIT: Final[int] = 10 ** 18

# Argon2 constants
ARGON2_MEM: Final[int] = M * 512
ARGON2_TAG_SIZE: Final[int] = ENC_KEY_SIZE + PAD_KEY_SIZE + MAC_KEY_SIZE

# Minimum valid size for cryptoblob
MIN_VALID_CRYPTOBLOB_SIZE: Final[int] = \
    SALTS_SIZE + PROCESSED_COMMENTS_SIZE + MAC_TAG_SIZE


# Debug mode flag
DEBUG: bool = False

# Check command line arguments for debug mode
if not argv[1:]:
    pass  # No arguments provided
elif argv[1:] == ['-d'] or argv[1:] == ['--debug']:
    DEBUG = True  # Enable debug mode
else:
    log_e(f'invalid command line options: {argv[1:]}')  # Log invalid options
    exit(1)  # Exit with error


# Main entry point of the application
if __name__ == '__main__':
    main()  # Call the main function to start the application
