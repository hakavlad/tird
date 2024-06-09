#!/usr/bin/env python3
"""A tool for encrypting files and hiding encrypted data."""

from gc import collect
from getpass import getpass
from hashlib import blake2b
from hmac import compare_digest
from os import fsync, path, remove, urandom, walk
from signal import SIGINT, signal
from sys import argv, exit, platform, version
from time import monotonic
from typing import Any, NoReturn, Optional

from Cryptodome.Cipher import ChaCha20
from nacl.pwhash import argon2id

# pylint: disable=consider-using-with
# pylint: disable=invalid-name
# pylint: disable=empty-docstring
# pylint: disable=broad-exception-caught
# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-many-lines
# pylint: disable=too-many-locals
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-statements


# Define constants
# --------------------------------------------------------------------------- #


WIN32: bool = bool(platform == 'win32')

if WIN32:
    BOL: str = ''
    ITA: str = ''
    ERR: str = ''
    WAR: str = ''
    RES: str = ''
else:
    BOL = '\033[1m'  # bold text
    ITA = '\033[3m'  # italic text
    ERR = '\033[1;3;97;101m'  # bold italic white text, red background
    WAR = '\033[1;3;93;40m'  # bold italic yellow text, black background
    RES = '\033[0m'  # reset


DEBUG: bool = False

if not argv[1:]:
    pass
elif argv[1:] == ['-d'] or argv[1:] == ['--debug']:
    DEBUG = True
else:
    print(f'{ERR}E: invalid command line options: {argv[1:]}{RES}')
    exit(1)


VERSION: str = '0.15.0'

INFO: str = f"""{ITA}I: tird v{VERSION}
    A tool for encrypting files and hiding encrypted data.
    Homepage: https://github.com/hakavlad/tird{RES}"""

DEBUG_INFO: str = f"""{ITA}D: Python version {version}{RES}"""

WARNINGS: str = f"""{WAR}W: warnings:{RES}
{WAR}    - The author is not a cryptographer.{RES}
{WAR}    - tird has not been independently audited.{RES}
{WAR}    - tird probably won't help much when used in a compromised \
environment.{RES}
{WAR}    - tird probably won't help much when used with short and \
predictable keys.{RES}
{WAR}    - Sensitive data may leak into the swap space.{RES}
{WAR}    - tird does not erase sensitive data from memory after use.{RES}
{WAR}    - tird always releases unverified plaintext (violates The \
Cryptographic Doom Principle).{RES}
{WAR}    - Padding is not used to create a MAC tag (only ciphertext and \
salt will be authenticated).{RES}
{WAR}    - tird does not sort digests of keyfiles and passphrases in \
constant-time.{RES}
{WAR}    - Overwriting file contents does not mean securely destroying the \
data on the media.{RES}
{WAR}    - Development is not complete, there may be backward compatibility \
issues in the future.{RES}"""

MENU: str = f"""{BOL}
                       MENU
    ———————————————————————————————————————————
    0. Exit              1. Info & warnings
    2. Encrypt           3. Decrypt
    4. Embed             5. Extract
    6. Encrypt & embed   7. Extract & decrypt
    8. Create w/ random  9. Overwrite w/ random
    ———————————————————————————————————————————
[01] Select an option [0-9]:{RES} """


A0_DESCRIPTION: str = f"""{ITA}I: action #0:\n\
    exit{RES}"""

A1_DESCRIPTION: str = f"""{ITA}I: action #1:\n\
    displaying info and warnings{RES}"""

A2_DESCRIPTION: str = f"""{ITA}I: action #2:\n\
    encrypt file contents and comments;\n\
    write the cryptoblob to a new file{RES}"""

A3_DESCRIPTION: str = f"""{ITA}I: action #3:\n\
    decrypt cryptoblob;\n\
    display the decrypted comments and\n\
    write the decrypted contents to a new file{RES}"""

A4_DESCRIPTION: str = f"""{ITA}I: action #4:\n\
    embed file contents (no encryption):\n\
    write input file contents over output file contents{RES}"""

A5_DESCRIPTION: str = f"""{ITA}I: action #5:\n\
    extract file contents (no decryption) to a new file{RES}"""

A6_DESCRIPTION: str = f"""{ITA}I: action #6:\n\
    encrypt file contents and comments;\n\
    write the cryptoblob over a container{RES}"""

A7_DESCRIPTION: str = f"""{ITA}I: action #7:\n\
    extract and decrypt cryptoblob;\n\
    display the decrypted comments and\n\
    write the decrypted contents to a new file{RES}"""

A8_DESCRIPTION: str = f"""{ITA}I: action #8:\n\
    create a file with random data{RES}"""

A9_DESCRIPTION: str = f"""{ITA}I: action #9:\n\
    overwrite file contents with random data{RES}"""


INVALID_UTF8_BYTE: bytes = b'\xff'  # 0xFF is not valid in UTF-8

iod: dict = {}  # I/O file objects
sd: dict = {}  # salts
md: dict = {}  # miscellaneous

K: int = 2 ** 10
M: int = 2 ** 20
G: int = 2 ** 30

MIN_PRINT_INTERVAL: float = 5.0

BYTEORDER: str = 'little'

POT_COMMENTS_SIZE: int = 512

# Salt constants
ONE_SALT_HALF_SIZE: int = 8
ONE_SALT_SIZE: int = ONE_SALT_HALF_SIZE * 2
SALTS_HALF_SIZE: int = ONE_SALT_HALF_SIZE * 2
SALTS_SIZE: int = ONE_SALT_SIZE * 2

# ChaCha20 constants
ENC_KEY_SIZE: int = 32
NONCE_SIZE: int = 12
NONCE_COUNTER_INIT_VALUE: int = 0
RW_CHUNK_SIZE: int = K * 128

# Default values for custom options
DEFAULT_ARGON2_TIME_COST: int = 4
DEFAULT_MAX_PAD_SIZE_PERCENT: int = 20
DEFAULT_SET_FAKE_MAC: bool = False

# BLAKE2b constants
PERSON_SIZE: int = 16
PERSON_KEYFILE: bytes = b'K' * PERSON_SIZE
PERSON_PASSPHRASE: bytes = b'P' * PERSON_SIZE
IKM_DIGEST_SIZE: int = 64
MAC_KEY_SIZE: int = 64
MAC_TAG_SIZE: int = MAC_KEY_SIZE
EMBED_DIGEST_SIZE: int = 32

# Padding constants
PAD_KEY_HALF_SIZE: int = 16
PAD_KEY_SIZE: int = PAD_KEY_HALF_SIZE * 2
PAD_KEY_SPACE: int = 256 ** PAD_KEY_HALF_SIZE

# Argon2 constants
ARGON2_MEM: int = M * 512
ARGON2_TAG_SIZE: int = ENC_KEY_SIZE + PAD_KEY_SIZE + MAC_KEY_SIZE

MIN_VALID_CRYPTOBLOB_SIZE: int = SALTS_SIZE + POT_COMMENTS_SIZE + MAC_TAG_SIZE


# Handle files: open, seek, read etc.
# --------------------------------------------------------------------------- #


def open_file(f_path: str, f_mode: str) -> Any:
    """
    """
    if DEBUG:
        print(f'{ITA}D: opening file "{f_path}" in mode "{f_mode}"{RES}')

    try:
        fo: Any = open(f_path, f_mode)

        if DEBUG:
            print(f'{ITA}D: opened file (object): {fo}{RES}')

        return fo
    except Exception as e:
        print(f'{ERR}E: {e}{RES}')
        return None


def close_file(f: Any) -> None:
    """
    """
    if DEBUG:
        print(f'{ITA}D: closing {f}{RES}')

    f.close()

    if DEBUG and f.closed:
        print(f'{ITA}D: {f} closed{RES}')


def get_file_size(f_path: str) -> Optional[int]:
    """
    """
    try:
        with open(f_path, 'rb') as f:
            f_size: int = f.seek(0, 2)
            return f_size
    except Exception as e:
        print(f'{ERR}E: {e}{RES}')
        return None


def seek_pos(f: Any, offset: int, whence: int = 0) -> bool:
    """
    """
    if DEBUG:
        print(f'{ITA}D: move to position {offset} in {f}{RES}')

    try:
        f.seek(offset, whence)
        return True
    except OSError as e:
        print(f'{ERR}E: {e}{RES}')
        return False


def read_data(f: Any, size: int) -> Optional[bytes]:
    """
    """
    try:
        data: bytes = f.read(size)
    except OSError as e:
        print(f'{ERR}E: {e}{RES}')
        return None

    if len(data) < size:
        print(f'{ERR}E: the read data size is less than expected{RES}')
        return None

    return data


def write_data(data: bytes) -> bool:
    """
    """
    try:
        iod['o'].write(data)
        return True
    except OSError as e:
        print(f'{ERR}E: {e}{RES}')
        return False


def fsync_data() -> bool:
    """
    """
    try:
        iod['o'].flush()
        fsync(iod['o'].fileno())
        return True
    except OSError as e:
        print(f'{ERR}E: {e}{RES}')
        return False


# Handle user input
# --------------------------------------------------------------------------- #


def select_action() -> int:
    """
    """
    while True:
        action: str = input(MENU)

        if action == '0':
            print(A0_DESCRIPTION)
            return 0

        if action == '1':
            print(A1_DESCRIPTION)
            return 1

        if action == '2':
            print(A2_DESCRIPTION)
            return 2

        if action == '3':
            print(A3_DESCRIPTION)
            return 3

        if action == '4':
            print(A4_DESCRIPTION)
            return 4

        if action == '5':
            print(A5_DESCRIPTION)
            return 5

        if action == '6':
            print(A6_DESCRIPTION)
            return 6

        if action == '7':
            print(A7_DESCRIPTION)
            return 7

        if action == '8':
            print(A8_DESCRIPTION)
            return 8

        if action == '9':
            print(A9_DESCRIPTION)
            return 9

        print(f'{ERR}E: invalid value{RES}')


def is_custom() -> bool:
    """
    """
    while True:
        custom: str = input(
            f'{BOL}[02] Use custom settings? (Y/N, default=N):{RES} ')

        if custom in ('', 'N', 'n', '0'):
            return False

        if custom in ('Y', 'y', '1'):
            return True

        print(f'{ERR}E: invalid value; valid values are: '
              f'Y, y, 1, N, n, 0{RES}')
        continue


def get_argon2_time_cost() -> int:
    """
    """
    while True:
        argon2_time_cost_s: str = input(
            f'    {BOL}[03] Argon2 time cost (default'
            f'={DEFAULT_ARGON2_TIME_COST}):{RES} ')

        if argon2_time_cost_s in ('', str(DEFAULT_ARGON2_TIME_COST)):
            return DEFAULT_ARGON2_TIME_COST

        try:
            argon2_time_cost: int = int(argon2_time_cost_s)
        except Exception:
            print(f'    {ERR}E: invalid value; must be an integer >= 1 and '
                  f'<= {argon2id.OPSLIMIT_MAX}{RES}')
            continue

        if argon2_time_cost < 1 or argon2_time_cost > argon2id.OPSLIMIT_MAX:
            print(f'    {ERR}E: invalid value; must be an integer >= 1 and '
                  f'<= {argon2id.OPSLIMIT_MAX}{RES}')
            continue

        return argon2_time_cost


def get_max_pad_size_percent() -> int:
    """
    """
    while True:
        max_pad_size_percent_s: str = input(
            f'    {BOL}[04] Max padding size, % (default'
            f'={DEFAULT_MAX_PAD_SIZE_PERCENT}):{RES} ')

        if max_pad_size_percent_s in ('', str(DEFAULT_MAX_PAD_SIZE_PERCENT)):
            return DEFAULT_MAX_PAD_SIZE_PERCENT

        try:
            max_pad_size_percent: int = int(max_pad_size_percent_s)
        except Exception:
            print(f'    {ERR}E: invalid value; must be an integer >= 0{RES}')
            continue

        if max_pad_size_percent < 0:
            print(f'    {ERR}E: invalid value; must be an integer >= 0{RES}')
            continue

        return max_pad_size_percent


def is_fake_mac() -> bool:
    """
    """
    while True:
        set_fake_mac: str = input(
            f'    {BOL}[05] Set a fake MAC tag? (Y/N, default=N):{RES} ')

        if set_fake_mac in ('', 'N', 'n', '0'):
            return False

        if set_fake_mac in ('Y', 'y', '1'):
            return True

        print(f'    {ERR}E: invalid value; valid values are: '
              f'Y, y, 1, N, n, 0{RES}')
        continue


def get_input_file(action: int) -> tuple:
    """
    """
    if action == 2:
        s: str = 'File to encrypt'
    elif action == 3:
        s = 'File to decrypt'
    elif action == 4:
        s = 'File to embed'
    elif action in (5, 7):
        s = 'Container'
    else:  # 6
        s = 'File to encrypt and embed'

    while True:
        i_file: str = input(f'{BOL}[06] {s}:{RES} ')

        if i_file == '':
            print(f'{ERR}E: input file path is not specified{RES}')
            continue

        if DEBUG:
            print(f'{ITA}D: real path: "{path.realpath(i_file)}"{RES}')

        i_size: Optional[int] = get_file_size(i_file)

        if i_size is None:
            continue

        i_object: Any = open_file(i_file, 'rb')

        if i_object is None:
            continue

        break

    return i_file, i_size, i_object


def get_output_file_new(action: int) -> tuple:
    """
    """
    if action == 2:
        s: str = 'Output (encrypted) file'
    elif action in (3, 7):
        s = 'Output (decrypted) file'
    else:  # 5, 8
        s = 'Output file'

    while True:
        o_file: str = input(f'{BOL}[07] {s}:{RES} ')

        if o_file == '':
            print(f'{ERR}E: output file path is not specified{RES}')
            continue

        if path.exists(o_file):
            print(f'{ERR}E: file "{o_file}" already exists{RES}')
            continue

        if DEBUG:
            print(f'{ITA}D: real path: "{path.realpath(o_file)}"{RES}')

        o_object: Any = open_file(o_file, 'wb')

        if o_object is None:
            continue

        break

    return o_file, o_object


def get_output_file_exist(i_file: str, i_size: int, action: int) -> tuple:
    """
    """
    if action in (4, 6):
        s: str = 'File to overwrite (container)'
    else:  # 9
        s = 'File to overwrite'

    while True:
        o_file: str = input(f'{BOL}[07] {s}:{RES} ')

        if o_file == '':
            print(f'{ERR}E: output file path is not specified{RES}')
            continue

        if o_file == i_file:
            print(f'{ERR}E: input and output files must not be at '
                  f'the same path{RES}')
            continue

        if DEBUG:
            print(f'{ITA}D: real path: "{path.realpath(o_file)}"{RES}')

        o_size: Optional[int] = get_file_size(o_file)

        if o_size is None:
            continue

        if o_size < i_size:
            print(f'{ERR}E: specified output file is too small ({o_size} B); '
                  f'size must be >= {i_size} B{RES}')
            continue

        o_object: Any = open_file(o_file, 'rb+')

        if o_object is None:
            continue

        break

    return o_file, o_size, o_object


def get_start_pos(max_start_pos: int, no_default: bool) -> int:
    """
    """
    while True:
        if no_default:
            start_pos_s: str = input(
                f'{BOL}[08] Start position, valid values '
                f'are [0; {max_start_pos}]:{RES} ')
            if start_pos_s == '':
                print(f'{ERR}E: start position is not specified{RES}')
                continue
        else:
            start_pos_s = input(
                f'{BOL}[08] Start position, valid values '
                f'are [0; {max_start_pos}], default=0:{RES} ')
            if start_pos_s == '':
                start_pos_s = '0'

        try:
            start_pos: int = int(start_pos_s)
        except Exception:
            print(f'{ERR}E: invalid value{RES}')
            continue

        if start_pos > max_start_pos or start_pos < 0:
            print(f'{ERR}E: invalid value{RES}')
            continue

        return start_pos


def get_end_pos(min_pos: int, max_pos: int, no_default: bool) -> int:
    """
    """
    while True:
        if no_default:
            end_pos_s: str = input(
                f'{BOL}[09] End position, valid values '
                f'are [{min_pos}; {max_pos}]:{RES} ')
        else:
            end_pos_s = input(
                f'{BOL}[09] End position, valid values '
                f'are [{min_pos}; {max_pos}], default={max_pos}:{RES} ')
            if end_pos_s == '':
                end_pos_s = str(max_pos)

        try:
            end_pos: int = int(end_pos_s)
        except Exception:
            print(f'{ERR}E: invalid value{RES}')
            continue

        if end_pos < min_pos or end_pos > max_pos:
            print(f'{ERR}E: invalid value{RES}')
            continue

        return end_pos


def get_pot_comments() -> bytes:
    """
    """
    comments: str = input(
        f'{BOL}[10] Comments (optional, up to {POT_COMMENTS_SIZE} B):{RES} ')

    if comments != '':
        # Sanitize comments: prevent possible UnicodeDecodeError in some cases
        comments = comments.encode(
        )[:POT_COMMENTS_SIZE].decode('utf-8', 'ignore')

        comments_bytes: bytes = comments.encode()

        pot_comments: bytes = b''.join([
            comments_bytes,
            INVALID_UTF8_BYTE,
            urandom(POT_COMMENTS_SIZE)
        ])[:POT_COMMENTS_SIZE]
    else:
        if md['set_fake_mac']:
            pot_comments = urandom(POT_COMMENTS_SIZE)
        else:
            while True:
                pot_comments = urandom(POT_COMMENTS_SIZE)

                if decode_pot_comments(pot_comments) is None:
                    # p=99.164% if POT_COMMENTS_SIZE=512
                    break

    if DEBUG:
        print(f'{ITA}D: comments: {[comments]}{RES}')
        print(f'{ITA}D: pot_comments: {[pot_comments]}{RES}')

    comments_decoded: Optional[str] = decode_pot_comments(pot_comments)
    print(f'{ITA}I: comments will be shown as: {[comments_decoded]}{RES}')

    return pot_comments


def get_ikm_digest_list() -> list:
    """
    Get input keying material (keyfiles and passphrases) and return digest
    list.
    """
    ikm_digest_list: list = []

    while True:
        k_file: str = input(f'{BOL}[11] Keyfile path (optional):{RES} ')

        if k_file == '':
            break

        if not path.exists(k_file):
            print(f'{ERR}E: file "{k_file}" does not exist{RES}')
            print(f'{ERR}E: keyfile NOT accepted{RES}')
            continue

        if DEBUG:
            print(f'{ITA}D: real path: "{path.realpath(k_file)}"{RES}')

        if path.isdir(k_file):
            digest_list: Optional[list] = get_keyfile_digest_list(k_file)

            if digest_list is None:
                print(f'{ERR}E: keyfiles NOT accepted{RES}')
                continue

            if not digest_list:
                print(f'{WAR}W: this directory is empty; no keyfiles '
                      f'to accept!{RES}')
            else:
                ikm_digest_list.extend(digest_list)
                print(f'{ITA}I: {len(digest_list)} keyfiles has been '
                      f'accepted{RES}')

                del k_file, digest_list
                collect()
        else:
            f_digest: Optional[bytes] = get_keyfile_digest(k_file)

            if f_digest is None:
                print(f'{ERR}E: keyfile NOT accepted{RES}')
            else:
                ikm_digest_list.append(f_digest)
                print(f'{ITA}I: keyfile accepted{RES}')
            continue

    if DEBUG:
        print(f'{WAR}W: entered passphrases will be displayed!{RES}')

    while True:
        pp0: bytes = getpass(
            f'{BOL}[12] Passphrase (optional):{RES} '
        ).encode()

        if not pp0:
            break

        if DEBUG:
            print(f'{ITA}D: entered passphrase: {pp0!r}{RES}')
            print(f'{ITA}D: length: {len(pp0)} B{RES}')

        pp1: bytes = getpass(
            f'{BOL}[12] Confirm passphrase:{RES} '
        ).encode()

        if DEBUG:
            print(f'{ITA}D: entered passphrase: {pp1!r}{RES}')
            print(f'{ITA}D: length: {len(pp1)} B{RES}')

        if compare_digest(pp0, pp1):
            print(f'{ITA}I: passphrase accepted{RES}')

            pp_digest: bytes = get_passphrase_digest(pp0)
            ikm_digest_list.append(pp_digest)
        else:
            print(f'{ERR}E: passphrase confirmation failed{RES}')

        del pp0, pp1
        collect()

    return ikm_digest_list


def proceed(var: int) -> bool:
    """
    """
    if var == 1:
        print(f'{WAR}W: output file contents will be '
              f'partially overwritten!{RES}')
        question: str = f'{BOL}[13] Proceed? (Y/N):{RES} '
    else:
        print(f'{ITA}I: next it\'s offered to remove '
              f'the output file path{RES}')
        question = f'{BOL}[13] Proceed? (Y/N, default=Y):{RES} '

    while True:
        user_input: str = input(question)

        if user_input in ('Y', 'y', '1'):
            return True

        if user_input == '' and var == 2:
            return True

        if user_input in ('N', 'n', '0'):
            return False

        print(f'{ERR}E: invalid value; valid values are: '
              f'Y, y, 1, N, n, 0{RES}')
        continue


def get_output_file_size() -> int:
    """
    """
    while True:
        o_size_s: str = input(f'{BOL}[14] Output file size in bytes:{RES} ')

        if o_size_s == '':
            print(f'{ERR}E: output file size is not specified{RES}')
            continue

        try:
            o_size: int = int(o_size_s)
        except Exception as e:
            print(f'{ERR}E: {e}{RES}')
            continue

        if o_size < 0:
            print(f'{ERR}E: negative file size value{RES}')
            continue

        return o_size


# Handle various things to perform actions
# --------------------------------------------------------------------------- #


def set_custom_settings(action: int) -> None:
    """
    """
    custom: bool = is_custom()

    print(f'{ITA}I: use custom settings: {custom}{RES}')

    if custom:
        if action in (2, 6):
            print(f'{WAR}W: decryption will require the same custom '
                  f'values!{RES}')

        argon2_time_cost: int = get_argon2_time_cost()
        max_pad_size_percent: int = get_max_pad_size_percent()

        if action in (2, 6):
            set_fake_mac: bool = is_fake_mac()
    else:
        argon2_time_cost = DEFAULT_ARGON2_TIME_COST
        max_pad_size_percent = DEFAULT_MAX_PAD_SIZE_PERCENT

        if action in (2, 6):
            set_fake_mac = DEFAULT_SET_FAKE_MAC

    if DEBUG:
        print(f'{ITA}D: Argon2 time cost: {argon2_time_cost}{RES}')
        print(f'{ITA}D: max padding size, %: {max_pad_size_percent}{RES}')

        if action in (2, 6):
            print(f'{ITA}D: set fake MAC tag: {set_fake_mac}{RES}')

    md['argon2_time_cost'] = argon2_time_cost
    md['max_pad_size_percent'] = max_pad_size_percent
    if action in (2, 6):
        md['set_fake_mac'] = set_fake_mac


def get_salts(i_size: int, end_pos: int, action: int) -> bool:
    """
    """
    if DEBUG:
        print(f'{ITA}D: salt handling...{RES}')

    if action in (2, 6):
        blake2_salt: bytes = urandom(ONE_SALT_SIZE)
        argon2_salt: bytes = urandom(ONE_SALT_SIZE)

        header_salt: bytes = b''.join([
            blake2_salt[:ONE_SALT_HALF_SIZE],
            argon2_salt[:ONE_SALT_HALF_SIZE]
        ])

        footer_salt: bytes = b''.join([
            blake2_salt[-ONE_SALT_HALF_SIZE:],
            argon2_salt[-ONE_SALT_HALF_SIZE:]
        ])
    else:
        # 3, 7
        # read the salts from the beginning and the end of the cryptoblob

        opt_data: Optional[bytes] = read_data(iod['i'], SALTS_HALF_SIZE)

        if opt_data is None:
            return False

        header_salt = opt_data

        if DEBUG:
            print(f'{ITA}D: header_salt has been read{RES}')
            print_positions()

        cur_pos: int = iod['i'].tell()

        if action == 3:
            new_pos: int = i_size - SALTS_HALF_SIZE
        else:  # 7
            new_pos = end_pos - SALTS_HALF_SIZE

        # move to the beginning of footer_salt
        if not seek_pos(iod['i'], new_pos):
            return False

        if DEBUG:
            print(f'{ITA}D: current position: before footer_salt{RES}')
            print_positions()

        opt_data = read_data(iod['i'], SALTS_HALF_SIZE)

        if opt_data is None:
            return False

        footer_salt = opt_data

        if DEBUG:
            print(f'{ITA}D: footer_salt has been read{RES}')
            print_positions()

        # return to the previously saved position
        if not seek_pos(iod['i'], cur_pos):
            return False

        if DEBUG:
            print(f'{ITA}D: returned to the position after '
                  f'header_salt{RES}')
            print_positions()

        blake2_salt = b''.join([
            header_salt[:ONE_SALT_HALF_SIZE],
            footer_salt[:ONE_SALT_HALF_SIZE]
        ])

        argon2_salt = b''.join([
            header_salt[-ONE_SALT_HALF_SIZE:],
            footer_salt[-ONE_SALT_HALF_SIZE:]
        ])

    sd['blake2_salt'] = blake2_salt
    sd['argon2_salt'] = argon2_salt
    sd['header_salt'] = header_salt
    sd['footer_salt'] = footer_salt

    if DEBUG:
        print(f'{ITA}D: blake2_salt: {blake2_salt.hex()}{RES}')
        print(f'{ITA}D: argon2_salt: {argon2_salt.hex()}{RES}')
        print(f'{ITA}D: header_salt: {header_salt.hex()}{RES}')
        print(f'{ITA}D: footer_salt: {footer_salt.hex()}{RES}')
        print(f'{ITA}D: salt handling is completed{RES}')

    return True


def blake2b_keyfile_digest(
    f: Any,
    f_size: int,
    salt: bytes
) -> Optional[bytes]:
    """
    """
    ho: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        person=PERSON_KEYFILE,
        salt=salt
    )

    num_chunks: int = f_size // RW_CHUNK_SIZE
    rem_size: int = f_size % RW_CHUNK_SIZE

    for _ in range(num_chunks):
        data: Optional[bytes] = read_data(f, RW_CHUNK_SIZE)

        if data is None:
            return None

        ho.update(data)

    if rem_size:
        data = read_data(f, rem_size)

        if data is None:
            return None

        ho.update(data)

    keyfile_digest: bytes = ho.digest()

    return keyfile_digest


def get_keyfile_digest(f_path: str) -> Optional[bytes]:
    """
    """
    f_size: Optional[int] = get_file_size(f_path)

    if f_size is None:
        return None

    print(f'{ITA}I: path: "{f_path}"; size: {string_size(f_size)}{RES}')
    print(f'{ITA}I: hashing the keyfile...{RES}')

    f: Any = open_file(f_path, 'rb')

    if f is None:
        return None

    f_digest: Optional[bytes] = blake2b_keyfile_digest(
        f, f_size, salt=sd['blake2_salt'])

    close_file(f)

    if f_digest is None:
        return None

    if DEBUG:
        print(f'{ITA}D: digest:\n    {f_digest.hex()}{RES}')

    return f_digest


def get_keyfile_digest_list(d_path: str) -> Optional[list]:
    """
    """
    f_tuple_list: list = []

    size_sum: int = 0

    print(f'{ITA}I: scanning the directory "{d_path}"{RES}')

    for root, _, files in walk(d_path):
        for fp in files:
            f_path: str = path.join(root, fp)

            if DEBUG:
                print(f'{ITA}D: getting the size of "{f_path}" '
                      f'(real path: "{path.realpath(f_path)}"){RES}')

            opt_f_size: Optional[int] = get_file_size(f_path)

            if opt_f_size is None:
                return None

            f_size: int = opt_f_size

            if DEBUG:
                print(f'{ITA}D: size: {string_size(f_size)}{RES}')

            size_sum += f_size

            f_tuple: tuple = (f_path, f_size)

            f_tuple_list.append(f_tuple)

    f_tuple_list_len: int = len(f_tuple_list)

    if f_tuple_list_len == 0:
        return []

    for f_tuple in f_tuple_list:
        f_path, f_size = f_tuple
        print(f'{ITA}  - found "{f_path}", {string_size(f_size)}{RES}')

    print(f'{ITA}I: found {f_tuple_list_len} files; '
          f'total size: {string_size(size_sum)}{RES}')

    print(f'{ITA}I: hashing files in the directory "{d_path}"{RES}')

    digest_list: list = []

    for f_tuple in f_tuple_list:

        f_path, f_size = f_tuple

        if DEBUG:
            print(f'{ITA}D: hashing "{f_path}"{RES}')

        f = open_file(f_path, 'rb')

        if f is None:
            return None

        f_digest = blake2b_keyfile_digest(f, f_size, salt=sd['blake2_salt'])

        close_file(f)

        if f_digest is None:
            return None

        if DEBUG:
            print(f'{ITA}D: digest:\n    {f_digest.hex()}{RES}')

        digest_list.append(f_digest)

    return digest_list


def get_passphrase_digest(pp: bytes) -> bytes:
    """
    """
    ho: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        person=PERSON_PASSPHRASE,
        salt=sd['blake2_salt']
    )

    ho.update(pp)

    pp_digest: bytes = ho.digest()

    if DEBUG:
        print(f'{ITA}D: passphrase digest:\n    {pp_digest.hex()}{RES}')

    return pp_digest


def get_argon2_password() -> None:
    """
    """
    digest_list: list = get_ikm_digest_list()

    print(f'{ITA}I: entering keying material is completed{RES}')

    if not digest_list:
        print(f'{WAR}W: no keyfile or passphrase specified!{RES}')

    if DEBUG:
        print(f'{ITA}D: user input is complete{RES}')
        print_positions()

    digest_list.sort()

    if DEBUG and digest_list:
        print(f'{ITA}D: sorted digests of keying material items:{RES}')
        for digest in digest_list:
            print(f'{ITA}  - {digest.hex()}{RES}')

    ho: Any = blake2b(
        digest_size=IKM_DIGEST_SIZE,
        salt=sd['blake2_salt']
    )

    for digest in digest_list:
        ho.update(digest)

    md['argon2_password'] = ho.digest()

    if DEBUG:
        argon2_password: bytes = md['argon2_password']
        print(f'{ITA}D: argon2_password:\n    {argon2_password.hex()}{RES}')


def derive_keys() -> bool:
    """
    Derive keys using Argon2 MHF.
    """
    print(f'{ITA}I: deriving keys...{RES}')

    t0: float = monotonic()

    try:
        argon2_tag: bytes = argon2id.kdf(
            size=ARGON2_TAG_SIZE,
            password=md['argon2_password'],
            salt=sd['argon2_salt'],
            opslimit=md['argon2_time_cost'],
            memlimit=ARGON2_MEM
        )
    except RuntimeError as e:
        print(f'{ERR}E: {e}{RES}')
        return False

    t1: float = monotonic()

    # enc_key:32 || pad_key:32 ||  mac_key:64 = argon2_tag:128

    enc_key: bytes = argon2_tag[:ENC_KEY_SIZE]
    pad_key: bytes = argon2_tag[ENC_KEY_SIZE:ENC_KEY_SIZE + PAD_KEY_SIZE]
    mac_key: bytes = argon2_tag[-MAC_KEY_SIZE:]

    if DEBUG:
        print(f'{ITA}D: argon2_tag:\n    {argon2_tag.hex()}{RES}')
        print(f'{ITA}D: enc_key:\n    {enc_key.hex()}{RES}')
        print(f'{ITA}D: pad_key:\n    {pad_key.hex()}{RES}')
        print(f'{ITA}D: mac_key:\n    {mac_key.hex()}{RES}')

    print(f'{ITA}I: keys derived in {round(t1 - t0, 1)}s{RES}')

    md['enc_key'] = enc_key
    md['pad_key'] = pad_key
    md['mac_key'] = mac_key

    return True


def encrypt_decrypt(input_data: bytes) -> bytes:
    """
    Encrypt or decrypt data chunk with ChaCha20 cipher.
    """
    md['nonce_counter'] += 1

    nonce_counter: int = md['nonce_counter']

    nonce: bytes = nonce_counter.to_bytes(NONCE_SIZE, BYTEORDER)

    cipher: Any = ChaCha20.new(key=md['enc_key'], nonce=nonce)

    output_data: bytes = cipher.encrypt(input_data)

    if DEBUG:
        print(f'{ITA}D: nonce counter: {nonce_counter}, '
              f'nonce: {nonce.hex()}{RES}')

    return output_data


def pad_from_ciphertext(
    ciphertext_size: int,
    pad_key1_bytes: bytes,
    max_pad_size_percent: int
) -> int:
    """
    """
    pad_key1_int: int = int.from_bytes(pad_key1_bytes, BYTEORDER)

    pad_size: int = ciphertext_size * max_pad_size_percent * pad_key1_int // (
        PAD_KEY_SPACE * 100)

    if DEBUG:
        print(f'{ITA}D: getting total pad size...{RES}')

        print(f'{ITA}D: pad_key1_bytes:             '
              f'{pad_key1_bytes.hex()}{RES}')

        print(f'{ITA}D: pad_key1_int:               {pad_key1_int}{RES}')

        print(f'{ITA}D: pad_key1_int/PAD_KEY_SPACE: '
              f'{pad_key1_int/PAD_KEY_SPACE}{RES}')

        print(f'{ITA}D: ciphertext_size:            '
              f'{string_size(ciphertext_size)} B{RES}')

        print(f'{ITA}D: pad_size:                   '
              f'{string_size(pad_size)}{RES}')

        print(f'{ITA}D: pad_size/ciphertext_size:   '
              f'{pad_size/ciphertext_size}{RES}')

    return pad_size


def pad_from_padded_ciphertext(
    padded_ciphertext_size: int,
    pad_key1_bytes: bytes,
    max_pad_size_percent: int
) -> int:
    """
    """
    pad_key1_int: int = int.from_bytes(pad_key1_bytes, BYTEORDER)

    pad_size: int = (
        padded_ciphertext_size * pad_key1_int * max_pad_size_percent // (
            pad_key1_int * max_pad_size_percent + PAD_KEY_SPACE * 100)
    )

    if DEBUG:
        print(f'{ITA}D: getting total pad size...{RES}')

        print(f'{ITA}D: pad_key1_bytes:             '
              f'{pad_key1_bytes.hex()}{RES}')

        print(f'{ITA}D: pad_key1_int:               {pad_key1_int}{RES}')

        print(f'{ITA}D: pad_key1_int/PAD_KEY_SPACE: '
              f'{pad_key1_int/PAD_KEY_SPACE}{RES}')

        print(f'{ITA}D: padded_ciphertext_size:     '
              f'{string_size(padded_ciphertext_size)}{RES}')

        print(f'{ITA}D: pad_size:                   '
              f'{string_size(pad_size)}{RES}')

        ciphertext_size: int = padded_ciphertext_size - pad_size

        print(f'{ITA}D: ciphertext_size:            '
              f'{string_size(ciphertext_size)}{RES}')

        print(f'{ITA}D: pad_size/ciphertext_size:   '
              f'{pad_size/ciphertext_size}{RES}')

    return pad_size


def header_footer_pads(
    pad_size: int,
    pad_key2_bytes: bytes
) -> tuple:
    """
    """
    pad_key2_int: int = int.from_bytes(pad_key2_bytes, BYTEORDER)

    header_pad_size: int = pad_key2_int % (pad_size + 1)
    footer_pad_size: int = pad_size - header_pad_size

    if DEBUG:
        print(f'{ITA}D: getting sizes of header_pad and footer_pad...{RES}')
        print(f'{ITA}D: pad_key2_bytes:   {pad_key2_bytes.hex()}{RES}')
        print(f'{ITA}D: pad_key2_int:     {pad_key2_int}{RES}')
        print(f'{ITA}D: header_pad_size:  {string_size(header_pad_size)}{RES}')
        print(f'{ITA}D: footer_pad_size:  {string_size(footer_pad_size)}{RES}')

    return header_pad_size, footer_pad_size


def write_pad(
    pad_size: int,
    action: int,
    w_sum: int,
    t_start: float,
    t_last_print: float,
    output_data_size: int
) -> Optional[tuple]:
    """
    """
    if action in (2, 6):
        num_chunks: int = pad_size // RW_CHUNK_SIZE
        rem_size: int = pad_size % RW_CHUNK_SIZE

        for _ in range(num_chunks):
            chunk: bytes = urandom(RW_CHUNK_SIZE)

            if not write_data(chunk):
                return None

            w_sum += len(chunk)

            if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                progress(w_sum, output_data_size, t_start)
                t_last_print = monotonic()

        if rem_size:
            chunk = urandom(rem_size)

            if not write_data(chunk):
                return None

            w_sum += len(chunk)

            if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                progress(w_sum, output_data_size, t_start)
                t_last_print = monotonic()
    else:  # 3, 7
        if not seek_pos(iod['i'], pad_size, 1):
            return None

    return w_sum, t_last_print


def decode_pot_comments(pot_comments: bytes) -> Optional[str]:
    """
    """
    pot_comments_part: bytes = pot_comments.partition(INVALID_UTF8_BYTE)[0]

    try:
        decoded_comments: Optional[str] = pot_comments_part.decode('utf-8')
    except UnicodeDecodeError:
        decoded_comments = None

    return decoded_comments


def string_size(size: int) -> str:
    """
    """
    if size >= G:
        s: str = f'{size} B, {round(size / G, 1)} GiB'
    elif size >= M:
        s = f'{size} B, {round(size / M, 1)} MiB'
    elif size >= K:
        s = f'{size} B, {round(size / K, 1)} KiB'
    else:
        s = f'{size} B'

    return s


def progress(written_sum: int, data_size: int, t_start: float) -> None:
    """
    """
    if data_size == 0:
        print(f'{ITA}I: written 0 B{RES}')
        return

    t: float = monotonic() - t_start

    if t > 0:
        print(
            f'{ITA}I: written {string_size(written_sum)}, '
            f'{round(written_sum / data_size * 100, 1)}% in '
            f'{round(t, 1)}s, avg {round(written_sum / M / t, 1)} MiB/s{RES}')
    else:
        print(f'{ITA}I: written {string_size(written_sum)}, '
              f'{round(written_sum / data_size * 100, 1)}% in '
              f'{round(t, 1)}s{RES}')


def print_positions() -> None:
    """
    """
    o: int = iod['o'].tell()

    if 'i' in iod:
        i: int = iod['i'].tell()
        print(f'{ITA}D: current positions: if={i}, of={o}{RES}')
    else:
        print(f'{ITA}D: current position: of={o}{RES}')


def remove_output() -> None:
    """
    """
    if proceed(var=2):
        o_name: str = iod['o'].name
        try:
            remove(o_name)
            print(f'{ITA}I: path "{o_name}" has been removed{RES}')
        except Exception as e:
            print(f'{ERR}E: {e}{RES}')
            print(f'{WAR}W: failed to remove path "{o_name}"!{RES}')
    else:
        print(f'{ITA}I: output file path is NOT removed{RES}')


# Perform actions: high-level functions
# --------------------------------------------------------------------------- #


def encrypt_and_embed(action: int) -> bool:
    """
    """
    md['act'] = True

    pot_comments: Optional[bytes] = None
    ciphertext_size: Optional[int] = None
    start_pos: Optional[int] = None
    end_pos: Optional[int] = None

    set_custom_settings(action)

    i_file, i_size, iod['i'] = get_input_file(action)

    print(f'{ITA}I: path: "{i_file}"; '
          f'size: {string_size(i_size)}{RES}')

    if action in (2, 6):
        ciphertext_size = i_size + POT_COMMENTS_SIZE

        min_cryptoblob_size: int = i_size + MIN_VALID_CRYPTOBLOB_SIZE

        max_pad: int = ciphertext_size * md['max_pad_size_percent'] // 100 - 1
        max_pad = max(0, max_pad)

        max_cryptoblob_size: int = max_pad + min_cryptoblob_size

        if DEBUG:
            print(f'{ITA}D: ciphertext_size: {ciphertext_size}')
            print(f'D: min_cryptoblob_size: {min_cryptoblob_size}')
            print(f'D: max_pad: {max_pad}')
            print(f'D: max_cryptoblob_size: {max_cryptoblob_size}{RES}')

    if action in (3, 7):
        if i_size < MIN_VALID_CRYPTOBLOB_SIZE:
            if action == 3:
                print(f'{ERR}E: input file is too small (min valid '
                      f'cryptoblob size is {MIN_VALID_CRYPTOBLOB_SIZE} '
                      f'bytes){RES}')
            else:  # 7
                print(f'{ERR}E: inporrect start/end positions (min '
                      f'valid cryptoblob size is '
                      f'{MIN_VALID_CRYPTOBLOB_SIZE} B){RES}')
            return False

    if action in (2, 3):
        o_file, iod['o'] = get_output_file_new(action)
        print(f'{ITA}I: new file "{o_file}" has been created{RES}')
    elif action == 6:
        o_file, o_size, iod['o'] = get_output_file_exist(
            i_file, max_cryptoblob_size, action
        )
        max_start_pos: int = o_size - max_cryptoblob_size
        print(f'{ITA}I: path: "{o_file}"{RES}')
    else:  # 7
        o_file, iod['o'] = get_output_file_new(action)
        max_start_pos = i_size - MIN_VALID_CRYPTOBLOB_SIZE
        print(f'{ITA}I: new file "{o_file}" has been created{RES}')

    if action == 6:
        print(f'{ITA}I: size: {string_size(o_size)}{RES}')

    if action in (6, 7):
        start_pos = get_start_pos(max_start_pos, no_default=True)

        print(f'{ITA}I: start position: {start_pos}{RES}')

    if action == 7:
        end_pos = get_end_pos(
            min_pos=start_pos + MIN_VALID_CRYPTOBLOB_SIZE,
            max_pos=i_size,
            no_default=True
        )
        print(f'{ITA}I: end position: {end_pos}{RES}')

    if action in (2, 6):
        pot_comments = get_pot_comments()

    if action == 6:
        if not seek_pos(iod['o'], start_pos):
            return False
    if action == 7:
        if not seek_pos(iod['i'], start_pos):
            return False

    if DEBUG and action in (6, 7):
        print(f'{ITA}D: pointers set to start positions{RES}')
        print_positions()

    if not get_salts(i_size, end_pos, action):
        return False

    get_argon2_password()

    collect()

    if action == 6:
        if not proceed(var=1):
            print(f'{ITA}I: stopped by user request{RES}')
            return False

    ok: bool = encrypt_and_embed_handler(
        action,
        i_size,
        start_pos,
        end_pos,
        ciphertext_size,
        pot_comments,
    )

    return ok


def encrypt_and_embed_handler(
    action: int,
    i_size: int,
    start_pos: Optional[int],
    end_pos: Optional[int],
    ciphertext_size: Optional[int],
    pot_comments: Optional[bytes],
) -> bool:
    """
    """
    if not derive_keys():
        return False

    # Init ChaCha20 nonce counter for the current action
    md['nonce_counter'] = NONCE_COUNTER_INIT_VALUE

    # Init MAC for the current action
    mac_ho: Any = blake2b(
        digest_size=MAC_TAG_SIZE,
        key=md['mac_key']
    )

    # ----------------------------------------------------------------------- #

    pad_key: bytes = md['pad_key']

    pad_key1: bytes = pad_key[:PAD_KEY_SIZE // 2]
    pad_key2: bytes = pad_key[-PAD_KEY_SIZE // 2:]

    if action in (2, 6):
        pad_size: int = pad_from_ciphertext(
            ciphertext_size,
            pad_key1,
            md['max_pad_size_percent']
        )
    else:  # 3, 7
        if action == 3:
            padded_ciphertext_size: int = i_size - SALTS_SIZE - MAC_TAG_SIZE
        else:  # 7
            padded_ciphertext_size = (
                end_pos - start_pos - SALTS_SIZE - MAC_TAG_SIZE)

        pad_size = pad_from_padded_ciphertext(
            padded_ciphertext_size,
            pad_key1,
            md['max_pad_size_percent']
        )

    header_pad_size, footer_pad_size = header_footer_pads(pad_size, pad_key2)

    del pad_key, pad_key1, pad_key2
    del md['argon2_password'], md['pad_key'], md['mac_key']

    collect()

    # ----------------------------------------------------------------------- #

    if action in (2, 6):
        cryptoblob_size: int = i_size + pad_size + MIN_VALID_CRYPTOBLOB_SIZE
    elif action == 3:
        cryptoblob_size = i_size
    else:  # 7
        cryptoblob_size = end_pos - start_pos

    if action in (2, 6):
        contents_size: int = i_size
    else:  # 3, 7
        contents_size = cryptoblob_size - pad_size - MIN_VALID_CRYPTOBLOB_SIZE

    if action in (2, 6):
        output_data_size: int = (
            contents_size + pad_size + MIN_VALID_CRYPTOBLOB_SIZE)
    else:  # 3, 7
        output_data_size = contents_size

    if DEBUG:
        print(f'{ITA}D: contents size: {string_size(contents_size)}{RES}')
        print(f'{ITA}D: cryptoblob size: {string_size(cryptoblob_size)}{RES}')
        print(f'{ITA}D: output data size: '
              f'{string_size(output_data_size)}{RES}')

    if contents_size < 0:
        print(f'{ERR}E: invalid combination of input values{RES}')
        return False

    t_start: float = monotonic()
    t_last_print: float = t_start

    w_sum: int = 0

    # ----------------------------------------------------------------------- #

    print(f'{ITA}I: reading, writing...{RES}')

    header_salt: bytes = sd['header_salt']
    footer_salt: bytes = sd['footer_salt']

    mac_ho.update(header_salt)
    mac_ho.update(footer_salt)

    if action in (2, 6):
        if DEBUG:
            print(f'{ITA}D: writing header_salt...{RES}')

        if not write_data(header_salt):
            return False

        w_sum += len(header_salt)

        if DEBUG:
            print(f'{ITA}D: header_salt is written{RES}')
            print_positions()

    # ----------------------------------------------------------------------- #

    if DEBUG:
        print(f'{ITA}D: handling header padding...{RES}')

    rnd_pad_pos0: int = iod['o'].tell()

    write_pad_res: Optional[tuple] = write_pad(
        header_pad_size, action, w_sum, t_start, t_last_print, output_data_size
    )

    if write_pad_res is None:
        return False

    w_sum, t_last_print = write_pad_res

    rnd_pad_pos1: int = iod['o'].tell()

    if DEBUG:
        print(f'{ITA}D: handling header padding is completed{RES}')
        print_positions()

    # ----------------------------------------------------------------------- #

    if DEBUG:
        print(f'{ITA}D: handling comments...{RES}')

    if action in (3, 7):
        pot_comments = read_data(iod['i'], POT_COMMENTS_SIZE)

        if pot_comments is None:
            return False

    pot_comments_out: bytes = encrypt_decrypt(pot_comments)

    if DEBUG:
        print(f'{ITA}D: pot_comments found in plain and encrypted forms{RES}')

    if action in (2, 6):
        if not write_data(pot_comments_out):
            return False

        w_sum += len(pot_comments_out)

        if DEBUG:
            print(f'{ITA}D: encrypted comments '
                  f'(size={len(pot_comments_out)}) is written{RES}')
    else:  # 3, 7
        decoded_comments: Optional[str] = decode_pot_comments(pot_comments_out)

        print(f'{ITA}I: comments: {[decoded_comments]}{RES}')

    if action in (2, 6):
        mac_ho.update(pot_comments_out)
    else:  # 3, 7
        mac_ho.update(pot_comments)

    if DEBUG:
        print(f'{ITA}D: handling comments is completed{RES}')
        print_positions()

    # ----------------------------------------------------------------------- #

    if DEBUG:
        if action in (2, 6):
            print(f'{ITA}D: handling input file contents...{RES}')
        else:  # 3, 7
            print(f'{ITA}D: writing output file contents...{RES}')

    num_chunks = contents_size // RW_CHUNK_SIZE
    rem_size = contents_size % RW_CHUNK_SIZE

    for _ in range(num_chunks):
        input_chunk: Optional[bytes] = read_data(iod['i'], RW_CHUNK_SIZE)

        if input_chunk is None:
            return False

        output_chunk: bytes = encrypt_decrypt(input_chunk)

        if not write_data(output_chunk):
            return False

        w_sum += len(output_chunk)

        if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
            progress(w_sum, output_data_size, t_start)
            t_last_print = monotonic()

        if DEBUG:
            print(f'{ITA}D: contents chunk (size={len(output_chunk)}) '
                  f'is written{RES}')
            print_positions()

        if action in (2, 6):
            mac_ho.update(output_chunk)
        else:  # 3, 7
            mac_ho.update(input_chunk)

    if rem_size:
        input_chunk = read_data(iod['i'], rem_size)

        if input_chunk is None:
            return False

        output_chunk = encrypt_decrypt(input_chunk)

        if not write_data(output_chunk):
            return False

        w_sum += len(output_chunk)

        if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
            progress(w_sum, output_data_size, t_start)
            t_last_print = monotonic()

        if DEBUG:
            print(f'{ITA}D: contents chunk (size={len(output_chunk)}) '
                  f'is written{RES}')

        if action in (2, 6):
            mac_ho.update(output_chunk)
        else:  # 3, 7
            mac_ho.update(input_chunk)

    if DEBUG:
        print(f'{ITA}D: handling input file contents is completed{RES}')

        if action in (2, 6):
            print(f'{ITA}D: encryption is completed{RES}')

        print_positions()

    if action in (3, 7):
        print(f'{ITA}I: decryption is completed{RES}')

    # ----------------------------------------------------------------------- #

    if DEBUG:
        print(f'{ITA}D: handling MAC tag...{RES}')

    found_mac_tag: bytes = mac_ho.digest()

    if DEBUG:
        print(f'{ITA}D: found MAC tag:\n    {found_mac_tag.hex()}{RES}')

    if action in (2, 6):
        fake_mac_tag: bytes = urandom(MAC_TAG_SIZE)

        if DEBUG:
            print(f'{ITA}D: fake MAC tag:\n    {fake_mac_tag.hex()}{RES}')

        if md['set_fake_mac']:
            mac_tag: bytes = fake_mac_tag
        else:
            mac_tag = found_mac_tag

        if DEBUG:
            print(f'{ITA}D: MAC tag to write:\n    {mac_tag.hex()}{RES}')

        if not write_data(mac_tag):
            return False

        if DEBUG:
            print(f'{ITA}D: MAC tag is written{RES}')

        w_sum += len(mac_tag)
    else:  # 3, 7
        read_mac_tag: Optional[bytes] = read_data(iod['i'], MAC_TAG_SIZE)

        if read_mac_tag is None:
            md['auth_fail'] = True

            print(f'{WAR}W: integrity/authenticity verification failed!{RES}')
            return False

        if DEBUG:
            print(f'{ITA}D: read MAC tag:\n    {read_mac_tag.hex()}{RES}')

        if compare_digest(found_mac_tag, read_mac_tag):
            if DEBUG:
                print(f'{ITA}D: found_mac_tag is equal to read_mac_tag{RES}')

            print(f'{ITA}I: integrity/authenticity verification: OK{RES}')
        else:
            md['auth_fail'] = True

            if DEBUG:
                print(f'{ITA}D: found_mac_tag is not equal to '
                      f'read_mac_tag{RES}')

            print(f'{WAR}W: integrity/authenticity verification failed!{RES}')

    if DEBUG:
        print(f'{ITA}D: handling MAC tag is completed{RES}')
        print_positions()

    # ----------------------------------------------------------------------- #

    if DEBUG:
        print(f'{ITA}D: handling footer padding...{RES}')

    rnd_pad_pos2: int = iod['o'].tell()

    write_pad_res = write_pad(
        footer_pad_size, action, w_sum, t_start, t_last_print, output_data_size
    )

    if write_pad_res is None:
        return False

    w_sum, t_last_print = write_pad_res

    rnd_pad_pos3: int = iod['o'].tell()

    if DEBUG:
        print(f'{ITA}D: handling footer padding is completed{RES}')
        print_positions()

    # ----------------------------------------------------------------------- #

    if action in (2, 6):
        if DEBUG:
            print(f'{ITA}D: writing footer_salt...{RES}')

        if not write_data(footer_salt):
            return False

        w_sum += len(footer_salt)

        progress(w_sum, output_data_size, t_start)

        if DEBUG:
            print(f'{ITA}D: footer_salt is written{RES}')
            print_positions()

    if action == 6:
        print(f'{ITA}I: fsyncing...{RES}')
        t0: float = monotonic()

        if not fsync_data():
            return False

        t1: float = monotonic()
        print(f'{ITA}I: fsynced in {round(t1 - t0, 1)}s{RES}')

    # ----------------------------------------------------------------------- #

    if action == 6:
        end_pos = iod['o'].tell()
        print(f'{ITA}I: remember the location of the cryptoblob in the '
              f'container:')
        print(f'    [{start_pos}:{end_pos}]{RES}')

    if action in (3, 7):
        progress(w_sum, output_data_size, t_start)

    if DEBUG:
        print(f'{ITA}D: expected output data size: {output_data_size} B{RES}')
        print(f'{ITA}D: written {w_sum} B{RES}')

    if w_sum != output_data_size:
        print(f'{ERR}E: the size of the written data does not match '
              f'the expected size{RES}')
        return False

    if action in (2, 6):
        print(f'{ITA}I: padding location in the output file:\n'
              f'    [{rnd_pad_pos0}:{rnd_pad_pos1}] — '
              f'{string_size(rnd_pad_pos1 - rnd_pad_pos0)}\n'
              f'    [{rnd_pad_pos2}:{rnd_pad_pos3}] — '
              f'{string_size(rnd_pad_pos3 - rnd_pad_pos2)}{RES}')

    return True


def embed(action: int) -> bool:
    """
    """
    md['act'] = True

    i_file, i_size, iod['i'] = get_input_file(action)

    print(f'{ITA}I: path: "{i_file}"; '
          f'size: {string_size(i_size)}{RES}')

    if action == 4:
        o_file, o_size, iod['o'] = get_output_file_exist(
            i_file, i_size, action)
        max_start_pos = o_size - i_size
        print(f'{ITA}I: path: "{o_file}"{RES}')
    else:  # 5
        o_file, iod['o'] = get_output_file_new(action)
        max_start_pos = i_size - 1
        print(f'{ITA}I: new file "{o_file}" has been created{RES}')

    if action == 4:
        print(f'{ITA}I: size: {string_size(o_size)}{RES}')

    start_pos: int = get_start_pos(max_start_pos, no_default=True)
    print(f'{ITA}I: start position: {start_pos}{RES}')

    if action == 4:
        message_size: int = i_size
        end_pos: int = start_pos + message_size
        print(f'{ITA}I: end position: {end_pos}{RES}')

        if not proceed(var=1):
            print(f'{ITA}I: stopped by user request{RES}\n')
            return False
    else:
        end_pos = get_end_pos(
            min_pos=start_pos,
            max_pos=i_size,
            no_default=True
        )
        print(f'{ITA}I: end position: {end_pos}{RES}')

        message_size = end_pos - start_pos

        print(f'{ITA}I: message size to retrieve: {message_size} B{RES}')

    ok: bool = embed_handler(action, start_pos, message_size)

    return ok


def embed_handler(action: int, start_pos: int, message_size: int) -> bool:
    """
    """
    if DEBUG:
        print_positions()

    # seek start_pos in the container
    if action == 4:
        if not seek_pos(iod['o'], start_pos):
            return False
    else:  # 5
        if not seek_pos(iod['i'], start_pos):
            return False

    if DEBUG:
        print_positions()

    print(f'{ITA}I: reading, writing...{RES}')

    ho: Any = blake2b(digest_size=EMBED_DIGEST_SIZE)

    t_start: float = monotonic()
    t_last_print: float = t_start

    w_sum: int = 0

    num_chunks: int = message_size // RW_CHUNK_SIZE
    rem_size: int = message_size % RW_CHUNK_SIZE

    for _ in range(num_chunks):
        i_data: Optional[bytes] = read_data(iod['i'], RW_CHUNK_SIZE)

        if i_data is None:
            return False

        if not write_data(i_data):
            return False

        ho.update(i_data)

        w_sum += len(i_data)

        if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
            progress(w_sum, message_size, t_start)
            t_last_print = monotonic()

    if rem_size:
        i_data = read_data(iod['i'], rem_size)

        if i_data is None:
            return False

        if not write_data(i_data):
            return False

        ho.update(i_data)

        w_sum += len(i_data)

    if DEBUG:
        print_positions()

    progress(w_sum, message_size, t_start)

    if action == 4:
        print(f'{ITA}I: fsyncing...{RES}')
        t0: float = monotonic()

        if not fsync_data():
            return False

        t1: float = monotonic()
        print(f'{ITA}I: fsynced in {round(t1 - t0, 1)}s{RES}')

    message_checksum: str = ho.hexdigest()

    end_pos: int = iod['o'].tell()

    if action == 4:
        print(f'{ITA}I: remember the location of the message '
              f'in the container:\n    [{start_pos}:{end_pos}]')

    print(f'{ITA}I: message checksum:\n    {message_checksum}{RES}')

    return True


def create_with_random(action: int) -> bool:
    """
    """
    md['act'] = True

    o_file, iod['o'] = get_output_file_new(action)
    print(f'{ITA}I: new file "{o_file}" has been created{RES}')

    o_size: int = get_output_file_size()
    print(f'{ITA}I: size: {string_size(o_size)}{RES}')

    ok: bool = create_with_random_handler(o_size)

    return ok


def create_with_random_handler(o_size: int) -> bool:
    """
    """
    print(f'{ITA}I: writing random data...{RES}')

    t_start: float = monotonic()
    t_last_print: float = t_start

    w_sum: int = 0

    num_chunks: int = o_size // RW_CHUNK_SIZE
    rem_size: int = o_size % RW_CHUNK_SIZE

    for _ in range(num_chunks):
        chunk: bytes = urandom(RW_CHUNK_SIZE)

        if not write_data(chunk):
            return False

        w_sum += len(chunk)

        if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
            progress(w_sum, o_size, t_start)
            t_last_print = monotonic()

    if rem_size:
        chunk = urandom(rem_size)

        if not write_data(chunk):
            return False

        w_sum += len(chunk)

    progress(w_sum, o_size, t_start)

    return True


def overwrite_with_random(action: int) -> bool:
    """
    """
    md['act'] = True

    o_file, o_size, iod['o'] = get_output_file_exist(
        i_file='', i_size=0, action=action)

    print(f'{ITA}I: path: "{o_file}"; size: {string_size(o_size)}{RES}')

    if o_size == 0:
        print(f'{ITA}I: nothing to do{RES}')
        return False

    start_pos: int = get_start_pos(
        max_start_pos=o_size,
        no_default=False
    )
    print(f'{ITA}I: start position: {start_pos}{RES}')

    if start_pos == o_size:
        print(f'{ITA}I: nothing to do{RES}')
        return False

    end_pos: int = get_end_pos(
        min_pos=start_pos,
        max_pos=o_size,
        no_default=False
    )
    print(f'{ITA}I: end position: {end_pos}{RES}')

    data_size: int = end_pos - start_pos
    print(f'{ITA}I: data size to write: {string_size(data_size)}{RES}')

    if data_size == 0:
        print(f'{ITA}I: nothing to do{RES}')
        return False

    if not proceed(var=1):
        print(f'{ITA}I: stopped by user request{RES}')
        return False

    ok: bool = overwrite_with_random_handler(start_pos, data_size)

    return ok


def overwrite_with_random_handler(start_pos: int, data_size: int) -> bool:
    """
    """
    if DEBUG:
        print_positions()

    if not seek_pos(iod['o'], start_pos):
        return False

    if DEBUG:
        print_positions()

    print(f'{ITA}I: writing random data...{RES}')

    t_start: float = monotonic()
    t_last_print: float = t_start

    w_sum: int = 0

    num_chunks: int = data_size // RW_CHUNK_SIZE
    rem_size: int = data_size % RW_CHUNK_SIZE

    for _ in range(num_chunks):
        chunk: bytes = urandom(RW_CHUNK_SIZE)

        if not write_data(chunk):
            return False

        w_sum += len(chunk)

        if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
            progress(w_sum, data_size, t_start)
            t_last_print = monotonic()

    if rem_size:
        chunk = urandom(rem_size)

        if not write_data(chunk):
            return False

        w_sum += len(chunk)

    if DEBUG:
        print_positions()

    progress(w_sum, data_size, t_start)

    print(f'{ITA}I: fsyncing...{RES}')
    t0: float = monotonic()

    if not fsync_data():
        return False

    t1: float = monotonic()
    print(f'{ITA}I: fsynced in {round(t1 - t0, 1)}s{RES}')

    return True


# Handle signals and main()
# --------------------------------------------------------------------------- #


def signal_handler(signum: Any, frame: Any) -> NoReturn:
    """
    """
    if 'act' in md:
        print(f'\n{ERR}E: caught signal {signum}{RES}')
        exit(1)
    else:
        print(f'\n{ITA}I: caught signal {signum}{RES}')
        exit()


def main() -> NoReturn:
    """
    """
    signal(SIGINT, signal_handler)

    if DEBUG:
        print(f'{WAR}W: debug messages enabled!{RES}')

    while True:
        action: int = select_action()

        ok: Optional[bool] = None

        if action == 0:
            exit()

        elif action == 1:
            print(INFO)

            print(WARNINGS)

            if DEBUG:
                print(DEBUG_INFO)

        elif action in (2, 3, 6, 7):
            ok = encrypt_and_embed(action)

        elif action in (4, 5):
            ok = embed(action)

        elif action == 8:
            ok = create_with_random(action)

        else:  # 9
            ok = overwrite_with_random(action)

        if 'i' in iod:
            close_file(iod['i'])

        if 'o' in iod:
            close_file(iod['o'])

        if action in (2, 3, 5, 7, 8):
            # Offer to remove the output file path if something went wrong
            if not ok or 'auth_fail' in md:
                remove_output()

        iod.clear()
        sd.clear()
        md.clear()

        collect()

        if ok:
            print(f'{ITA}I: action is completed{RES}')


if __name__ == '__main__':
    main()
