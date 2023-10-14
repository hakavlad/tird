#!/usr/bin/env python3
"""A tool for encrypting file contents and hiding random data
among other random data.
"""

from gc import collect
from getpass import getpass
from hashlib import blake2b, scrypt, shake_256
from os import fsync, path, urandom, walk
from signal import SIGINT, signal
from sys import argv, byteorder, exit, platform
from time import monotonic
from typing import Any, NoReturn, Optional, Union

# pylint: disable=invalid-name
# pylint: disable=pointless-string-statement
# pylint: disable=empty-docstring
# pylint: disable=broad-exception-caught
# pylint: disable=consider-using-with
# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
# pylint: disable=too-many-lines
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-statements


def open_file(f_path: str, f_mode: str) -> Any:
    """
    """
    try:
        return open(f_path, f_mode)
    except Exception as e:
        print(f'{ERR}E: {e}{END}')
        return None


def seek_pos(f: Any, offset: int, whence: int = 0) -> bool:
    """
    """
    try:
        f.seek(offset, whence)
        return True
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        return False


def read_data(size: int, f: Any) -> Optional[bytes]:
    """
    """
    try:
        data = f.read(size)
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        return None

    if len(data) < size:
        print(f'{ERR}E: the read data size is less than expected{END}')
        return None

    return data


def write_data(data: bytes) -> bool:
    """
    """
    try:
        fod['o'].write(data)
        return True
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        return False


def fsync_data() -> bool:
    """
    """
    try:
        fod['o'].flush()
        fsync(fod['o'].fileno())
        return True
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        return False


def get_mode() -> int:
    """
    """
    while True:
        mode = input(MENU)

        if mode == '0':
            print(f'{ITA}I: exit{END}')
            return 0

        if mode == '1':
            return 1

        if mode == '2':
            print(f'{ITA}I: mode: encrypt file contents{END}')
            return 2

        if mode == '3':
            print(f'{ITA}I: mode: decrypt file contents{END}')
            return 3

        if mode == '4':
            print(f'{ITA}I: mode: hide file contents (no encryption){END}')
            return 4

        if mode == '5':
            print(f'{ITA}I: mode: unhide file contents (no decryprion){END}')
            return 5

        if mode == '6':
            print(f'{ITA}I: mode: encrypt and hide file contents{END}')
            return 6

        if mode == '7':
            print(f'{ITA}I: mode: unhide and decrypt file contents{END}')
            return 7

        if mode == '8':
            print(f'{ITA}I: mode: create a file with uniform random data{END}')
            return 8

        if mode == '9':
            print(f'{ITA}I: mode: overwrite file contents with uniform '
                  f'random data{END}')
            return 9

        print(f'{ERR}E: invalid value{END}')


def is_custom() -> bool:
    """
    """
    while True:
        custom: str = input(f'{BOL}Use custom settings? (N/y):{END} ')

        if custom in ('', 'N', 'n', '0'):
            return False

        if custom in ('Y', 'y', '1'):
            return True

        print(f'{ERR}E: invalid value{END}')
        continue


def get_pad_max_percent() -> int:
    """
    """
    while True:
        pad_max_percent_s: str = input(
            f'    {BOL}Randomized padding max percent (default'
            f'={DEFAULT_PAD_MAX_PERCENT}):{END} ')

        if pad_max_percent_s in ('', str(DEFAULT_PAD_MAX_PERCENT)):
            return DEFAULT_PAD_MAX_PERCENT

        try:
            pad_max_percent: int = int(pad_max_percent_s)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if pad_max_percent < 0:
            print(f'  {ERR}E: invalid value; must be >= 0{END}')
            continue

        return pad_max_percent


def get_catpig_space_mib() -> int:
    """
    """
    while True:
        catpig_space_mib_s: str = input(
            f'    {BOL}Catpig KDF space, MiB (default'
            f'={DEFAULT_CATPIG_SPACE_MIB}): {END}')

        if catpig_space_mib_s in ('', str(DEFAULT_CATPIG_SPACE_MIB)):
            return DEFAULT_CATPIG_SPACE_MIB

        try:
            catpig_space_mib: int = int(catpig_space_mib_s)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if catpig_space_mib < 1 or catpig_space_mib > MAX_SPACE_MIB:
            print(f'  {ERR}E: invalid value; must be >= 1 and '
                  f'<= {MAX_SPACE_MIB}{END}')
            continue

        return catpig_space_mib


def get_catpig_passes() -> int:
    """
    """
    while True:
        catpig_passes_s: str = input(
            f'    {BOL}Catpig KDF passes (default'
            f'={DEFAULT_CATPIG_PASSES}): {END}')

        if catpig_passes_s in ('', str(DEFAULT_CATPIG_PASSES)):
            return DEFAULT_CATPIG_PASSES

        try:
            catpig_passes: int = int(catpig_passes_s)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if catpig_passes < 1:
            print(f'  {ERR}E: invalid value; must be >= 1{END}')
            continue

        return catpig_passes


def get_input_keys() -> list:
    """
    Get input keys (keyfiles and passphrases).
    """
    key_digest_list: list = []

    # get digests of keyfiles
    while True:
        k_file: str = input(f'{BOL}Keyfile (optional):{END} ')

        if k_file == '':
            break

        k_file = path.realpath(k_file)

        if not path.exists(k_file):
            print(f'{ERR}E: {k_file} does not exist{END}')
            print(f'{ERR}E: keyfile NOT accepted!{END}')
            continue

        if path.isdir(k_file):
            digest_list: Optional[list] = get_keyfile_digest_list(k_file)

            if digest_list is None:
                print(f'{ERR}E: keyfiles NOT accepted!{END}')
                continue

            if digest_list == []:
                print(f'{WAR}W: this is empty directory; no keyfiles '
                      f'to accept!{END}')
            else:
                key_digest_list.extend(digest_list)
                print(f'{ITA}I: keyfiles accepted!{END}')

                del k_file, digest_list
                collect()
        else:
            f_digest = get_keyfile_digest(k_file)

            if f_digest is None:
                print(f'{ERR}E: keyfile NOT accepted!{END}')
            else:
                key_digest_list.append(f_digest)
                print(f'{ITA}I: keyfile accepted!{END}')
            continue

    # get digests of passphrases
    while True:
        pp0: str = getpass(f'{BOL}Passphrase (optional):{END} ')
        if pp0 == '':
            break

        pp1: str = getpass(f'{BOL}Confirm passphrase:{END} ')

        if pp0 == pp1:
            pp: bytes = pp0.encode()

            pp_digest: bytes = get_passphrase_digest(pp)

            key_digest_list.append(pp_digest)

            del pp0, pp1, pp, pp_digest
            collect()

            print(f'{ITA}I: passphrase accepted!{END}')
        else:
            print(f'{ERR}E: passphrase confirmation failed!{END}')

            del pp0, pp1
            collect()

    return key_digest_list


def get_input_file(mode: int) -> tuple:
    """
    """
    if mode == 2:
        i: str = 'File to encrypt: '
    elif mode == 3:
        i = 'File to decrypt: '
    elif mode == 6:
        i = 'File to encrypt and hide: '
    elif mode in (7, 5):
        i = 'Container: '
    else:  # 4
        i = 'File to hide: '

    while True:
        i_file: str = input(f'{BOL}{i}{END}')

        if i_file == '':
            print(f'{ERR}E: input file is not set{END}')
            continue

        i_file = path.realpath(i_file)

        i_size: Optional[int] = get_file_size(i_file)

        if i_size is None:
            continue

        i_object: Any = open_file(i_file, 'rb')

        if i_object is None:
            continue

        break

    return i_file, i_size, i_object


def get_output_file_c(mode: int) -> tuple:
    """
    """
    if mode == 2:
        i = 'Output (encrypted) file: '
    elif mode in (3, 7):
        i = 'Output (decrypted) file: '
    else:  # 5, 8
        i = 'Output file: '

    while True:
        o_file = input(f'{BOL}{i}{END}')

        if o_file == '':
            print(f'{ERR}E: output file is not set{END}')
            continue

        o_file = path.realpath(o_file)

        if path.exists(o_file):
            print(f'{ERR}E: this file already exists{END}')
            continue

        o_object: Any = open_file(o_file, 'wb')

        if o_object is None:
            continue

        break

    return o_file, o_object


def get_output_file_w(i_file, i_size: int, mode: int) -> tuple:
    """
    """
    if mode in (6, 4):
        i: str = 'File to overwrite (container): '
    else:  # 9
        i = 'File to overwrite: '

    while True:
        o_file: str = input(f'{BOL}{i}{END}')

        if o_file == '':
            print(f'{ERR}E: output file is not set{END}')
            continue

        o_size: Optional[int] = get_file_size(o_file)

        if o_size is None:
            continue

        o_file = path.realpath(o_file)

        if o_file == i_file:
            print(f'{ERR}E: input and output files should not be at '
                  f'the same path!{END}')
            continue

        if o_size < i_size:
            print(f'{ERR}E: output file must be not smaller '
                  f'than {i_size} bytes{END}')
            continue

        o_object: Any = open_file(o_file, 'rb+')

        if o_object is None:
            continue

        break

    return o_file, o_size, o_object


def get_init_pos(max_init_pos: int, fix: bool) -> int:
    """
    fix=True for wiper()
    """
    while True:
        if fix:
            init_pos_s: str = input(
                f'{BOL}Initial position, valid values are [0; {max_init_pos}],'
                f' default=0:{END} ')
            if init_pos_s == '':
                init_pos_s = '0'
        else:
            init_pos_s = input(f'{BOL}Initial position, valid values are '
                               f'[0; {max_init_pos}]:{END} ')
            if init_pos_s == '':
                print(f'{ERR}E: initial position is not set{END}')
                continue

        try:
            init_pos = int(init_pos_s)
        except Exception:
            print(f'{ERR}E: invalid value{END}')
            continue

        if init_pos > max_init_pos or init_pos < 0:
            print(f'{ERR}E: invalid initial position{END}')
            continue

        return init_pos


def get_final_pos(min_pos: int, max_pos: int, fix: bool) -> int:
    """
    """
    while True:
        if fix:
            final_pos_s: str = input(
                f'{BOL}Final position, valid values are [{min_pos};'
                f' {max_pos}], default={max_pos}:{END} ')
            if final_pos_s == '':
                final_pos_s = str(max_pos)
        else:
            final_pos_s = input(f'{BOL}Final position, valid values are '
                                f'[{min_pos}; {max_pos}]:{END} ')

        try:
            final_pos = int(final_pos_s)
        except Exception:
            print(f'{ERR}E: invalid value{END}')
            continue

        if final_pos < min_pos or final_pos > max_pos:
            print(f'{ERR}E: invalid value{END}')
            continue

        return final_pos


def get_comments_bytes() -> bytes:
    """
    """
    comments: str = input(
        f'{BOL}Comments (optional, up to '
        f'{KS_COMMENTS_SITE_SIZE} bytes):{END} ')

    rnd_bytes: bytes = urandom(KS_COMMENTS_SITE_SIZE)

    if comments == '':
        comments_bytes: bytes = rnd_bytes
    else:
        comments_bytes = comments.encode()

        comments_bytes = b''.join([
            comments_bytes,
            INVALID_UTF8_BYTE,
            rnd_bytes
        ])[:KS_COMMENTS_SITE_SIZE]

    comments_decoded: Optional[str] = decode_comments(comments_bytes)
    print(f'{ITA}I: comments will be shown as: {[comments_decoded]}{END}')

    return comments_bytes


def is_real_mac() -> bool:
    """
    """
    while True:
        add_mac: str = input(
            f'{BOL}Add an authentication tag? (Y/n):{END} ')

        if add_mac in ('', '0', '1', 'y', 'n', 'Y', 'N'):
            break

        print(f'{ERR}E: invalid value{END}')
        continue

    if add_mac in ('', 'Y', 'y', '1'):
        return True

    return False


def get_output_file_size() -> int:
    """
    """
    while True:
        o_size_s: str = input(f'{BOL}Output file size in bytes:{END} ')

        if o_size_s == '':
            print(f'{ERR}E: output file is not set{END}')
            continue

        try:
            o_size: int = int(o_size_s)
        except Exception as e:
            print(f'{ERR}E: {e}{END}')
            continue

        if o_size < 0:
            print(f'{ERR}E: negative file size value{END}')
            continue

        return o_size


def do_continue(fix: str) -> bool:
    """
    """
    while True:
        do_cont: str = input(f'{BOL}Output file will be partially '
                             f'overwritten{fix}.'
                             f' Proceed? (y/n):{END} ')
        if do_cont in ('y', 'Y', '1'):
            return True
        if do_cont in ('n', 'N', '0'):
            return False


def print_positions() -> None:
    """
    """
    i: int = fod['i'].tell()
    o: int = fod['o'].tell()
    print(f'{ITA}D: current pointer positions: if={i}, of={o}{END}')


def print_progress(
    written_sum: int,
    data_size: int,
    t_start: float,
    fix: str
) -> None:
    """
    """
    if data_size == 0:
        print(f'{ITA}I: written 0 bytes{END}')
        return

    t = monotonic() - t_start

    if t > 0:
        print(
            f'{ITA}I: written{fix} {written_sum} bytes'
            f', {round(written_sum / M, 1)} MiB'
            f', {round(written_sum / data_size * 100, 1)}% in'
            f' {round(t, 1)}s, avg {round(written_sum / M / t, 1)} MiB/s{END}')
    else:
        print(f'{ITA}I: written{fix} {written_sum} bytes'
              f', {round(written_sum / M, 1)} MiB'
              f', {round(written_sum / data_size * 100, 1)}% in'
              f' {round(t, 1)}s{END}')


def xor(a: bytes, b: bytes) -> bytes:
    """
    """
    length: int = min(len(a), len(b))
    a_int: int = int.from_bytes(a[:length], byteorder=byteorder)
    b_int: int = int.from_bytes(b[:length], byteorder=byteorder)
    c_int: int = a_int ^ b_int
    c: bytes = c_int.to_bytes(length, byteorder=byteorder)
    return c


def shake_256_digest(data: bytes, size: int) -> bytes:
    """
    """
    ho: Any = shake_256()
    ho.update(data)
    return ho.digest(size)


def blake2b_digest(
    data: bytes,
    person: bytes = b'',
    salt: bytes = b''
) -> bytes:
    """
    """
    ho: Any = blake2b(
        digest_size=BLAKE_DIGEST_SIZE,
        person=person,
        salt=salt
    )

    ho.update(data)

    return ho.digest()


def blake2b_file_digest(
    f_object: Any,
    f_size: int,
    person: bytes = b'',
    salt: bytes = b''
) -> Optional[bytes]:
    """
    """
    ho: Any = blake2b(digest_size=BLAKE_DIGEST_SIZE, person=person, salt=salt)

    n: int = f_size // RW_CHUNK_SIZE
    r: int = f_size % RW_CHUNK_SIZE

    for _ in range(n):
        data: Optional[bytes] = read_data(RW_CHUNK_SIZE, f_object)

        if data is None:
            return None

        ho.update(data)

    data = read_data(r, f_object)

    if data is None:
        return None

    ho.update(data)

    return ho.digest()


def get_keyfile_digest(f_path: str) -> Optional[bytes]:
    """
    """
    f_size: Optional[int] = get_file_size(f_path)

    if f_size is None:
        return None

    print(f'{ITA}I: keyfile size: {f_size} bytes, real path: "{f_path}"{END}')
    print(f'{ITA}I: hashing the keyfile...{END}')

    f: Any = open_file(f_path, 'rb')

    if f is None:
        return None

    salt_keys: bytes = sd['keys']

    f_digest: Optional[bytes] = blake2b_file_digest(
        f,
        f_size,
        person=BLAKE_PERSON_KEYFILE,
        salt=salt_keys
    )

    f.close()

    if f_digest is None:
        return None

    if DEBUG:
        print(f'{ITA}D: digest: {f_digest.hex()}{END}')

    return f_digest


def get_keyfile_digest_list(d_path: str) -> Optional[list]:
    """
    """
    f_tuple_list: list = []

    size_sum: int = 0

    print(f'{ITA}I: scanning the directory "{d_path}"{END}')

    for root, _, files in walk(d_path):
        for fp in files:
            f_path: str = path.join(root, fp)

            if DEBUG:
                print(f'{ITA}D: getting the size of "{f_path}"{END}')

            f_size: Optional[int] = get_file_size(f_path)

            if f_size is None:
                return None

            if DEBUG:
                print(f'{ITA}D: size: {f_size} bytes{END}')

            size_sum += f_size

            f_tuple: tuple = (f_path, f_size)

            f_tuple_list.append(f_tuple)

    f_tuple_list_len: int = len(f_tuple_list)

    print(f'{ITA}I: found {f_tuple_list_len} files, total '
          f'size: {size_sum} bytes{END}')

    if f_tuple_list_len == 0:
        return []

    print(f'{ITA}I: hashing files in the directory "{d_path}"{END}')

    salt_keys: bytes = sd['keys']

    digest_list: list = []

    for f_tuple in f_tuple_list:

        f_path, f_size = f_tuple

        if DEBUG:
            print(f'{ITA}D: hashing "{f_path}"{END}')

        f = open_file(f_path, 'rb')

        if f is None:
            return None

        f_digest = blake2b_file_digest(
            f,
            f_size,
            person=BLAKE_PERSON_KEYFILE,
            salt=salt_keys
        )

        f.close()

        if f_digest is None:
            return None

        if DEBUG:
            print(f'{ITA}D: digest: {f_digest.hex()}{END}')

        digest_list.append(f_digest)

    return digest_list


def get_passphrase_digest(pp: bytes) -> bytes:
    """
    """
    salt_keys: bytes = sd['keys']

    pp_digest: bytes = blake2b_digest(
        pp,
        person=BLAKE_PERSON_PASSPHRASE,
        salt=salt_keys
    )

    if DEBUG:
        print(f'{ITA}D: passphrase length: {len(pp)} bytes{END}')
        print(f'{ITA}D: passphrase digest: {pp_digest.hex()}{END}')

    return pp_digest


def get_key_for_kdf() -> bytes:
    """
    """
    digest_list: list = get_input_keys()

    collect()

    print(f'{ITA}I: getting user keys completed{END}')

    if not digest_list:
        print(f'{WAR}W: no passphrase or keyfile specified!{END}')

    if DEBUG:
        print(f'{ITA}D: getting user input completed{END}')
        print_positions()

    digest_list.sort()

    if DEBUG:
        print(f'{ITA}D: sorted digests of key units:{END}')
        for digest in digest_list:
            print(f'{ITA}  - {digest.hex()}{END}')

    salt_keys: bytes = sd['keys']

    ho: Any = blake2b(
        digest_size=BLAKE_DIGEST_SIZE,
        salt=salt_keys
    )

    for digest in digest_list:
        ho.update(digest)

    key: bytes = ho.digest()

    if DEBUG:
        print(f'{ITA}D: key for catpig function:\n    {key.hex()}{END}')

    return key


def get_salts(i_size: int, final_pos: int, mode: int) -> bool:
    """
    """
    if mode in (2, 6):  # encryption
        sd['keys'] = urandom(ONE_SALT_SIZE)
        sd['catpig'] = urandom(ONE_SALT_SIZE)
        sd['scrypt'] = urandom(ONE_SALT_SIZE)

        if DEBUG:
            print(f'{ITA}D: the salts has been created{END}')
    else:
        # decryption, mode 3 and 7
        # read the salts from the beginning and the end of the cryptoblob

        salt_header: Optional[bytes] = read_data(SALTS_HALF_SIZE, fod['i'])

        if salt_header is None:
            return False

        if DEBUG:
            print(f'{ITA}D: salt_header has been read{END}')
            print_positions()

        cur_pos: int = fod['i'].tell()

        if mode == 3:
            new_pos: int = i_size - SALTS_HALF_SIZE
        else:
            new_pos = final_pos - SALTS_HALF_SIZE

        # jump to the beginning of salt_footer
        if not seek_pos(fod['i'], new_pos):
            return False

        if DEBUG:
            print(f'{ITA}D: we are in position before salt_footer{END}')
            print_positions()

        salt_footer: Optional[bytes] = read_data(SALTS_HALF_SIZE, fod['i'])

        if salt_footer is None:
            return False

        if DEBUG:
            print(f'{ITA}D: salt_footer has been read{END}')
            print_positions()

        # return to the previously saved position
        if not seek_pos(fod['i'], cur_pos):
            return False

        if DEBUG:
            print(f'{ITA}D: we returned to the position after '
                  f'salt_footer{END}')
            print_positions()

        sd['keys'] = b''.join([
            salt_header[:ONE_SALT_HALF_SIZE],
            salt_footer[:ONE_SALT_HALF_SIZE]
        ])

        sd['catpig'] = b''.join([
            salt_header[ONE_SALT_HALF_SIZE:ONE_SALT_HALF_SIZE * 2],
            salt_footer[ONE_SALT_HALF_SIZE:ONE_SALT_HALF_SIZE * 2]
        ])

        sd['scrypt'] = b''.join([
            salt_header[-ONE_SALT_HALF_SIZE:],
            salt_footer[-ONE_SALT_HALF_SIZE:]
        ])

        if DEBUG:
            print(f'{ITA}D: getting salts completed{END}')

    return True


def get_salts_header_footer() -> None:
    """
    """
    sd['salt_header'] = b''.join([
        sd['keys'][:ONE_SALT_HALF_SIZE],
        sd['catpig'][:ONE_SALT_HALF_SIZE],
        sd['scrypt'][:ONE_SALT_HALF_SIZE]
    ])

    sd['salt_footer'] = b''.join([
        sd['keys'][-ONE_SALT_HALF_SIZE:],
        sd['catpig'][-ONE_SALT_HALF_SIZE:],
        sd['scrypt'][-ONE_SALT_HALF_SIZE:]
    ])


def catpig(
    password: bytes,
    salt: bytes,
    space_mib: int,
    passes: int
) -> bytes:
    """Memory-hard password-hashing function.
    """
    if space_mib < 1 or space_mib > MAX_SPACE_MIB:
        raise ValueError('Invalid space_mib value')

    if passes < 1:
        raise ValueError('Invalid passes value')

    space_size: int = space_mib * M
    num_read_blocks: int = NUM_READ_BLOCKS_IN_MIB * space_mib * passes
    half_num_read_blocks: int = num_read_blocks // 2 - 1

    ho_blake = blake2b()
    ho_blake.update(password)
    key64: bytes = ho_blake.digest()

    ho_blake = blake2b()
    ho_blake.update(salt)
    salt64: bytes = ho_blake.digest()

    ho_passes = blake2b()
    ho_passes.update(key64)
    ho_passes.update(salt64)

    ho_space = shake_256()
    ho_space.update(key64)
    ho_space.update(salt64)

    ho_mem_access_pattern = shake_256()
    ho_mem_access_pattern.update(salt64)

    num_space_blocks: int = space_size // MAX_SPACE_BLOCK_SIZE
    rem_space_size: int = space_size % MAX_SPACE_BLOCK_SIZE

    space_block_list: list = []

    for _ in range(num_space_blocks):
        space_block: bytes = ho_space.digest(MAX_SPACE_BLOCK_SIZE)
        space_block_list.append(space_block)
        ho_space.update(space_block[-SHAKE_SIZE:])

    if rem_space_size > 0:
        space_block = ho_space.digest(rem_space_size)
        space_block_list.append(space_block)

    for i in range(num_read_blocks):
        rnd_block: bytes = ho_mem_access_pattern.digest(RND_BLOCK_SIZE)
        rnd_block_read_pos: int = 0

        for _ in range(NUM_CHUNKS_IN_READ_BLOCK):
            rnd_chunk: bytes = rnd_block[rnd_block_read_pos:
                                         rnd_block_read_pos + RND_CHUNK_SIZE]
            int_rnd_chunk: int = int.from_bytes(rnd_chunk, byteorder=BYTEORDER)
            rnd_offset: int = int_rnd_chunk % space_size

            cur_block_num: int = rnd_offset // MAX_SPACE_BLOCK_SIZE
            cur_block_rnd_offset: int = rnd_offset % MAX_SPACE_BLOCK_SIZE
            cur_block_size: int = len(space_block_list[cur_block_num])

            if cur_block_size - cur_block_rnd_offset >= READ_CHUNK_SIZE:
                read_chunk: bytes = space_block_list[cur_block_num][
                    cur_block_rnd_offset:
                    cur_block_rnd_offset + READ_CHUNK_SIZE]
            else:
                if space_size - rnd_offset < READ_CHUNK_SIZE:
                    cur_block_num2: int = 0
                else:
                    cur_block_num2 = cur_block_num + 1

                read_size1: int = cur_block_size - cur_block_rnd_offset
                read_size2: int = READ_CHUNK_SIZE - read_size1

                read_chunk = b''.join([
                    space_block_list[cur_block_num][-read_size1:],
                    space_block_list[cur_block_num2][:read_size2]
                ])

            ho_passes.update(read_chunk)
            rnd_block_read_pos += RND_CHUNK_SIZE

        ho_mem_access_pattern.update(rnd_block[-SHAKE_SIZE:])

        if i >= half_num_read_blocks:
            passes_intermediate_digest = ho_passes.digest()
            ho_mem_access_pattern.update(passes_intermediate_digest)

    derived_key: bytes = ho_passes.digest()

    return derived_key


def kdfs(key: bytes) -> bytes:
    """
    """
    print(f'{ITA}I: deriving keys...{END}')

    t0 = monotonic()

    salt_catpig: bytes = sd['catpig']
    space_mib: int = cd['catpig_space_mib']
    passes: int = cd['catpig_passes']

    catpig_digest: bytes = catpig(key, salt=salt_catpig, space_mib=space_mib,
                                  passes=passes)

    if DEBUG:
        print(f'{ITA}D: catpig key: {key.hex()}{END}')
        print(f'{ITA}D: catpig salt: {salt_catpig.hex()}{END}')
        print(f'{ITA}D: catpig space, MiB: {space_mib}{END}')
        print(f'{ITA}D: catpig passes: {passes}{END}')
        print(f'{ITA}D: catpig digest: {catpig_digest.hex()}{END}')

    del key
    collect()

    t1 = monotonic()

    salt_scrypt: bytes = sd['scrypt']

    scrypt_dk: bytes = scrypt(catpig_digest, salt=salt_scrypt, n=SCRYPT_N,
                              r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM,
                              dklen=SCRYPT_DKLEN)

    if DEBUG:
        print(f'{ITA}D: scrypt key: {catpig_digest.hex()}{END}')
        print(f'{ITA}D: scrypt salt: {salt_scrypt.hex()}{END}')
        print(f'{ITA}D: scrypt dk: {scrypt_dk.hex()}{END}')

    del catpig_digest
    collect()

    t2 = monotonic()

    t_catpig, t_scrypt = t1 - t0, t2 - t1
    t = t_catpig + t_scrypt

    print(f'{ITA}I: keys derived in {round(t, 1)}s (catpig: '
          f'{round(t_catpig, 1)}s, scrypt: {round(t_scrypt, 1)}s){END}')

    return scrypt_dk


def get_ks_block(data: bytes) -> bytes:
    """
    Update SHAKE256 hash object with data and get a digest (keystream block).
    """
    cd['shake_ho'].update(data)

    ks_block: bytes = cd['shake_ho'].digest(KS_BLOCK_SIZE)

    return ks_block


def use_custom_settings(mode: int) -> None:
    """
    """
    custom: bool = is_custom()

    print(f'{ITA}I: use custom settings: {custom}{END}')

    if custom:
        if mode in (2, 6):
            print(f'{WAR}W: decryption will require the same custom '
                  f'values!{END}')

        cd['pad_max_percent'] = get_pad_max_percent()
        cd['catpig_space_mib'] = get_catpig_space_mib()
        cd['catpig_passes'] = get_catpig_passes()
    else:
        cd['pad_max_percent'] = DEFAULT_PAD_MAX_PERCENT
        cd['catpig_space_mib'] = DEFAULT_CATPIG_SPACE_MIB
        cd['catpig_passes'] = DEFAULT_CATPIG_PASSES


def get_file_size(f_path: str) -> Optional[int]:
    """
    """
    try:
        with open(f_path, 'rb') as f:
            return f.seek(0, 2)
    except Exception as e:
        print(f'{ERR}E: {e}{END}')
        return None


def decode_comments(comments_bytes: bytes) -> Optional[str]:
    """
    """
    comments_bytes_part: bytes = comments_bytes.partition(INVALID_UTF8_BYTE)[0]

    try:
        return comments_bytes_part.decode('utf-8')
    except UnicodeDecodeError:
        return None


def get_pad_from_msg(
    msg_size: int,
    rnd_bytes: bytes,
    max_pad_percent: int
) -> int:
    """
    """
    int_rnd_bytes: int = int.from_bytes(rnd_bytes, byteorder=BYTEORDER)

    rnd_max_variability: int = int(256 ** len(rnd_bytes))

    pad_size: int = int_rnd_bytes * msg_size * \
        max_pad_percent // (rnd_max_variability * 100)

    return pad_size


def get_pad_from_pmsg(
    pmsg_size: int,
    rnd_bytes: bytes,
    max_pad_percent: int
) -> int:
    """
    """
    int_rnd_bytes: int = int.from_bytes(rnd_bytes, byteorder=BYTEORDER)

    rnd_max_variability: int = int(256 ** len(rnd_bytes))

    pad_size: int = pmsg_size * int_rnd_bytes * max_pad_percent // (
        int_rnd_bytes * max_pad_percent + rnd_max_variability * 100)

    return pad_size


def get_header_footer_pad(pad_size: int, rnd_bytes: bytes) -> tuple:
    """
    """
    int_rnd_bytes: int = int.from_bytes(rnd_bytes, byteorder=BYTEORDER)

    header_pad: int = int_rnd_bytes % (pad_size + 1)
    footer_pad: int = pad_size - header_pad

    return header_pad, footer_pad


def hider_processor(mode: int, init_pos: int, data_size: int) -> bool:
    """
    """
    if mode == 4:
        if not seek_pos(fod['o'], init_pos):
            return False

        not_fsync_sum: int = 0
    else:
        if not seek_pos(fod['i'], init_pos):
            return False

    ho: Any = blake2b(digest_size=HIDER_DIGEST_SIZE)

    t_start = monotonic()
    t_last_print = t_start

    w_sum: int = 0

    num_chunks: int = data_size // RW_CHUNK_SIZE
    rem_size: int = data_size % RW_CHUNK_SIZE

    for _ in range(num_chunks):
        i_data: Optional[bytes] = read_data(RW_CHUNK_SIZE, fod['i'])
        if i_data is None:
            return False

        if not write_data(i_data):
            return False

        ho.update(i_data)

        w_len: int = len(i_data)
        w_sum += w_len

        if mode == 4:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:
                if not fsync_data():
                    return False

                not_fsync_sum = 0
                if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                    print_progress(w_sum, data_size, t_start, fix='/fsynced')
                    t_last_print = monotonic()
        else:
            if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, data_size, t_start, fix='')
                t_last_print = monotonic()

    i_data = read_data(rem_size, fod['i'])

    if i_data is None:
        return False

    if not write_data(i_data):
        return False

    ho.update(i_data)

    w_len = len(i_data)
    w_sum += w_len

    if mode == 4:
        if not fsync_data():
            return False

        print_progress(w_sum, data_size, t_start, fix='/fsynced')
    else:
        print_progress(w_sum, data_size, t_start, fix='')

    message_checksum = ho.hexdigest()

    final_pos = fod['o'].tell()

    if mode == 4:
        print(f'{ITA}Remember the following values to retrieve '
              f'the message correctly:')
        print(f'    Initial position: {init_pos}')
        print(f'    Final position: {final_pos}')
        print(f'    Message checksum: {message_checksum}{END}')
    else:
        print(f'{ITA}I: message checksum: {message_checksum}{END}')

    return True


def wiper_processor(init_pos: int, data_size: int) -> bool:
    """
    """
    if not seek_pos(fod['o'], init_pos):
        return False

    num_chunks: int = data_size // RW_CHUNK_SIZE
    rem_size: int = data_size % RW_CHUNK_SIZE

    print(f'{ITA}I: writing/fsyncing...{END}')

    fix: str = '/fsynced'

    w_sum: int = 0
    not_fsync_sum: int = 0

    t_start = monotonic()
    t_last_print = t_start

    for _ in range(num_chunks):
        chunk: bytes = urandom(RW_CHUNK_SIZE)

        if not write_data(chunk):
            return False

        w_len: int = len(chunk)
        w_sum += w_len
        not_fsync_sum += w_len

        if not_fsync_sum >= MIN_FSYNC_SIZE:

            if not fsync_data():
                return False

            not_fsync_sum = 0

            if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, data_size, t_start, fix=fix)
                t_last_print = monotonic()

    chunk = urandom(rem_size)

    if not write_data(chunk):
        return False

    w_len = len(chunk)
    w_sum += w_len

    if not fsync_data():
        return False

    print_progress(w_sum, data_size, t_start, fix=fix)

    return True


def cryptohider(mode: int) -> bool:
    """
    """
    comments_bytes: Optional[bytes] = None
    message_size: Optional[int] = None
    init_pos: Optional[int] = None
    final_pos: Optional[int] = None

    use_custom_settings(mode)

    i_file, i_size, fod['i'] = get_input_file(mode)
    print(f'{ITA}I: input file real path (in quotes):\n    "{i_file}"{END}')

    print(f'{ITA}I: input file size: {i_size} '
          f'bytes, {round(i_size / M, 1)} MiB{END}')

    if mode in (2, 6):
        message_size = i_size + KS_COMMENTS_SITE_SIZE
        min_cryptoblob_size: int = SALTS_SIZE + message_size + MAC_TAG_SIZE
        max_pad: int = message_size * cd['pad_max_percent'] // 100 - 1
        max_pad = max(0, max_pad)
        max_cryptoblob_size: int = max_pad + min_cryptoblob_size

        if DEBUG:
            print(f'{ITA}D: message_size: {message_size}')
            print(f'D: min_cryptoblob_size: {min_cryptoblob_size}')
            print(f'D: max_pad: {max_pad}')
            print(f'D: max_cryptoblob_size: {max_cryptoblob_size}{END}')

    if mode in (3, 7):
        if i_size < MIN_VALID_CRYPTOBLOB_SIZE:
            if mode == 3:
                print(f'{ERR}E: input file is too small (min valid '
                      f'cryptoblob size is {MIN_VALID_CRYPTOBLOB_SIZE} '
                      f'bytes){END}')
            else:  # 7
                print(f'{ERR}E: inporrect initial/final positions (min '
                      f'valid cryptoblob size is '
                      f'{MIN_VALID_CRYPTOBLOB_SIZE} '
                      f'bytes){END}')
            return False

    if mode in (2, 3):
        o_file, fod['o'] = get_output_file_c(mode)

    elif mode == 6:
        o_file, o_size, fod['o'] = get_output_file_w(
            i_file, max_cryptoblob_size, mode)

        max_init_pos: int = o_size - max_cryptoblob_size

    else:  # 7
        o_file, fod['o'] = get_output_file_c(mode)

        max_init_pos = i_size - MIN_VALID_CRYPTOBLOB_SIZE

    print(f'{ITA}I: output file real path (in quotes):\n    "{o_file}"{END}')

    if mode == 6:
        print(f'{ITA}I: output file size: {o_size} '
              f'bytes, {round(o_size / M, 1)} MiB{END}')

    if mode in (6, 7):
        init_pos = get_init_pos(max_init_pos, fix=False)

        print(f'{ITA}I: initial position: {init_pos}{END}')

    if mode == 7:
        final_pos = get_final_pos(
            min_pos=init_pos + MIN_VALID_CRYPTOBLOB_SIZE,
            max_pos=i_size,
            fix=False
        )

        print(f'{ITA}I: final position: {final_pos}{END}')

    if mode in (2, 6):
        comments_bytes = get_comments_bytes()

    if mode in (2, 6):
        add_real_mac: bool = is_real_mac()
        print(f'{ITA}I: add an authentication tag: {add_real_mac}{END}')
    else:  # 3, 5
        add_real_mac = True

    if mode == 6:
        if not seek_pos(fod['o'], init_pos):
            return False
    if mode == 7:
        if not seek_pos(fod['i'], init_pos):
            return False
    if mode in (6, 7):
        if DEBUG:
            print(f'{ITA}D: pointers set to initial positions{END}')
            print_positions()

    if DEBUG:
        print(f'{ITA}D: salts processing...{END}')

    if not get_salts(i_size, final_pos, mode):
        return False

    if DEBUG:
        salt_keys_s: str = sd['keys'].hex()
        salt_catpig_s: str = sd['catpig'].hex()
        salt_scrypt_s: str = sd['scrypt'].hex()
        print(f'{ITA}D: salt for hashing input keys:\n    {salt_keys_s}{END}')
        print(f'{ITA}D: salt for catpig KDF:\n    {salt_catpig_s}{END}')
        print(f'{ITA}D: salt for scrypt KDF:\n    {salt_scrypt_s}{END}')

    get_salts_header_footer()

    key_for_kdf: bytes = get_key_for_kdf()

    collect()

    if mode == 6:
        if not do_continue(fix=' with cryptoblob'):
            print(f'{ITA}I: stopped by user request{END}')
            return False

    return cryptohider_processor(
        mode,
        i_size,
        init_pos,
        final_pos,
        message_size,
        comments_bytes,
        add_real_mac,
        key_for_kdf
    )


def write_pad(
    pad_size: int,
    mode: int,
    w_sum: int,
    not_fsync_sum: int,
    t_start: float,
    t_last_print: float,
    output_data_size: int
) -> Optional[tuple]:
    """
    """
    if mode in (2, 6):
        pad_num_chunks: int = pad_size // RW_CHUNK_SIZE
        pad_rem_size: int = pad_size % RW_CHUNK_SIZE

        for _ in range(pad_num_chunks):
            chunk: bytes = urandom(RW_CHUNK_SIZE)
            if not write_data(chunk):
                return None

            w_len = len(chunk)
            w_sum += w_len

            if mode == 6:
                not_fsync_sum += w_len
                if not_fsync_sum >= MIN_FSYNC_SIZE:
                    if not fsync_data():
                        return None

                    not_fsync_sum = 0
                    if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                        print_progress(
                            w_sum, output_data_size, t_start, fix='/fsynced')
                        t_last_print = monotonic()
            else:
                if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                    print_progress(
                        w_sum, output_data_size, t_start, fix='')
                    t_last_print = monotonic()

        chunk = urandom(pad_rem_size)

        if not write_data(chunk):
            return None

        w_len = len(chunk)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:
                if not fsync_data():
                    return None

                not_fsync_sum = 0
                if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                    print_progress(
                        w_sum, output_data_size, t_start, fix='/fsynced')
                    t_last_print = monotonic()
        else:
            if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, output_data_size, t_start, fix='')
                t_last_print = monotonic()

    else:  # 3, 5
        if not seek_pos(fod['i'], pad_size, 1):
            return None

    return w_sum, not_fsync_sum, t_last_print


def cryptohider_processor(
    mode: int,
    i_size: int,
    init_pos: Optional[int],
    final_pos: Optional[int],
    message_size: Optional[int],
    comments_bytes: Optional[bytes],
    add_real_mac: bool,
    key_for_kdf: bytes
) -> bool:
    """
    """
    dk: bytes = kdfs(key_for_kdf)

    del key_for_kdf
    collect()

    dek: bytes = dk[:DEK_SIZE]
    mac_key: bytes = dk[DEK_SIZE:DEK_SIZE + MAC_KEY_SIZE]
    pad_key: bytes = dk[-PAD_KEY_SIZE:]

    if DEBUG:
        print(f'{ITA}D: dk:\n    {dk.hex()}{END}')
        print(f'{ITA}D: dek:\n    {dek.hex()}{END}')
        print(f'{ITA}D: mac_key:\n    {mac_key.hex()}{END}')
        print(f'{ITA}D: pad_key:\n    {pad_key.hex()}{END}')

    cd['shake_ho'] = shake_256()

    mac_ho: Any = blake2b(
        digest_size=MAC_TAG_SIZE,
        key=mac_key,
    )

    pad_key1: bytes = pad_key[:PAD_KEY_SIZE // 2]
    pad_key2: bytes = pad_key[-PAD_KEY_SIZE // 2:]

    if mode in (2, 6):
        pad: int = get_pad_from_msg(
            message_size,
            pad_key1,
            cd['pad_max_percent']
        )
    else:  # 3, 7
        if mode == 3:
            pmsg_size: int = i_size - SALTS_SIZE - MAC_TAG_SIZE
        else:  # 7
            pmsg_size = final_pos - init_pos - SALTS_SIZE - MAC_TAG_SIZE

        pad = get_pad_from_pmsg(
            pmsg_size,
            pad_key1,
            cd['pad_max_percent']
        )

    pad_header_size, pad_footer_size = get_header_footer_pad(pad, pad_key2)

    if DEBUG:
        print(f'{ITA}D: pad_header_size: {pad_header_size}{END}')
        print(f'{ITA}D: pad_footer_size: {pad_footer_size}{END}')

    if mode in (2, 6):
        contents_size: int = i_size
    elif mode == 3:
        contents_size = (i_size - SALTS_SIZE - pad -
                         KS_COMMENTS_SITE_SIZE - MAC_TAG_SIZE)
    else:  # 7
        contents_size = (final_pos - init_pos - SALTS_SIZE - pad -
                         KS_COMMENTS_SITE_SIZE - MAC_TAG_SIZE)

    if DEBUG:
        print(f'{ITA}D: contents size: {contents_size}{END}')

    if contents_size < 0:
        print(f'{ERR}E: invalid input values combination '
              f'(incorrect input file size, max padding, keys){END}')
        return False

    if mode in (2, 6):
        output_data_size: int = (SALTS_SIZE + pad + contents_size +
                                 KS_COMMENTS_SITE_SIZE + MAC_TAG_SIZE)
    else:  # 3, 7
        output_data_size = contents_size

    if DEBUG:
        print(f'{ITA}D: output data size: {output_data_size}{END}')

    t_start: float = monotonic()

    t_last_print: float = t_start

    w_sum: int = 0

    not_fsync_sum: Optional[int] = None

    if mode == 6:
        not_fsync_sum = 0

    salt_header: bytes = sd['salt_header']
    salt_footer: bytes = sd['salt_footer']

    if DEBUG:
        print(f'{ITA}D: salt header:\n    {salt_header.hex()}{END}')
        print(f'{ITA}D: salt footer:\n    {salt_footer.hex()}{END}')

    mac_ho.update(salt_header)
    mac_ho.update(salt_footer)

    if mode in (2, 6):
        if DEBUG:
            print(f'{ITA}D: writing salt_header...{END}')

        if not write_data(salt_header):
            return False

        w_len: int = len(salt_header)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len

        if DEBUG:
            print(f'{ITA}D: salt_header is written{END}')
            print_positions()

    rnd_pad_pos0: int = fod['o'].tell()

    wp_res: Optional[tuple] = write_pad(
        pad_header_size, mode, w_sum, not_fsync_sum,
        t_start, t_last_print, output_data_size)

    if wp_res is None:
        return False

    w_sum, not_fsync_sum, t_last_print = wp_res

    rnd_pad_pos1: int = fod['o'].tell()

    if DEBUG:
        print(f'{ITA}D: randomized padding header has been handled{END}')
        print_positions()

    if DEBUG:
        print(f'{ITA}D: handling input file contents...{END}')

    num_blocks = contents_size // KS_CONTENTS_SITE_SIZE
    rem_size = contents_size % KS_CONTENTS_SITE_SIZE

    ks_footer_site = dek

    ks_block_counter: int = 0

    for _ in range(num_blocks):

        input_block: Optional[bytes] = read_data(
            KS_CONTENTS_SITE_SIZE, fod['i'])

        if input_block is None:
            return False

        ks_block = get_ks_block(ks_footer_site)
        ks_block_counter += 1

        ks_footer_site = ks_block[-KS_FOOTER_SITE_SIZE:]

        output_block: bytes = xor(
            input_block,
            ks_block[:KS_CONTENTS_SITE_SIZE]
        )

        if not write_data(output_block):
            return False

        w_len = len(output_block)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:
                if not fsync_data():
                    return False

                not_fsync_sum = 0
                if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                    print_progress(
                        w_sum, output_data_size, t_start, fix='/fsynced')
                    t_last_print = monotonic()
        else:
            if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, output_data_size, t_start, fix='')
                t_last_print = monotonic()

        if DEBUG:
            print(f'{ITA}D: contents block has been written; its '
                  f'size: { len(output_block)}{END}')
            print_positions()

        if mode in (2, 6):
            mac_ho.update(output_block)
        else:  # 3, 7
            mac_ho.update(input_block)

    if rem_size:
        input_block = read_data(rem_size, fod['i'])

        if input_block is None:
            return False

        ks_block = get_ks_block(ks_footer_site)
        ks_block_counter += 1

        output_block = xor(input_block, ks_block[:rem_size])

        if not write_data(output_block):
            return False

        w_len = len(output_block)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:
                if not fsync_data():
                    return False

                not_fsync_sum = 0
                if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                    print_progress(
                        w_sum, output_data_size, t_start, fix='/fsynced')
                    t_last_print = monotonic()
        else:
            if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, output_data_size, t_start, fix='')
                t_last_print = monotonic()

        if DEBUG:
            print(f'{ITA}D: contents block has been written; its '
                  f'size: {len(output_block)}{END}')
            print_positions()

        if mode in (2, 6):
            mac_ho.update(output_block)
        else:  # 3, 7
            mac_ho.update(input_block)

    if DEBUG:
        print(f'{ITA}D: total ks_block_counter'
              f': {ks_block_counter}{END}')
        print(f'{ITA}D: file contents has been handled{END}')

    if DEBUG:
        print(f'{ITA}D: handling comments...{END}')

    if mode in (3, 7):
        comments_bytes = read_data(KS_COMMENTS_SITE_SIZE, fod['i'])

        if comments_bytes is None:
            return False

    ks_comments_site: bytes = ks_block[
        KS_COMMENTS_SITE_START_POS:KS_COMMENTS_SITE_FIN_POS
    ]

    comments_bytes_out: bytes = xor(comments_bytes, ks_comments_site)

    if DEBUG:
        print(f'{ITA}D: comments (binary) found in plain and '
              f'encrypted forms{END}')

    if mode in (2, 6):
        if not write_data(comments_bytes_out):
            return False

        w_len = len(comments_bytes_out)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len

        if DEBUG:
            print(f'{ITA}D: encrypted comments written; '
                  f'its size: {len(comments_bytes_out)}{END}')
    else:  # 3, 5
        comments: Optional[str] = decode_comments(comments_bytes_out)

        print(f'{ITA}I: comments (may be not genuine): {[comments]}{END}')

    if mode in (2, 6):
        mac_ho.update(comments_bytes_out)
    else:  # 3, 7
        mac_ho.update(comments_bytes)

    if DEBUG:
        print(f'{ITA}D: comments have been handled{END}')
        print_positions()

    if DEBUG:
        print(f'{ITA}D: handling MAC...{END}')

    found_mac: bytes = mac_ho.digest()

    if DEBUG:
        print(f'{ITA}D: found MAC (keyed digest of salts and encrypted '
              f'message): {found_mac.hex()}{END}')

    if mode in (2, 6):
        fake_mac: bytes = urandom(MAC_TAG_SIZE)
        if DEBUG:
            print(f'{ITA}D: fake MAC: {fake_mac.hex()}{END}')

    ks_mac_site: bytes = ks_block[KS_MAC_SITE_START_POS:KS_MAC_SITE_FIN_POS]

    if DEBUG:
        print(f'{ITA}D: ks_mac_site (ks for encrypting/decrypting '
              f'MAC): {ks_mac_site.hex()}{END}')

    if mode in (2, 6) and not add_real_mac:
        encrypted_mac: bytes = xor(fake_mac, ks_mac_site)
    else:
        encrypted_mac = xor(found_mac, ks_mac_site)

    if DEBUG:
        print(f'{ITA}D: encrypted MAC: {encrypted_mac.hex()}{END}')

    if mode in (2, 6):
        if not write_data(encrypted_mac):
            return False

        w_len = len(encrypted_mac)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len

        if DEBUG:
            print(f'{ITA}D: encrypted MAC has been written; '
                  f'its size: {len(encrypted_mac)}{END}')

    else:  # 3, 7
        read_mac: Optional[bytes] = read_data(MAC_TAG_SIZE, fod['i'])

        if read_mac is None:
            return False

        if DEBUG:
            print(f'D: read MAC: {read_mac.hex()}')

        if encrypted_mac == read_mac:
            print(f'{ITA}I: data/keys authentication: OK{END}')
        else:
            print(f'{WAR}W: data/keys authentication failed!{END}')

    if DEBUG:
        print(f'{ITA}D: MAC has been handled{END}')
        print_positions()

    if DEBUG:
        print(f'{ITA}D: handling randomized padding footer{END}')

    rnd_pad_pos2: int = fod['o'].tell()

    wp_res = write_pad(pad_footer_size, mode, w_sum, not_fsync_sum,
                       t_start, t_last_print, output_data_size)

    if wp_res is None:
        return False

    w_sum, not_fsync_sum, t_last_print = wp_res

    rnd_pad_pos3: int = fod['o'].tell()

    if DEBUG:
        print(f'{ITA}D: randomized padding footer has been handled{END}')
        print_positions()

    if mode in (2, 6):
        if DEBUG:
            print(f'{ITA}D: writing salt_footer...{END}')

        if not write_data(salt_footer):
            return False

        w_len = len(salt_footer)
        w_sum += w_len

        if mode == 6:
            if not fsync_data():
                return False

            print_progress(w_sum, output_data_size, t_start, fix='/fsynced')
        else:
            print_progress(w_sum, output_data_size, t_start, fix='')

        if DEBUG:
            print(f'{ITA}D: salt_footer is written{END}')
            print_positions()

    if mode == 6:
        final_pos = fod['o'].tell()
        print(f'{ITA}Remember the positions of the cryptoblob in the '
              f'container:{END}')
        print(f'    {ITA}Initial/Final:  {init_pos}/{final_pos}{END}')

    if mode in (3, 7):
        print_progress(w_sum, output_data_size, t_start, fix='')

    if DEBUG:
        print(f'{ITA}D: expected output data size: {output_data_size}{END}')
        print(f'{ITA}D: written {w_sum} bytes{END}')

    if w_sum != output_data_size:
        print(f'{ITA}E: the size of the written data does not match '
              f'the expected size{END}')
        return False

    if mode in (2, 6):
        pad0_b: int = rnd_pad_pos1 - rnd_pad_pos0
        pad1_b: int = rnd_pad_pos3 - rnd_pad_pos2
        pad0_m: float = round((pad0_b) / M, 1)
        pad1_m: float = round((pad1_b) / M, 1)

        print(f'{ITA}I: randomized padding positions in the cryptoblob:\n'
              f'    {rnd_pad_pos0}-{rnd_pad_pos1} ({pad0_b} bytes, {pad0_m}'
              f' MiB),\n'
              f'    {rnd_pad_pos2}-{rnd_pad_pos3} ({pad1_b} bytes, {pad1_m}'
              f' MiB){END}')

    return True


def hider(mode: int) -> bool:
    """
    """
    i_file, i_size, fod['i'] = get_input_file(mode)
    print(f'{ITA}I: input file real path (in quotes):\n    "{i_file}"{END}')
    print(f'{ITA}I: input file size: {i_size} '
          f'bytes, {round(i_size / M, 1)} MiB{END}')

    if mode == 4:  # hide
        o_file, o_size, fod['o'] = get_output_file_w(i_file, i_size, mode)
        max_init_pos = o_size - i_size
    else:  # unhide
        o_file, fod['o'] = get_output_file_c(mode)
        max_init_pos = i_size - 1

    print(f'{ITA}I: output file real path (in quotes):\n    "{o_file}"{END}')

    if mode == 4:
        print(f'{ITA}I: output file size: {o_size} bytes, '
              f'{round(o_size / M, 1)} MiB{END}')

    init_pos: int = get_init_pos(max_init_pos, fix=False)
    print(f'{ITA}I: initial position: {init_pos}{END}')

    if mode == 4:
        data_size: int = i_size
        final_pos: int = init_pos + data_size
        print(f'{ITA}I: final position: {final_pos}{END}')

        if not do_continue(fix=' with input file'):
            print(f'{ITA}I: stopped by user request{END}\n')
            return False
    else:
        final_pos = get_final_pos(
            min_pos=init_pos, max_pos=i_size, fix=False)

        print(f'{ITA}I: final position: {final_pos}{END}')

        data_size = final_pos - init_pos

        print(f'{ITA}I: data size to retrieve: {data_size}{END}')

    if mode == 4:
        print(f'{ITA}I: reading, writing, fsyncing...{END}')
    else:
        print(f'{ITA}I: reading, writing...{END}')

    return hider_processor(mode, init_pos, data_size)


def randgen_processor(o_size: int) -> bool:
    """
    """
    num_chunks: int = o_size // RW_CHUNK_SIZE
    rem_size: int = o_size % RW_CHUNK_SIZE

    print(f'{ITA}I: writing data...{END}')

    fix = ''
    w_sum = 0

    t_start = monotonic()
    t_last_print = t_start

    for _ in range(num_chunks):
        chunk = urandom(RW_CHUNK_SIZE)

        if not write_data(chunk):
            return False

        w_len = len(chunk)
        w_sum += w_len

        if monotonic() - t_last_print >= MIN_PRINT_INTERVAL:
            print_progress(w_sum, o_size, t_start, fix)
            t_last_print = monotonic()

    chunk = urandom(rem_size)

    if not write_data(chunk):
        return False

    w_len = len(chunk)
    w_sum += w_len

    print_progress(w_sum, o_size, t_start, fix)

    return True


def randgen(mode: int) -> bool:
    """
    """
    o_file, fod['o'] = get_output_file_c(mode)
    print(f'{ITA}I: output file real path (in quotes):\n    "{o_file}"{END}')

    o_size = get_output_file_size()
    print(f'{ITA}I: output file size: {o_size} bytes'
          f', {round(o_size / M, 1)} MiB{END}')

    return randgen_processor(o_size)


def wiper(mode: int) -> bool:
    """
    """
    o_file, o_size, fod['o'] = get_output_file_w(
        i_file='', i_size=0, mode=mode)
    print(f'{ITA}I: output file real path (in quotes):\n    "{o_file}"{END}')
    print(f'{ITA}I: output file size: {o_size} bytes'
          f', {round(o_size / M, 1)} MiB{END}')

    if o_size == 0:
        print(f'{ITA}I: nothing to overwrite{END}')
        return False

    init_pos = get_init_pos(max_init_pos=o_size, fix=True)
    print(f'{ITA}I: initial position: {init_pos}{END}')

    if init_pos == o_size:
        print(f'{ITA}I: nothing to overwrite{END}')
        return False

    final_pos = get_final_pos(min_pos=init_pos, max_pos=o_size, fix=True)
    print(f'{ITA}I: final position: {final_pos}{END}')

    data_size = final_pos - init_pos
    print(f'{ITA}I: data size to write: {data_size} bytes'
          f', {round(data_size / M, 1)} MiB{END}')

    if data_size == 0:
        print(f'{ITA}I: nothing to overwrite{END}')
        return False

    if not do_continue(fix=' with random bytes'):
        print(f'{ITA}I: stopped by user request{END}')
        return False

    return wiper_processor(init_pos, data_size)


def signal_handler(signum: Any, frame: Any) -> NoReturn:
    """
    """
    print(f'\n{ERR}E: got signal {signum}{END}')
    exit(1)


def main() -> NoReturn:
    """
    """
    signal(SIGINT, signal_handler)

    if DEBUG:
        print(f'{WAR}W: debug messages enabled!{END}')

    while True:
        mode: int = get_mode()  # returns 0-9

        ok: Union[bool, None] = None

        if mode == 0:
            exit()
        elif mode == 1:
            print(INFO)
        elif mode in (2, 3, 6, 7):
            ok = cryptohider(mode)
        elif mode in (4, 5):
            ok = hider(mode)
        elif mode == 8:
            ok = randgen(mode)
        else:
            ok = wiper(mode)

        if ok:
            print(f'{ITA}I: completed successfully{END}')

        if 'i' in fod:
            fod['i'].close()
        if 'o' in fod:
            fod['o'].close()

        dicts = (fod, sd, cd)
        for i in dicts:
            i.clear()

        collect()


DEBUG: bool = bool('-d' in argv[1:] or '--debug' in argv[1:])

WIN32: bool = bool(platform == 'win32')

if WIN32:
    BOL: str = ''
    ITA: str = ''
    ERR: str = ''
    WAR: str = ''
    END: str = ''
else:
    BOL = '\033[1m'  # bold text
    ITA = '\033[3m'  # italic text
    ERR = '\033[1;3;97;101m'  # bold italic white text, red bg
    WAR = '\033[1;3;93;40m'
    END = '\033[0m'

MENU: str = f"""
                        {BOL}MENU{END}
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    0. Exit               1. Get info
    2. Encrypt            3. Decrypt
    4. Hide               5. Unhide
    6. Encrypt and hide   7. Unhide and decrypt
    8. Create w/ urandom  9. Overwrite w/ urandom
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{BOL}Please enter [0-9]:{END} """

INFO: str = f'{ITA}I: tird is a tool for encrypting file contents' \
    f' and\n   hiding random data among other random data\n' \
    f'I: more info: https://github.com/hakavlad/tird{END}'

INVALID_UTF8_BYTE: bytes = b'\xff'

fod: dict = {}  # file objects dict
sd: dict = {}  # salts dict
cd: dict = {}  # custom dict


K: int = 2 ** 10
M: int = 2 ** 20

BLAKE_DIGEST_SIZE: int = 64

BLAKE_PERSON_KEYFILE: bytes = b'KEYFILE'
BLAKE_PERSON_PASSPHRASE: bytes = b'PASSPHRASE'

DEFAULT_PAD_MAX_PERCENT: int = 20

DEFAULT_CATPIG_SPACE_MIB: int = 16
DEFAULT_CATPIG_PASSES: int = 4

BYTEORDER = 'little'

# catpig constants
RND_CHUNK_SIZE: int = 8
SHAKE_SIZE: int = 64
READ_CHUNK_SIZE: int = K * 4
READ_BLOCK_SIZE: int = K * 64
NUM_CHUNKS_IN_READ_BLOCK: int = READ_BLOCK_SIZE // READ_CHUNK_SIZE
NUM_READ_BLOCKS_IN_MIB: int = M // READ_BLOCK_SIZE
RND_BLOCK_SIZE: int = RND_CHUNK_SIZE * \
    NUM_CHUNKS_IN_READ_BLOCK + SHAKE_SIZE
MAX_SPACE_BLOCK_SIZE: int = (2 ** 31 - 1) // M
MAX_SPACE_MIB: int = (256 ** RND_CHUNK_SIZE - 1) // M

ONE_SALT_HALF_SIZE: int = 8
ONE_SALT_SIZE: int = ONE_SALT_HALF_SIZE * 2
SALTS_HALF_SIZE: int = ONE_SALT_HALF_SIZE * 3
SALTS_SIZE: int = ONE_SALT_SIZE * 3

MAC_KEY_SIZE: int = 64
MAC_TAG_SIZE: int = MAC_KEY_SIZE

PAD_KEY_SIZE = 32

KS_CONTENTS_SITE_SIZE: int = 64 * K
KS_COMMENTS_SITE_SIZE: int = 512
KS_MAC_SITE_SIZE: int = MAC_TAG_SIZE
KS_FOOTER_SITE_SIZE: int = 64

KS_BLOCK_SIZE: int = (
    KS_CONTENTS_SITE_SIZE +
    KS_COMMENTS_SITE_SIZE +
    KS_MAC_SITE_SIZE +
    KS_FOOTER_SITE_SIZE
)

KS_COMMENTS_SITE_START_POS: int = KS_CONTENTS_SITE_SIZE
KS_COMMENTS_SITE_FIN_POS: int = KS_COMMENTS_SITE_START_POS + \
    KS_COMMENTS_SITE_SIZE

KS_MAC_SITE_START_POS: int = KS_COMMENTS_SITE_FIN_POS
KS_MAC_SITE_FIN_POS: int = KS_MAC_SITE_START_POS + KS_MAC_SITE_SIZE


MIN_VALID_CRYPTOBLOB_SIZE: int = (
    SALTS_SIZE +
    KS_COMMENTS_SITE_SIZE +
    MAC_TAG_SIZE
)

DEK_SIZE = 64

SCRYPT_N: int = 2 ** 20
SCRYPT_R: int = 8
SCRYPT_P: int = 1
SCRYPT_MAXMEM: int = 2 ** 31 - 1
SCRYPT_DKLEN: int = DEK_SIZE + MAC_KEY_SIZE + PAD_KEY_SIZE

RW_CHUNK_SIZE: int = KS_CONTENTS_SITE_SIZE
MIN_PRINT_INTERVAL: int = 5
MIN_FSYNC_SIZE: int = M * 256
HIDER_DIGEST_SIZE: int = 20

if __name__ == '__main__':
    main()
