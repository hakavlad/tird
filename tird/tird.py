#!/usr/bin/env python3
"""A tool for encrypting file contents and hiding random data
among other random data.
"""

from copy import deepcopy
from getpass import getpass
from hashlib import blake2b, scrypt, shake_256
from operator import itemgetter
from os import fsync, path, urandom, walk
from signal import SIGINT, signal
from sys import byteorder, exit, platform
from time import monotonic


def get_mode():
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
            print(f'{ITA}I: mode: encrypt file{END}')
            return 2

        if mode == '3':
            print(f'{ITA}I: mode: decrypt file{END}')
            return 3

        if mode == '4':
            print(f'{ITA}I: mode: hide file (without encryption){END}')
            return 4

        if mode == '5':
            print(f'{ITA}I: mode: unhide file (without decryprion){END}')
            return 5

        if mode == '6':
            print(f'{ITA}I: mode: encrypt and hide file{END}')
            return 6

        if mode == '7':
            print(f'{ITA}I: mode: unhide and decrypt file{END}')
            return 7

        if mode == '8':
            print(f'{ITA}I: mode: create file with random data{END}')
            return 8

        if mode == '9':
            print(f'{ITA}I: mode: overwrite file with random data{END}')
            return 9

        print(f'{ERR}E: invalid value{END}')


def is_custom():
    """
    """
    while True:
        custom = input(f'{BOL}Custom options (0|1):{END} ')
        if custom in ('', '0'):
            return False
        if custom == '1':
            return True
        print(f'{ERR}E: invalid value{END}')
        continue


def is_debug():
    """
    """
    while True:
        debug = input(f'  {BOL}Debug (0|1):{END} ')
        if debug in ('', '0'):
            return False
        if debug == '1':
            return True
        print(f'  {ERR}E: invalid value{END}')
        continue


def get_num_rounds():
    """
    """
    while True:
        num_rounds = input(f'  {BOL}Number of rounds (default'
                           f'={DEFAULT_NUM_ROUNDS}):{END} ')

        if num_rounds in ('', str(DEFAULT_NUM_ROUNDS)):
            return DEFAULT_NUM_ROUNDS

        try:
            num_rounds = int(num_rounds)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if num_rounds < 1:
            print(f'  {ERR}E: invalid value; must be >= 1{END}')
            continue

        return num_rounds


def get_keystream_block_size():
    """
    """
    while True:
        keystram_block_size_m = input(
            f'  {BOL}Keystream block size, MiB (default'
            f'={DEFAULT_KEYSTREAM_BLOCK_SIZE_M}):{END} ')

        if keystram_block_size_m in ('', str(DEFAULT_KEYSTREAM_BLOCK_SIZE_M)):
            return DEFAULT_KEYSTREAM_BLOCK_SIZE_M * M

        try:
            keystram_block_size_m = int(keystram_block_size_m)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if keystram_block_size_m < 1 or keystram_block_size_m > 2047:
            print(f'  {ERR}E: invalid value; must be >= 1 and <= 2047{END}')
            continue

        return keystram_block_size_m * M


def get_padding_order():
    """
    """
    while True:
        padding_order = input(
            f'  {BOL}Randomized padding order (default'
            f'={DEFAULT_PADDING_ORDER}):{END} ')

        if padding_order in ('', str(DEFAULT_PADDING_ORDER)):
            return DEFAULT_PADDING_ORDER

        try:
            padding_order = int(padding_order)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if padding_order < 0 or padding_order > MAX_PADDING_ORDER:
            print(f'  {ERR}E: invalid value; must be >= 0 and '
                  f'<= {MAX_PADDING_ORDER}{END}')
            continue

        return padding_order


def get_padding_max_percent():
    """
    """
    while True:
        padding_max_percent = input(
            f'  {BOL}Randomized padding max percent (default'
            f'={DEFAULT_PADDING_MAX_PERCENT}):{END} ')

        if padding_max_percent in ('', str(DEFAULT_PADDING_MAX_PERCENT)):
            return DEFAULT_PADDING_MAX_PERCENT

        try:
            padding_max_percent = int(padding_max_percent)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if padding_max_percent < 0:
            print(f'  {ERR}E: invalid value; must be >= 0{END}')
            continue

        return padding_max_percent


def get_dk_len():
    """
    """
    while True:
        dk_len_m = input(
            f'  {BOL}Derived key length, MiB '
            f'(default={DEFAULT_DK_LEN_M}):{END} ')

        if dk_len_m in ('', str(DEFAULT_DK_LEN_M)):
            return DEFAULT_DK_LEN

        try:
            dk_len_m = int(dk_len_m)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if dk_len_m < 1:
            print(f'  {ERR}E: invalid value; must be >= 1{END}')
            continue

        return dk_len_m * M


def get_metadata_size():
    """
    """
    while True:
        metadata_size = input(
            f'  {BOL}Metadata size (default={DEFAULT_METADATA_SIZE}): {END}')

        if metadata_size in ('', str(DEFAULT_METADATA_SIZE)):
            return DEFAULT_METADATA_SIZE

        try:
            metadata_size = int(metadata_size)
        except Exception:
            print(f'  {ERR}E: invalid value{END}')
            continue

        if metadata_size < 0 or metadata_size > MAX_METADATA_SIZE:
            print(f'  {ERR}E: invalid value; must be >= 0 and '
                  f'<= {MAX_METADATA_SIZE}{END}')
            continue

        return metadata_size


def get_input_keys():
    """
    Get input keys (keyfiles and passphrases).
    """
    k_list_list = []

    while True:
        k_file = input(f'{BOL}Keyfile (optional):{END} ')

        if k_file == '':
            break

        k_file = path.realpath(k_file)

        if not path.exists(k_file):
            print(f'{ERR}E: {k_file} does not exist{END}')
            print(f'{ERR}E: keyfile NOT accepted!{END}')
            continue

        if path.isdir(k_file):

            dir_list = dir_to_list_list(k_file)

            if dir_list is None:
                print(f'{ERR}E: keyfiles NOT accepted!{END}')
                continue
            if dir_list == []:
                print(f'{ERR}E: nothing to accept!{END}')
            else:
                k_list_list.extend(dir_list)
                print(f'{ITA}I: keyfiles accepted!{END}')

        else:
            file_list = keyfile_to_list(k_file)
            if file_list is None:
                print(f'{ERR}E: keyfile NOT accepted!{END}')
            else:
                k_list_list.append(file_list)
                print(f'{ITA}I: keyfile accepted!{END}')
            continue

    while True:
        pp0 = getpass(f'{BOL}Passphrase (optional):{END} ')
        if pp0 == '':
            break

        pp1 = getpass(f'{BOL}Confirm passphrase:{END} ')
        if pp0 == pp1:
            pp_list = pp_to_list(pp0)
            k_list_list.append(pp_list)
            print(f'{ITA}I: passphrase accepted!{END}')
        else:
            print(f'{ERR}E: passphrase confirmation failed!{END}')

            pp_list = pp_to_list(pp0)
            k_list_list.append(pp_list)

    return k_list_list


def get_input_file(mode):
    """
    """
    if mode == 2:
        i = 'File to encrypt: '
    elif mode == 3:
        i = 'File to decrypt: '
    elif mode == 6:
        i = 'File to encrypt and hide: '
    elif mode in (7, 5):
        i = 'Container: '
    elif mode == 4:
        i = 'File to hide: '
    else:
        print(f'{ERR}E: invalid mode{END}')
        exit(1)

    while True:
        i_file = input(f'{BOL}{i}{END}')

        if i_file == '':
            print(f'{ERR}E: input file is not set{END}')
            continue

        i_file = path.realpath(i_file)
        i_size = get_file_size(i_file)
        if i_size is None:
            continue

        try:
            i_object = open(i_file, 'rb')
            break
        except Exception as e:
            print(f'{ERR}E: {e}{END}')

    return i_file, i_size, i_object


def get_output_file_c(mode):
    """
    """
    if mode == 2:
        i = 'Output (encrypted) file: '
    elif mode in (3, 7):
        i = 'Output (decrypted) file: '
    elif mode in (5, 8):
        i = 'Output file: '
    else:
        print(f'{ERR}E: invalid mode{END}')
        exit(1)

    while True:
        o_file = input(f'{BOL}{i}{END}')

        if o_file == '':
            print(f'{ERR}E: output file is not set{END}')
            continue

        o_file = path.realpath(o_file)
        if path.exists(o_file):
            print(f'{ERR}E: this file already exists{END}')
            continue

        try:
            o_object = open(o_file, 'wb')
            break
        except Exception as e:
            print(f'{ERR}E: {e}{END}')

    return o_file, o_object


def get_output_file_w(i_file, i_size, mode):
    """
    """
    if mode in (6, 4):
        i = 'File to overwrite (container): '
    elif mode == 9:
        i = 'File to overwrite: '
    else:
        print(f'{ERR}E: invalid mode{END}')
        exit(1)

    while True:
        o_file = input(f'{BOL}{i}{END}')

        if o_file == '':
            print(f'{ERR}E: output file is not set{END}')
            continue

        o_size = get_file_size(o_file)
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

        try:
            o_object = open(o_file, 'rb+')
            break
        except Exception as e:
            print(f'{ERR}E: {e}{END}')
            continue

    return o_file, o_size, o_object


def get_init_pos(max_init_pos, fix):
    """
    fix=True for wiper()
    """
    while True:
        if fix:
            init_pos = input(f'{BOL}Initial position, valid values are '
                             f'[0; {max_init_pos}], default=0:{END} ')
            if init_pos == '':
                init_pos = 0
        else:
            init_pos = input(f'{BOL}Initial position, valid values are '
                             f'[0; {max_init_pos}]:{END} ')
            if init_pos == '':
                print(f'{ERR}E: initial position is not set{END}')
                continue

        try:
            init_pos = int(init_pos)
        except Exception:
            print(f'{ERR}E: invalid value{END}')
            continue

        if init_pos > max_init_pos or init_pos < 0:
            print(f'{ERR}E: invalid initial position{END}')
            continue

        return init_pos


def get_final_pos(min_pos, max_pos, fix):
    """
    """
    while True:
        if fix:
            final_pos = input(
                f'{BOL}Final position, valid values are [{min_pos};'
                f' {max_pos}], default={max_pos}:{END} ')
            if final_pos == '':
                final_pos = max_pos
        else:
            final_pos = input(f'{BOL}Final position, valid values are '
                              f'[{min_pos}; {max_pos}]:{END} ')

        try:
            final_pos = int(final_pos)
        except Exception:
            print(f'{ERR}E: invalid value{END}')
            continue

        if final_pos < min_pos or final_pos > max_pos:
            print(f'{ERR}E: invalid value{END}')
            continue

        return final_pos


def get_metadata_bytes():
    """
    Get binary data to save as metadata.
    """
    md_size = od['metadata_size']
    meta_utf = input(f'{BOL}Metadata (optional, up to {md_size} bytes):{END} ')

    if meta_utf == '':
        m_bytes = urandom(md_size)
    else:
        m_bytes = meta_utf.encode()
        m_bytes += METADATA_DIV_BYTE
        m_bytes = m_bytes[:md_size]
        m_bytes += urandom(max(md_size - len(m_bytes), 0))

    meta_utf = metadata_to_utf(m_bytes)
    print(f'{ITA}I: metadata as it will be shown: {[meta_utf]}{END}')
    return m_bytes


def get_mac():
    """
    """
    while True:
        add_mac = input(f'{BOL}Add MAC (0|1):{END} ')
        if add_mac in ('', '0', '1'):
            break
        print(f'{ERR}E: invalid value{END}')
        continue

    if add_mac in ('', '0'):
        return False

    return True


def get_output_file_size():
    """
    """
    while True:
        o_size = input(f'{BOL}Output file size in bytes:{END} ')

        if o_size == '':
            print(f'{ERR}E: output file is not set{END}')
            continue

        try:
            o_size = int(o_size)
        except Exception as e:
            print(f'{ERR}E: {e}{END}')
            continue

        if o_size < 0:
            print(f'{ERR}E: negative file size value{END}')
            continue

        return o_size


def do_continue(fix):
    """
    """
    while True:
        do_cont = input(f'{BOL}Output file will be partially overwritten{fix}.'
                        f' Proceed? (y|n):{END} ')
        if do_cont in ('y', 'Y'):
            return True
        if do_cont in ('n', 'N'):
            return False


def eprint(i_list):
    """
    """
    for i in i_list:
        print(f'  - {i.hex()}')


def eeprint(i_list_list):
    """
    """
    i_len = len(i_list_list)
    for i in range(i_len):
        print(f'  {ITA}round {i + 1}/{i_len}:{END}')
        i_list = i_list_list[i]
        eprint(i_list)


def kprint(i_list):
    """
    """
    x_list = deepcopy(i_list)

    for x in x_list:
        x[4] = x[4].hex()
        print(f'{ITA}  - {x}{END}')


def print_positions():
    """
    """
    ift = od['i'].tell()
    oft = od['o'].tell()
    print(f'{ITA}D: current pointer positions: if={ift}, of={oft}{END}')


def print_progress(written_sum, data_size, T0, fix):
    """
    """
    if data_size == 0:
        print(f'{ITA}I: written 0 bytes{END}')
        return

    t = monotonic() - T0
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


def xor(a, b):
    """
    """
    length = min(len(a), len(b))
    a_int = int.from_bytes(a[:length], byteorder=byteorder)
    b_int = int.from_bytes(b[:length], byteorder=byteorder)
    c_int = a_int ^ b_int
    c = c_int.to_bytes(length, byteorder=byteorder)
    return c


def shake_256_digest(data, size):
    """
    """
    m = shake_256()
    m.update(data)
    return m.digest(size)


def blake2b_digest(data, person=b''):
    """
    """
    m = blake2b(digest_size=BLAKE_DIGEST_SIZE, person=person)
    m.update(data)
    return m.digest()


def blake2b_file_digest(f_object, f_size, person=b''):
    """
    """
    m = blake2b(digest_size=BLAKE_DIGEST_SIZE, person=person)

    n = f_size // RW_CHUNK_SIZE
    r = f_size % RW_CHUNK_SIZE

    try:
        for _ in range(n):
            data = f_object.read(RW_CHUNK_SIZE)
            m.update(data)
        data = f_object.read(r)
        m.update(data)
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        return None

    return m.digest()


def keyfile_to_list(f_path):
    """
    """
    f_size = get_file_size(f_path)

    if f_size is None:
        return None

    print(f'{ITA}I: keyfile size: {f_size} bytes, real path: "{f_path}"{END}')
    print(f'{ITA}I: hashing the keyfile...{END}')

    with open(f_path, 'rb') as f:
        f_digest = blake2b_file_digest(f, f_size, person=BLAKE_PERSON_KEYFILE)

    if f_digest is None:
        return None

    f_list = [False, f_path, None, f_size, f_digest]

    if od['debug']:
        print(f'{ITA}D: {f_list}{END}')

    return f_list


def dir_to_list_list(d_path):
    """
    """
    f_list_list = []
    size_sum = 0
    print(f'{ITA}I: scanning the directory "{d_path}"{END}')

    for root, _, files in walk(d_path):
        for f in files:
            k_file = path.join(root, f)

            if od['debug']:
                print(f'{ITA}D: getting the size of "{k_file}"{END}')

            f_size = get_file_size(k_file)

            if f_size is None:
                return None

            size_sum += f_size

            f_list = [False, k_file, None, f_size, None]
            f_list_list.append(f_list)

    f_list_list_len = len(f_list_list)

    print(f'{ITA}I: found {f_list_list_len} files, total '
          f'size: {size_sum} bytes{END}')

    if f_list_list_len == 0:
        return []

    print(f'{ITA}I: hashing files in the directory "{d_path}"{END}')

    for i in range(f_list_list_len):
        f_list = f_list_list[i]

        _, f_path, _, f_size, _ = f_list

        if od['debug']:
            print(f'{ITA}D: hashing "{k_file}"{END}')

        with open(f_path, 'rb') as f:
            f_digest = blake2b_file_digest(
                f, f_size, person=BLAKE_PERSON_KEYFILE)

            if f_digest is None:
                return None

        f_list_list[i][4] = f_digest

    if od['debug']:
        print(f'{ITA}D: final lists:{END}')
        for f_list in f_list_list:
            print(f'{ITA}D: {f_list}{END}')

    return f_list_list


def pp_to_list(pp):
    """
    """
    pp = pp.encode()
    pp_len = len(pp)
    pp_digest = blake2b_digest(pp, person=BLAKE_PERSON_PASSPHRASE)
    pp_list = [True, None, pp, pp_len, pp_digest]

    if od['debug']:
        print(f'{ITA}D: {pp_list}{END}')

    return pp_list


def get_keys_for_kdf():
    """
    Get N keys for KDF from M key units
    (keyfiles and passphrases from user input).

    =--====--------------=----=====-=--  M keys
    -----+++++-----+++++-----+++++-----  N blocks

    ======================-----=-==----  M keys
    -----+++++-----+++++-----+++++-----  N blocks
    """
    k_list_list = get_input_keys()

    if not k_list_list:
        print(f'{ITA}W: keys are not set!{END}')

    # sort by digests
    k_list_list.sort(key=itemgetter(4))

    if od['debug'] and len(k_list_list) > 0:
        print(f'{ITA}D: keyfiles and passphrases:{END}')
        kprint(k_list_list)

    keys_total_size = 0

    basic_m = blake2b(
        digest_size=BLAKE_DIGEST_SIZE,
        person=BLAKE_PERSON_BASIC_KEY)

    for k_list in k_list_list:
        _, _, _, k_size, k_digest = k_list
        keys_total_size += k_size
        basic_m.update(k_digest)

    if od['debug']:
        print(f'D: received {len(k_list_list)} key items with a total size '
              f'of {keys_total_size} bytes'
              f' ({round(keys_total_size / M, 1)} MiB)')

    basic_key = basic_m.digest()

    if od['debug']:
        print(f'{ITA}D: basic key: {basic_key.hex()}{END}')

    total_block_num = od['num_rounds'] * 3

    base_block_size = keys_total_size // total_block_num
    ext_block_size = base_block_size + 1
    ext_block_num = keys_total_size % total_block_num
    base_block_num = total_block_num - ext_block_num

    if od['debug']:
        print(f'{ITA}D: keys_total_size: {keys_total_size}, '
              f'total_block_num: {total_block_num}{END}')
        print(f'{ITA}D: ext_block_size: {ext_block_size}, '
              f'ext_block_num: {ext_block_num}{END}')
        print(f'{ITA}D: base_block_size: {base_block_size}, '
              f'base_block_num: {base_block_num}{END}')

    m = blake2b(digest_size=BLAKE_DIGEST_SIZE, person=BLAKE_PERSON_EQUAL_BLOCK)

    digest_tuple_list = []

    r_sum = 0
    block_r_sum = 0
    cur_block_num = 0
    cur_block_size = base_block_size

    if ext_block_num > 0:
        cur_block_size = ext_block_size

    cur_block_rem_size = cur_block_size

    stop = False

    if od['debug']:
        print(f'{ITA}D: hashing equal blocks of all key item content, '
              f'sorted by their digest...{END}')

    for key_list in k_list_list:
        if od['debug']:
            print(f'{ITA}D: handling key item {key_list}{END}')

        key_size = key_list[3]
        if key_size == 0:
            continue

        key_rem_size = key_size
        is_pp = key_list[0]

        if not is_pp:
            key_path = key_list[1]
            f = open(key_path, 'rb')
        else:
            pp_data = key_list[2]
            key_pos = 0

        if key_rem_size >= cur_block_rem_size:
            if cur_block_rem_size < cur_block_size:

                if not is_pp:
                    n = cur_block_rem_size // RW_CHUNK_SIZE
                    r = cur_block_rem_size % RW_CHUNK_SIZE
                    key_data_len = 0
                    try:
                        for _ in range(n):
                            key_data_chunk = f.read(RW_CHUNK_SIZE)
                            m.update(key_data_chunk)
                            key_data_len += len(key_data_chunk)
                        key_data_chunk = f.read(r)
                        m.update(key_data_chunk)
                        key_data_len += len(key_data_chunk)
                    except OSError as e:
                        print(f'{ERR}E: {e}{END}')
                        f.close()
                        return None
                else:
                    key_data = pp_data[:cur_block_rem_size]
                    key_pos = cur_block_rem_size
                    m.update(key_data)
                    key_data_len = len(key_data)

                block_r_sum += key_data_len
                r_sum += key_data_len

                part_digest = m.digest()
                digest_tuple = (part_digest, block_r_sum, cur_block_num)
                digest_tuple_list.append(digest_tuple)

                if od['debug']:
                    print(f'{ITA}D: got block digest #{cur_block_num}; block '
                          f'size: {block_r_sum} bytes; digest'
                          f': {part_digest.hex()}{END}')

                cur_block_num += 1
                block_r_sum = 0
                m = blake2b(
                    digest_size=BLAKE_DIGEST_SIZE,
                    person=BLAKE_PERSON_EQUAL_BLOCK)

                if cur_block_num < ext_block_num:
                    cur_block_size = ext_block_size
                else:
                    cur_block_size = base_block_size

                cur_block_rem_size = cur_block_size
                key_rem_size = key_rem_size - key_data_len

            while True:
                if key_rem_size < cur_block_size:
                    break

                if not is_pp:
                    n = cur_block_rem_size // RW_CHUNK_SIZE
                    r = cur_block_rem_size % RW_CHUNK_SIZE
                    key_data_len = 0
                    try:
                        for _ in range(n):
                            key_data_chunk = f.read(RW_CHUNK_SIZE)
                            m.update(key_data_chunk)
                            key_data_len += len(key_data_chunk)
                        key_data_chunk = f.read(r)
                        m.update(key_data_chunk)
                        key_data_len += len(key_data_chunk)
                    except OSError as e:
                        print(f'{ERR}E: {e}{END}')
                        f.close()
                        return None
                else:
                    new_pos = key_pos + cur_block_size
                    key_data = pp_data[key_pos:new_pos]
                    key_pos = new_pos
                    m.update(key_data)
                    key_data_len = len(key_data)

                block_r_sum += key_data_len
                r_sum += key_data_len

                part_digest = m.digest()
                digest_tuple = (part_digest, block_r_sum, cur_block_num)
                digest_tuple_list.append(digest_tuple)

                if od['debug']:
                    print(f'{ITA}D: got block digest #{cur_block_num}; block '
                          f'size: {block_r_sum} bytes; digest'
                          f': {part_digest.hex()}{END}')

                cur_block_num += 1
                if cur_block_num < ext_block_num:
                    cur_block_size = ext_block_size
                else:
                    cur_block_size = base_block_size

                if cur_block_size == 0:
                    stop = True
                    break

                cur_block_rem_size = cur_block_size
                key_rem_size = key_rem_size - key_data_len

                block_r_sum = 0
                m = blake2b(
                    digest_size=BLAKE_DIGEST_SIZE,
                    person=BLAKE_PERSON_EQUAL_BLOCK)

            if stop:
                break

            if not is_pp:
                n = key_rem_size // RW_CHUNK_SIZE
                r = key_rem_size % RW_CHUNK_SIZE
                key_data_len = 0
                try:
                    for _ in range(n):
                        key_data_chunk = f.read(RW_CHUNK_SIZE)
                        m.update(key_data_chunk)
                        key_data_len += len(key_data_chunk)
                    key_data_chunk = f.read(r)
                    m.update(key_data_chunk)
                    key_data_len += len(key_data_chunk)
                except OSError as e:
                    print(f'{ERR}E: {e}{END}')
                    f.close()
                    return None
            else:
                new_pos = key_pos + key_rem_size
                key_data = pp_data[key_pos:new_pos]
                key_pos = new_pos
                m.update(key_data)
                key_data_len = len(key_data)

            block_r_sum += key_data_len
            r_sum += key_data_len

            cur_block_rem_size = cur_block_rem_size - key_data_len
            key_rem_size = key_rem_size - key_data_len
        else:

            if not is_pp:
                n = key_rem_size // RW_CHUNK_SIZE
                r = key_rem_size % RW_CHUNK_SIZE
                key_data_len = 0
                try:
                    for _ in range(n):
                        key_data_chunk = f.read(RW_CHUNK_SIZE)
                        m.update(key_data_chunk)
                        key_data_len += len(key_data_chunk)
                    key_data_chunk = f.read(r)
                    m.update(key_data_chunk)
                    key_data_len += len(key_data_chunk)
                except OSError as e:
                    print(f'{ERR}E: {e}{END}')
                    f.close()
                    return None
            else:
                key_data = pp_data
                m.update(key_data)
                key_data_len = len(key_data)

            block_r_sum += key_data_len
            r_sum += key_data_len

            cur_block_rem_size = cur_block_rem_size - key_data_len

            key_rem_size = key_rem_size - key_data_len

        if not is_pp:
            f.close()

    if od['debug']:
        print(f'{ITA}D: hashing equal blocks of all key item content, '
              f'sorted by their digest: done{END}')

        print(f'{ITA}D: block sizes and digests:{END}')
        for digest_tuple in digest_tuple_list:
            c, b, a = digest_tuple
            print(f'  block#{a}, size={b}, digest={c.hex()}')

    for_kdf_key_list = []

    for i in range(total_block_num):
        try:
            part_key = digest_tuple_list[i][0]
        except IndexError:
            part_key = blake2b_digest(b'', person=BLAKE_PERSON_EQUAL_BLOCK)

        for_kdf_key_list.append(basic_key + part_key)

    for_kdf_key_list_list = []
    start, fin = 0, 3
    for i in range(od['num_rounds']):
        for_kdf_key_list_list.append(for_kdf_key_list[start:fin])
        start, fin = start + 3, fin + 3

    if od['debug']:
        print(f'{ITA}D: keys for KDF:{END}')
        eeprint(for_kdf_key_list_list)

    return for_kdf_key_list_list


def get_salt_list_list(i_size, final_pos, mode):
    """
    """
    salt_list_list = []

    if mode in (2, 6):  # encryption
        for _ in range(od['num_rounds']):
            salt_list = []
            for _ in range(3):
                salt_list.append(urandom(ONE_SALT_SIZE))
            salt_list_list.append(salt_list)

        if od['debug']:
            print(f'{ITA}D: the salts has been created{END}')

    else:
        # decryption, mode 3 and 7
        # read salts from the beginning and end of the encrypted file
        # (including positions with mode=7)
        try:
            salt_header = od['i'].read(od['salt_header_size'])
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        if od['debug']:
            print(f'{ITA}D: the start salt has been read{END}')
            print_positions()

        cur_pos = od['i'].tell()

        if mode == 3:
            new_pos = i_size - od['salt_footer_size']
        else:
            new_pos = final_pos - od['salt_footer_size']

        try:
            # move to the position of the beginning of the final salt
            od['i'].seek(new_pos)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        if od['debug']:
            print(f'{ITA}D: we are in position before the final salt{END}')
            print_positions()

        try:
            salt_footer = od['i'].read(od['salt_footer_size'])
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        if od['debug']:
            print(f'{ITA}D: the final salt has been read{END}')
            print_positions()

        # return to the previously saved position
        od['i'].seek(cur_pos)

        if od['debug']:
            print(f'{ITA}D: we returned to the position after the '
                  f'starting salt{END}')
            print_positions()

        # then we need to get lists with salts ready for submission to KDF

        y_list = []

        c = 0
        for i in range(od['salts_size']):
            if i % 2 == 0:
                y_list.append(salt_header[c:c + 1])
            else:
                y_list.append(salt_footer[c:c + 1])
                c += 1

        salts = b''.join(y_list)

        z_list = []

        start, fin = 0, ONE_SALT_SIZE

        for _ in range(od['num_rounds'] * 3):
            z_list.append(salts[start:fin])
            start, fin = start + ONE_SALT_SIZE, fin + ONE_SALT_SIZE

        salt_list_list = []

        start, fin = 0, 3
        for i in range(od['num_rounds']):
            salt_list_list.append(z_list[start:fin])
            start, fin = start + 3, fin + 3

    return salt_list_list


def get_two_salts(salt_list_list):
    """
    """
    s_list = []

    for salt_list in salt_list_list:
        s_list.extend(salt_list)

    salts = b''.join(s_list)
    salts_len = len(salts)

    salt_header_list = []
    salt_footer_list = []

    for i in range(salts_len):
        b = salts[i:i + 1]

        if i % 2 == 0:
            salt_header_list.append(b)
        else:
            salt_footer_list.append(b)

    salt_header = b''.join(salt_header_list)
    salt_footer = b''.join(salt_footer_list)

    return salt_header, salt_footer


def get_first_rk_list_list(for_kdf_key_list_list, salt_list_list):
    """
    """
    rk_list_list = []

    print(f'{ITA}I: deriving keys...{END}')
    tx1 = monotonic()

    num_rounds = od['num_rounds']

    for i in range(od['num_rounds']):

        if od['debug']:
            print(
                f'{ITA}D: deriving keys, round'
                f' {i + 1}/{num_rounds}...{END}')

        salt_list = salt_list_list[i]
        key_list = for_kdf_key_list_list[i]

        if od['debug']:
            print(f'{ITA}D: salt list:{END}')
            eprint(salt_list)
            print(f'{ITA}D: key list:{END}')
            eprint(key_list)

        dk_digest_list = []

        for i2 in range(3):
            if od['debug']:
                print(f'{ITA}D: get new dk...{END}')

            salt = salt_list[i2]
            if od['debug']:
                print(f'  salt: {salt.hex()}')

            key = key_list[i2]
            if od['debug']:
                print(f'  key: {key.hex()}')

            if od['debug']:
                t01 = monotonic()

            dk = scrypt(key, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, dklen=od['dk_len'])

            dk_digest = blake2b_digest(dk, person=BLAKE_PERSON_ROUND_KEY)

            if od['debug']:
                t02 = monotonic()
                print(f'  dk digest: {dk_digest.hex()}')
                print(f'D: one key derived in {round(t02 - t01, 3)}s')

            dk_digest_list.append(dk_digest)

        rk_list_list.append(dk_digest_list)

    tx2 = monotonic()
    print(f'{ITA}I: keys derived in {round(tx2 - tx1, 1)}s{END}')

    return rk_list_list


def get_updated_rk_list_list(rk_list_list, keystream_chunk):
    """
    """
    if od['debug']:
        print(f'{ITA}D: getting new `round keys`...{END}')

    new_rk_list_list = []

    for rk_list in rk_list_list:
        new_rk_list = []
        for rk in rk_list:
            new_rk = blake2b_digest(
                rk + keystream_chunk,
                person=BLAKE_PERSON_ROUND_KEY)
            new_rk_list.append(new_rk)
        new_rk_list_list.append(new_rk_list)

    if od['debug']:
        print(f'{ITA}D: old keys:{END}')
        eeprint(rk_list_list)
        print(f'{ITA}D: new keys:{END}')
        eeprint(new_rk_list_list)

    return new_rk_list_list


def get_mixed_block(rk_list):
    """
    """
    if od['debug']:
        T0 = monotonic()
        print(f'{ITA}D: starting get_mixed_block(){END}')
        print(f'{ITA}D: getting block_src, block_rip, block_mix...{END}')
        t0 = monotonic()

    block_src = shake_256_digest(rk_list[0], od['block_src_size'])
    block_rip = shake_256_digest(rk_list[1], od['block_rip_size'])
    block_mix = shake_256_digest(rk_list[2], od['block_mix_size'])

    if od['debug']:
        t1 = monotonic()
        print(f'{ITA}D: got block_src, block_rip, block_mix '
              f'in {round(t1 - t0, 3)}s{END}')

    chunks_dict = {}  # {'4 bytes': 'chunk 128 + 0-255 bytes', ...}
    block_mix_position = 0
    byte_num = 0
    read_pos = 0

    if od['debug']:
        print(f'{ITA}D: getting chunks_dict...{END}')
        t0 = monotonic()

    while True:
        rnd_chunk_size = MIN_KEYSTREAM_CHUNK_SIZE + block_rip[byte_num]
        rnd_chunk = block_src[read_pos:read_pos + rnd_chunk_size]

        if not rnd_chunk:
            break

        read_pos += rnd_chunk_size
        byte_num += 1

        while True:
            new_pos = block_mix_position + MIX_BYTES_SIZE
            mix_bytes = block_mix[block_mix_position:new_pos]

            block_mix_position = new_pos

            if mix_bytes not in chunks_dict:
                chunks_dict[mix_bytes] = rnd_chunk
                break

    if od['debug']:
        t1 = monotonic()
        print(f'{ITA}D: got chunks_dict {round(t1 - t0, 3)}s{END}')

        print(f'{ITA}D: sorting {len(chunks_dict)} chunks...{END}')
        t0 = monotonic()

    mixed_tuple_list = sorted(chunks_dict.items(), key=itemgetter(0))

    if od['debug']:
        t1 = monotonic()
        print(f'{ITA}D: chunks sorted in {round(t1 - t0, 3)}s{END}')
        print(f'{ITA}D: getting mixed_block...{END}')
        t0 = monotonic()

    mixed_list = []

    for rnd_tuple in mixed_tuple_list:
        mixed_list.append(rnd_tuple[1])

    mixed_block = b''.join(mixed_list)

    if od['debug']:
        t1 = monotonic()
        print(f'{ITA}D: got mixed_block in {round(t1 - t0, 3)}s{END}')
        print(f'{ITA}D: get_mixed_block() finished '
              f'in {round(t1 - T0, 3)}s{END}')

    return mixed_block


def get_keystream_block(rk_list_list):
    """
    """
    if od['debug']:
        print(f'{ITA}D: starting to get keystream block...{END}')
        t0 = monotonic()

    rk_list = rk_list_list[0]
    mixed_block = get_mixed_block(rk_list)

    if od['num_rounds'] == 1:
        if od['debug']:
            t1 = monotonic()
            print(f'{ITA}D: keystream block has been received '
                  f'in {round(t1 - t0, 3)}s{END}')
        return mixed_block

    mixed_block_int = int.from_bytes(mixed_block, byteorder)

    for rk_list in rk_list_list[1:]:
        mixed_block_x = get_mixed_block(rk_list)
        mixed_block_x_int = int.from_bytes(mixed_block_x, byteorder)

        mixed_block_int = mixed_block_int ^ mixed_block_x_int

    keystream_block = mixed_block_int.to_bytes(od['block_src_size'], byteorder)

    if od['debug']:
        t1 = monotonic()
        print(f'{ITA}D: keystream block has been received '
              f'in {round(t1 - t0, 3)}s{END}')

    return keystream_block


def set_custom_options():
    """
    """
    custom = is_custom()
    print(f'{ITA}I: custom options: {custom}{END}')

    if custom:
        od['debug'] = is_debug()
        od['num_rounds'] = get_num_rounds()
        od['block_src_size'] = get_keystream_block_size()
        od['padding_order'] = get_padding_order()

        od['padding_max_percent'] = get_padding_max_percent()

        od['dk_len'] = get_dk_len()
        od['metadata_size'] = get_metadata_size()
    else:
        od['debug'] = False
        od['num_rounds'] = DEFAULT_NUM_ROUNDS
        od['block_src_size'] = DEFAULT_KEYSTREAM_BLOCK_SIZE
        od['padding_order'] = DEFAULT_PADDING_ORDER

        od['padding_max_percent'] = DEFAULT_PADDING_MAX_PERCENT

        od['dk_len'] = DEFAULT_DK_LEN
        od['metadata_size'] = DEFAULT_METADATA_SIZE

    od['salts_size'] = ONE_SALT_SIZE * 3 * od['num_rounds']
    od['salt_footer_size'] = od['salts_size'] // 2
    od['salt_header_size'] = od['salts_size'] - od['salt_footer_size']
    od['block_rip_size'] = int(
        (od['block_src_size'] / (MIN_KEYSTREAM_CHUNK_SIZE + (255 / 2))) * 1.05)
    od['block_mix_size'] = od['block_rip_size'] * MIX_BYTES_SIZE
    od['contents_block_size'] = od[
        'block_src_size'] - OUT_OF_CONTENTS_BLOCK_SIZE
    od['rk_keysream_size'] = (OUT_OF_CONTENTS_BLOCK_SIZE -
                              PADDING_KEYSTREAM_SIZE - MAC_KEYSTREAM_SIZE -
                              od['metadata_size'])
    od['padding_start_pos'] = od['contents_block_size']
    od['padding_fin_pos'] = od['padding_start_pos'] + PADDING_KEYSTREAM_SIZE
    od['mac_start_pos'] = od['padding_fin_pos']
    od['mac_fin_pos'] = od['mac_start_pos'] + MAC_KEYSTREAM_SIZE
    od['meta_start_pos'] = od['mac_fin_pos']
    od['meta_fin_pos'] = od['meta_start_pos'] + od['metadata_size']
    od['rk_start_pos'] = od['meta_fin_pos']
    od['rk_fin_pos'] = od['rk_start_pos'] + od['rk_keysream_size']


def get_file_size(f_path):
    """
    """
    try:
        with open(f_path, 'rb') as f:
            try:
                f.seek(0, 2)
            except Exception as e:
                print(f'{ERR}E: {e}{END}')
                return None
            try:
                position = f.tell()
            except Exception as e:
                print(f'{ERR}E: {e}{END}')
                return None
            return position
    except Exception as e:
        print(f'{ERR}E: {e}{END}')
        return None


def metadata_to_utf(md_bytes):
    """
    """
    md = md_bytes.partition(METADATA_DIV_BYTE)[0]

    try:
        return md.decode('utf-8')
    except UnicodeDecodeError:
        return None


def rand_bytes_to_rand_padding(rand_bytes, padding_order):
    """
    """
    int_rand_bytes = int.from_bytes(rand_bytes, byteorder='big')
    rand_max_variability = 256 ** len(rand_bytes)
    padding_variability = 2 ** padding_order
    divider = rand_max_variability // padding_variability
    rand_padding = int_rand_bytes // divider

    return rand_padding


def get_padding_size_from_msg(msg_size, rand_bytes, max_pad_percent):
    """
    """
    int_rand_bytes = int.from_bytes(rand_bytes, byteorder='big')
    rand_max_variability = 256 ** len(rand_bytes)

    padding_size = int_rand_bytes * msg_size * max_pad_percent // (
        rand_max_variability * 100)

    return padding_size


def get_padding_size_from_ppm(ppm_size, rand_bytes, max_pad_percent):
    """
    """
    int_rand_bytes = int.from_bytes(rand_bytes, byteorder='big')
    rand_max_variability = 256 ** len(rand_bytes)

    padding_size = (ppm_size * int_rand_bytes * max_pad_percent // (
        int_rand_bytes * max_pad_percent + rand_max_variability * 100))

    return padding_size


def hider_data_handler(mode, i_object, o_object, init_pos, data_size):
    """
    """
    if mode == 4:
        o_object.seek(init_pos)
        not_fsync_sum = 0
    else:
        i_object.seek(init_pos)

    m = blake2b(digest_size=HIDER_DIGEST_SIZE, person=BLAKE_PERSON_HIDER)

    T0 = monotonic()
    t0 = T0

    w_sum = 0

    num_chunks = data_size // RW_CHUNK_SIZE
    rem_size = data_size % RW_CHUNK_SIZE

    for _ in range(num_chunks):
        try:
            i_data = i_object.read(RW_CHUNK_SIZE)
            o_object.write(i_data)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            return None

        m.update(i_data)

        w_len = len(i_data)
        w_sum += w_len

        if mode == 4:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:

                try:
                    o_object.flush()
                    fsync(o_object.fileno())
                except OSError as e:
                    print(f'{ERR}E: {e}{END}')
                    return None

                not_fsync_sum = 0
                if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                    print_progress(w_sum, data_size, T0, fix='/fsynced')
                    t0 = monotonic()
        else:
            if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, data_size, T0, fix='')
                t0 = monotonic()

    try:
        i_data = i_object.read(rem_size)
        o_object.write(i_data)
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        return None

    m.update(i_data)

    w_len = len(i_data)
    w_sum += w_len

    if mode == 4:
        try:
            o_object.flush()
            fsync(o_object.fileno())
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            return None

        print_progress(w_sum, data_size, T0, fix='/fsynced')
    else:
        print_progress(w_sum, data_size, T0, fix='')

    message_checksum = m.hexdigest()

    final_pos = o_object.tell()

    if mode == 4:
        print(f'{ITA}Remember the following values to retrieve '
              f'the message correctly:')
        print(f'    Initial position: {init_pos}')
        print(f'    Final position: {final_pos}')
        print(f'    Message checksum: {message_checksum}{END}')
    else:
        print(f'{ITA}I: message checksum: {message_checksum}{END}')

    return True


def wiper_data_handler(o_object, init_pos, data_size):
    """
    """
    o_object.seek(init_pos)

    num_chunks = data_size // RW_CHUNK_SIZE
    rem_size = data_size % RW_CHUNK_SIZE

    print(f'{ITA}I: writing/fsyncing...{END}')

    fix = '/fsynced'

    w_sum = 0
    not_fsync_sum = 0

    T0 = monotonic()
    t0 = T0

    for _ in range(num_chunks):
        chunk = urandom(RW_CHUNK_SIZE)

        try:
            o_object.write(chunk)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            return None

        w_len = len(chunk)
        w_sum += w_len
        not_fsync_sum += w_len

        if not_fsync_sum >= MIN_FSYNC_SIZE:

            try:
                o_object.flush()
                fsync(o_object.fileno())
            except OSError as e:
                print(f'{ERR}E: {e}{END}')
                return None

            not_fsync_sum = 0

            if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, data_size, T0, fix=fix)
                t0 = monotonic()

    chunk = urandom(rem_size)

    try:
        o_object.write(chunk)
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        return None

    w_len = len(chunk)
    w_sum += w_len

    try:
        o_object.flush()
        fsync(o_object.fileno())
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        return None

    print_progress(w_sum, data_size, T0, fix=fix)
    return True


def cryptohider(mode):
    """
    """
    set_custom_options()

    final_pos = None  # for mode=6

    for_kdf_key_list_list = get_keys_for_kdf()

    if for_kdf_key_list_list is None:
        return None

    i_file, i_size, od['i'] = get_input_file(mode)
    print(f'{ITA}I: input file real path (in quotes):\n    "{i_file}"{END}')

    print(f'{ITA}I: input file size: {i_size} '
          f'bytes, {round(i_size / M, 1)} MiB{END}')

    if mode in (2, 6):
        message_size = i_size + od['metadata_size']
        min_cryptoblob_size = od['salts_size'] + message_size + MAC_SIZE
        max_header_padding_size = 2 ** od['padding_order'] - 1
        max_footer_padding_size = message_size * \
            od['padding_max_percent'] // 100

        max_cryptoblob_size = max_header_padding_size + \
            min_cryptoblob_size + max_footer_padding_size

        if od['debug']:
            print(f'{ITA}D: message_size: {message_size}')
            print(f'D: min_cryptoblob_size: {min_cryptoblob_size}')
            print(f'D: max_header_padding_size: {max_header_padding_size}')
            print(f'D: max_footer_padding_size: {max_footer_padding_size}')
            print(f'D: max_cryptoblob_size: {max_cryptoblob_size}{END}')

    min_possible_cryptoblob_size = od['salts_size'] + od[
        'metadata_size'] + MAC_SIZE

    if mode in (3, 7):
        if i_size < min_possible_cryptoblob_size:
            print(f'{ERR}E: invalid input values combination (is input '
                  f'file too small?){END}')
            od['i'].close()
            return None

    if mode in (2, 3):
        o_file, od['o'] = get_output_file_c(mode)

    elif mode == 6:
        o_file, o_size, od['o'] = get_output_file_w(
            i_file, max_cryptoblob_size, mode)

        max_init_pos = o_size - max_cryptoblob_size

    else:  # 7
        o_file, od['o'] = get_output_file_c(mode)
        max_init_pos = i_size - min_possible_cryptoblob_size

    print(f'{ITA}I: output file real path (in quotes):\n    "{o_file}"{END}')

    if mode == 6:
        print(f'{ITA}I: output file size: {o_size} '
              f'bytes, {round(o_size / M, 1)} MiB{END}')

    if mode in (6, 7):
        init_pos = get_init_pos(max_init_pos, fix=False)
        print(f'{ITA}I: initial position: {init_pos}{END}')

    if mode == 7:
        final_pos = get_final_pos(
            min_pos=init_pos + min_possible_cryptoblob_size,
            max_pos=i_size,
            fix=False)
        print(f'{ITA}I: final position: {final_pos}{END}')

    if mode in (2, 6):
        meta = get_metadata_bytes()

    if mode in (2, 6):
        MAC = get_mac()
        print(f'{ITA}I: add MAC: {MAC}{END}')
    else:  # 3, 5
        MAC = True

    if mode == 6:
        if not do_continue(fix=' with cryptoblob'):
            print(f'{ITA}I: stopped by user request{END}')
            od['i'].close()
            od['o'].close()
            return None

    if od['debug']:
        print(f'{ITA}D: user input received!{END}')
        print_positions()

    if mode == 6:
        od['o'].seek(init_pos)
    if mode == 7:
        od['i'].seek(init_pos)
    if mode in (6, 7):
        if od['debug']:
            print(f'{ITA}D: pointers set to initial positions{END}')
            print_positions()

    T0 = monotonic()
    t0 = T0

    w_sum = 0

    if mode == 6:
        not_fsync_sum = 0

    if od['debug']:
        print(f'{ITA}D: salts processing...{END}')

    salt_list_list = get_salt_list_list(i_size, final_pos, mode)

    if salt_list_list is None:
        return None  # OSError

    if od['debug']:
        print(f'{ITA}D: salts for KDF:{END}')
        eeprint(salt_list_list)

    salt_header, salt_footer = get_two_salts(salt_list_list)

    if mode in (2, 6):
        try:
            od['o'].write(salt_header)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        w_len = len(salt_header)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len

        if od['debug']:
            print(f'{ITA}D: salt_header is written{END}')
            print_positions()

    if od['debug']:
        print(f'{ITA}D: salts processing done{END}')

    if od['debug']:
        print(f'{ITA}D: getting first `round keys` with KDF{END}')

    rk_list_list = get_first_rk_list_list(
        for_kdf_key_list_list, salt_list_list)

    if od['debug']:
        print(f'{ITA}D: first `round keys`:{END}')
        eeprint(rk_list_list)

    if od['debug']:
        print(f'{ITA}D: getting first keystream block{END}')

    keystream_block_counter = 0
    keystream_block = get_keystream_block(rk_list_list)

    padding_keystream = keystream_block[
        od['padding_start_pos']:od['padding_fin_pos']]

    padding_keystream_start = padding_keystream[:PADDING_KEYSTREAM_SIZE // 2]

    rand_padding_start = rand_bytes_to_rand_padding(
        padding_keystream_start, od['padding_order'])

    if od['debug']:
        print(f'{ITA}D: rand_padding_start: {rand_padding_start}{END}')

    padding_keystream_fin = padding_keystream[-PADDING_KEYSTREAM_SIZE // 2:]

    if mode in (2, 6):
        rand_padding_fin = get_padding_size_from_msg(
            message_size,
            padding_keystream_fin,
            od['padding_max_percent'])

    else:  # 3, 7
        if mode == 3:
            ppm_size = i_size - od['salts_size'] - \
                rand_padding_start - MAC_SIZE
        else:  # 7
            ppm_size = (final_pos - init_pos - od['salts_size'] -
                        rand_padding_start - MAC_SIZE)

        rand_padding_fin = get_padding_size_from_ppm(
            ppm_size,
            padding_keystream_fin,
            od['padding_max_percent'])

    if od['debug']:
        print(f'{ITA}D: rand_padding_fin: {rand_padding_fin}{END}')

    if mode in (2, 6):
        contents_size = i_size
    elif mode == 3:
        contents_size = (i_size - od['salts_size'] - rand_padding_start -
                         rand_padding_fin - od['metadata_size'] - MAC_SIZE)
    else:  # 5
        contents_size = (final_pos - init_pos - od['salts_size'] -
                         rand_padding_start - rand_padding_fin -
                         od['metadata_size'] - MAC_SIZE)

    if od['debug']:
        print(f'{ITA}D: contents size: {contents_size}{END}')

    if mode in (2, 6):
        output_data_size = (od['salts_size'] + rand_padding_start + i_size +
                            od['metadata_size'] + MAC_SIZE + rand_padding_fin)
    else:  # 3, 5
        output_data_size = contents_size

    if od['debug']:
        print(f'{ITA}D: output data size: {output_data_size}{END}')

    if output_data_size < 0:
        print(f'{ITA}E: output data size: {output_data_size}{END}')
        od['i'].close()
        od['o'].close()
        return None

    if mode in (2, 6):
        p_num_blocks = rand_padding_start // RW_CHUNK_SIZE
        p_rem_size = rand_padding_start % RW_CHUNK_SIZE

        for _ in range(p_num_blocks):
            chunk = urandom(RW_CHUNK_SIZE)

            try:
                od['o'].write(chunk)
            except OSError as e:
                print(f'{ERR}E: {e}{END}')
                od['i'].close()
                od['o'].close()
                return None

            w_len = len(chunk)
            w_sum += w_len

            if mode == 6:
                not_fsync_sum += w_len
                if not_fsync_sum >= MIN_FSYNC_SIZE:

                    try:
                        od['o'].flush()
                        fsync(od['o'].fileno())
                    except OSError as e:
                        print(f'{ERR}E: {e}{END}')
                        od['i'].close()
                        od['o'].close()
                        return None

                    not_fsync_sum = 0
                    if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                        print_progress(
                            w_sum, output_data_size, T0, fix='/fsynced')
                        t0 = monotonic()
            else:
                if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                    print_progress(w_sum, output_data_size, T0, fix='')
                    t0 = monotonic()

        chunk = urandom(p_rem_size)

        try:
            od['o'].write(chunk)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        w_len = len(chunk)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:

                try:
                    od['o'].flush()
                    fsync(od['o'].fileno())
                except OSError as e:
                    print(f'{ERR}E: {e}{END}')
                    od['i'].close()
                    od['o'].close()
                    return None

                not_fsync_sum = 0
                if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                    print_progress(
                        w_sum, output_data_size, T0, fix='/fsynced')
                    t0 = monotonic()
        else:
            if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, output_data_size, T0, fix='')
                t0 = monotonic()

    else:  # 3, 5
        od['i'].seek(rand_padding_start, 1)

    if od['debug']:
        print(f'{ITA}D: random padding header has been handled{END}')
        print_positions()

    if MAC:
        mac_key1 = keystream_block[
            od['mac_start_pos']:od['mac_fin_pos']
        ][:MAC_SIZE]

        if od['debug']:
            print(f'{ITA}D: mac_key1 (key for keyed hashing)'
                  f': {mac_key1.hex()}{END}')

        mac_m = blake2b(
            digest_size=MAC_SIZE,
            key=mac_key1,
            person=BLAKE_PERSON_MAC)

        mac_m.update(salt_header)
        mac_m.update(salt_footer)

    if od['debug']:
        print(f'{ITA}D: handling input file contents...{END}')

    num_blocks = contents_size // od['contents_block_size']
    rem_size = contents_size % od['contents_block_size']

    for _ in range(num_blocks):
        if keystream_block_counter > 0:
            keystream_block = get_keystream_block(rk_list_list)

        keystream_block_counter += 1
        rk_keystream = keystream_block[od['rk_start_pos']:od['rk_fin_pos']]
        rk_list_list = get_updated_rk_list_list(rk_list_list, rk_keystream)

        try:
            input_block = od['i'].read(od['contents_block_size'])
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        output_block = xor(input_block, keystream_block)
        try:
            od['o'].write(output_block)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        w_len = len(output_block)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:

                try:
                    od['o'].flush()
                    fsync(od['o'].fileno())
                except OSError as e:
                    print(f'{ERR}E: {e}{END}')
                    od['i'].close()
                    od['o'].close()
                    return None

                not_fsync_sum = 0
                if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                    print_progress(
                        w_sum, output_data_size, T0, fix='/fsynced')
                    t0 = monotonic()
        else:
            if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, output_data_size, T0, fix='')
                t0 = monotonic()

        if od['debug']:
            print(f'{ITA}D: contents block has been written; its '
                  f'size: { len(output_block)}{END}')
            print_positions()

        if MAC:
            if mode in (2, 6):
                mac_m.update(output_block)
            else:
                mac_m.update(input_block)

    if keystream_block_counter > 0:
        keystream_block = get_keystream_block(rk_list_list)

    keystream_block_counter += 1

    try:
        input_block = od['i'].read(rem_size)
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        od['i'].close()
        od['o'].close()
        return None

    output_block = xor(input_block, keystream_block)

    try:
        od['o'].write(output_block)
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        od['i'].close()
        od['o'].close()
        return None

    w_len = len(output_block)
    w_sum += w_len

    if mode == 6:
        not_fsync_sum += w_len
        if not_fsync_sum >= MIN_FSYNC_SIZE:

            try:
                od['o'].flush()
                fsync(od['o'].fileno())
            except OSError as e:
                print(f'{ERR}E: {e}{END}')
                od['i'].close()
                od['o'].close()
                return None

            not_fsync_sum = 0
            if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                print_progress(
                    w_sum, output_data_size, T0, fix='/fsynced')
                t0 = monotonic()
    else:
        if monotonic() - t0 >= MIN_PRINT_INTERVAL:
            print_progress(w_sum, output_data_size, T0, fix='')
            t0 = monotonic()

    if od['debug']:
        print(
            f'{ITA}D: last contents block has been written; its '
            f'size: {len(output_block)}{END}')
        print_positions()

    if MAC:
        if mode in (2, 6):
            mac_m.update(output_block)
        else:
            mac_m.update(input_block)

        if od['debug']:
            print(f'{ITA}D: file contents hashed{END}')

    if od['debug']:
        print(f'{ITA}D: handling metadata...{END}')

    if mode in (3, 7):
        try:
            # encrypted metadata
            meta = od['i'].read(od['metadata_size'])
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

    meta_keystream = keystream_block[od['meta_start_pos']:od['meta_fin_pos']]
    meta_out = xor(meta, meta_keystream)

    if od['debug']:
        print(f'{ITA}D: metadata (binary) found in plain and encrypted '
              f'forms{END}')

    if mode in (2, 6):
        try:
            od['o'].write(meta_out)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        w_len = len(meta_out)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len

        if od['debug']:
            print(f'{ITA}D: encrypted metadata written; its '
                  f'size: {len(meta_out)}{END}')
    else:  # 3, 5
        meta_utf = metadata_to_utf(meta_out)
        print(f'{ITA}I: metadata (could be faked): {[meta_utf]}{END}')

    if MAC:
        if mode in (2, 6):
            mac_m.update(meta_out)
        else:  # 3, 7
            mac_m.update(meta)

    if od['debug']:
        print(f'{ITA}D: metadata has been handled{END}')
        print_positions()

    if od['debug']:
        print(f'{ITA}D: handling MAC...{END}')

    if MAC:
        found_mac = mac_m.digest()
        if od['debug']:
            print(f'{ITA}D: MAC found (keyed digest of salts and encrypted '
                  f'message): {found_mac.hex()}{END}')

        mac_key2 = keystream_block[
            od['mac_start_pos']:od['mac_fin_pos']
        ][-MAC_SIZE:]

        if od['debug']:
            print(f'{ITA}D: mac_key2 (keystream for encrypting MAC)'
                  f': {mac_key2.hex()}{END}')

        encrypted_mac = xor(found_mac, mac_key2)
        if od['debug']:
            print(f'{ITA}D: encrypted MAC found: {encrypted_mac.hex()}{END}')

    if mode in (2, 6):
        if MAC:
            try:
                od['o'].write(encrypted_mac)
            except OSError as e:
                print(f'{ERR}E: {e}{END}')
                od['i'].close()
                od['o'].close()
                return None

            w_len = len(encrypted_mac)
            w_sum += w_len

            if mode == 6:
                not_fsync_sum += w_len

            if od['debug']:
                print(f'{ITA}D: encrypted MAC has been written; its size'
                      f': {len(encrypted_mac)}{END}')
        else:
            fake_mac = urandom(MAC_SIZE)
            try:
                od['o'].write(fake_mac)
            except OSError as e:
                print(f'{ERR}E: {e}{END}')
                od['i'].close()
                od['o'].close()
                return None

            w_len = len(fake_mac)
            w_sum += w_len

            if mode == 6:
                not_fsync_sum += w_len

            if od['debug']:
                print(f'{ITA}D: fake MAC has been written'
                      f': {fake_mac.hex()}{END}')
    else:  # 3, 5
        try:
            read_mac = od['i'].read(MAC_SIZE)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        if od['debug']:
            print(f'D: read MAC: {read_mac.hex()}')

        if encrypted_mac == read_mac:
            print(f'{ITA}I: MAC is valid: True{END}')
        else:
            print(f'{ITA}I: MAC is valid: False{END}')

    if od['debug']:
        print(f'{ITA}D: MAC has been handled{END}')
        print_positions()

    if od['debug']:
        print(f'{ITA}D: total keystream_block_counter'
              f': {keystream_block_counter}{END}')

        print(f'{ITA}D: handling padding footer{END}')

    if mode in (2, 6):
        p_num_blocks = rand_padding_fin // M
        p_rem_size = rand_padding_fin % M
        for _ in range(p_num_blocks):

            chunk = urandom(RW_CHUNK_SIZE)

            try:
                od['o'].write(chunk)
            except OSError as e:
                print(f'{ERR}E: {e}{END}')
                od['i'].close()
                od['o'].close()
                return None

            w_len = len(chunk)
            w_sum += w_len

            if mode == 6:
                not_fsync_sum += w_len
                if not_fsync_sum >= MIN_FSYNC_SIZE:

                    try:
                        od['o'].flush()
                        fsync(od['o'].fileno())
                    except OSError as e:
                        print(f'{ERR}E: {e}{END}')
                        od['i'].close()
                        od['o'].close()
                        return None

                    not_fsync_sum = 0
                    if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                        print_progress(
                            w_sum, output_data_size, T0, fix='/fsynced')
                        t0 = monotonic()
            else:
                if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                    print_progress(w_sum, output_data_size, T0, fix='')
                    t0 = monotonic()

        chunk = urandom(p_rem_size)

        try:
            od['o'].write(chunk)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        w_len = len(chunk)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:

                try:
                    od['o'].flush()
                    fsync(od['o'].fileno())
                except OSError as e:
                    print(f'{ERR}E: {e}{END}')
                    od['i'].close()
                    od['o'].close()
                    return None

                not_fsync_sum = 0
                if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                    print_progress(
                        w_sum, output_data_size, T0, fix='/fsynced')
                    t0 = monotonic()
        else:
            if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, output_data_size, T0, fix='')
                t0 = monotonic()

    else:  # 3, 5
        od['i'].seek(rand_padding_fin, 1)

    if od['debug']:
        print(f'{ITA}D: random padding footer has been handled{END}')
        print_positions()

    if mode in (2, 6):
        if od['debug']:
            print(f'{ITA}D: handling salt_footer...{END}')

        try:
            od['o'].write(salt_footer)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            od['i'].close()
            od['o'].close()
            return None

        w_len = len(salt_footer)
        w_sum += w_len

        if mode == 6:

            try:
                od['o'].flush()
                fsync(od['o'].fileno())
            except OSError as e:
                print(f'{ERR}E: {e}{END}')
                od['i'].close()
                od['o'].close()
                return None

            print_progress(w_sum, output_data_size, T0, fix='/fsynced')
        else:
            print_progress(w_sum, output_data_size, T0, fix='')

        if od['debug']:
            print(f'{ITA}D: salt_footer is written{END}')
            print_positions()

        if mode == 6:
            final_pos = od['o'].tell()
            print(
                f'{ITA}Remember the positions of the cryptoblob in the '
                f'container:{END}')
            print(f'    {ITA}Initial/Final:  {init_pos}/{final_pos}{END}')

    if mode in (3, 7):
        print_progress(w_sum, output_data_size, T0, fix='')

    if od['debug']:
        print(f'{ITA}D: written {w_sum} bytes{END}')
        print(f'{ITA}D: output data size: {output_data_size}{END}')

    if w_sum != output_data_size:
        print(f'{ITA}E: the size of the written data does not match '
              f'the expected size{END}')
        od['i'].close()
        od['o'].close()
        return None

    od['i'].close()
    od['o'].close()
    return True


def hider(mode):
    """
    """
    i_file, i_size, i_object = get_input_file(mode)
    print(f'{ITA}I: input file real path (in quotes):\n    "{i_file}"{END}')
    print(f'{ITA}I: input file size: {i_size} '
          f'bytes, {round(i_size / M, 1)} MiB{END}')

    if mode == 4:
        o_file, o_size, o_object = get_output_file_w(i_file, i_size, mode)
        max_init_pos = o_size - i_size
    else:
        o_file, o_object = get_output_file_c(mode)
        max_init_pos = i_size - 1

    print(f'{ITA}I: output file real path (in quotes):\n    "{o_file}"{END}')

    if mode == 4:
        print(
            f'{ITA}I: output file size: {o_size} bytes'
            f', {round(o_size / M, 1)} MiB{END}')

    init_pos = get_init_pos(max_init_pos, fix=False)
    print(f'{ITA}I: initial position: {init_pos}{END}')

    if mode == 4:
        data_size = i_size
        final_pos = init_pos + data_size
        print(f'{ITA}I: final position: {final_pos}{END}')

        if not do_continue(fix=' with input file'):
            print(f'{ITA}I: stopped by user request{END}\n')
            i_object.close()
            o_object.close()
            return None
    else:
        final_pos = get_final_pos(min_pos=init_pos, max_pos=i_size, fix=False)
        print(f'{ITA}I: final position: {final_pos}{END}')
        data_size = final_pos - init_pos
        print(f'{ITA}I: data size to retrieve: {data_size}{END}')

    if mode == 4:
        print(f'{ITA}I: reading, writing, fsyncing...{END}')
    else:
        print(f'{ITA}I: reading, writing...{END}')

    ok = hider_data_handler(mode, i_object, o_object, init_pos, data_size)

    i_object.close()
    o_object.close()

    if ok:
        return True

    return None


def randgen(mode):
    """
    """
    o_file, o_object = get_output_file_c(mode)
    print(f'{ITA}I: output file real path (in quotes):\n    "{o_file}"{END}')

    o_size = get_output_file_size()
    print(f'{ITA}I: output file size: {o_size} bytes'
          f', {round(o_size / M, 1)} MiB{END}')

    num_chunks = o_size // RW_CHUNK_SIZE
    rem_size = o_size % RW_CHUNK_SIZE

    print(f'{ITA}I: writing data...{END}')

    fix = ''

    T0 = monotonic()
    t0 = T0

    w_sum = 0

    for _ in range(num_chunks):
        chunk = urandom(RW_CHUNK_SIZE)

        try:
            o_object.write(chunk)
        except OSError as e:
            print(f'{ERR}E: {e}{END}')
            o_object.close()
            return None

        w_len = len(chunk)
        w_sum += w_len

        if monotonic() - t0 >= MIN_PRINT_INTERVAL:
            print_progress(w_sum, o_size, T0, fix)
            t0 = monotonic()

    chunk = urandom(rem_size)

    try:
        o_object.write(chunk)
    except OSError as e:
        print(f'{ERR}E: {e}{END}')
        o_object.close()
        return None

    w_len = len(chunk)
    w_sum += w_len

    print_progress(w_sum, o_size, T0, fix)
    o_object.close()
    return True


def wiper(mode):
    """
    """
    o_file, o_size, o_object = get_output_file_w(
        i_file='', i_size=0, mode=mode)
    print(f'{ITA}I: output file real path (in quotes):\n    "{o_file}"{END}')
    print(f'{ITA}I: output file size: {o_size} bytes'
          f', {round(o_size / M, 1)} MiB{END}')

    if o_size == 0:
        print(f'{ITA}I: nothing to overwrite{END}')
        return None

    init_pos = get_init_pos(max_init_pos=o_size, fix=True)
    print(f'{ITA}I: initial position: {init_pos}{END}')

    if init_pos == o_size:
        print(f'{ITA}I: nothing to overwrite{END}')
        return None

    final_pos = get_final_pos(min_pos=init_pos, max_pos=o_size, fix=True)
    print(f'{ITA}I: final position: {final_pos}{END}')

    data_size = final_pos - init_pos
    print(f'{ITA}I: data size to write: {data_size} bytes'
          f', {round(data_size / M, 1)} MiB{END}')

    if data_size == 0:
        print(f'{ITA}I: nothing to overwrite{END}')
        return None

    if not do_continue(fix=' with random bytes'):
        print(f'{ITA}I: stopped by user request{END}')
        o_object.close()
        return None

    ok = wiper_data_handler(o_object, init_pos, data_size)
    o_object.close()

    if ok:
        return True

    return None


def signal_handler(signum, frame):
    """
    """
    print(f'\n{ERR}E: got signal {signum}{END}')
    exit(1)


def main():
    """
    """
    signal(SIGINT, signal_handler)

    while True:
        mode = get_mode()

        ok = None

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

        else:  # mode == 9
            ok = wiper(mode)

        if ok:
            print(f'{OK}OK{END}')

        od.clear()


od = {}

K = 2**10
M = 2**20

BLAKE_DIGEST_SIZE = 64

BLAKE_PERSON_KEYFILE = b'KEYFILE'
BLAKE_PERSON_PASSPHRASE = b'PASSPHRASE'
BLAKE_PERSON_BASIC_KEY = b'BASIC_KEY'
BLAKE_PERSON_EQUAL_BLOCK = b'EQUAL_BLOCK'
BLAKE_PERSON_ROUND_KEY = b'ROUND_KEY'
BLAKE_PERSON_MAC = b'MAC'
BLAKE_PERSON_HIDER = b'HIDER'

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

RW_CHUNK_SIZE = M
MIN_PRINT_INTERVAL = 5
MIN_FSYNC_SIZE = M * 256
HIDER_DIGEST_SIZE = 20

ONE_SALT_SIZE = 32

MIN_KEYSTREAM_CHUNK_SIZE = 128

MIX_BYTES_SIZE = 4

OUT_OF_CONTENTS_BLOCK_SIZE = 32 * K

PADDING_KEYSTREAM_SIZE = 20

MAX_PADDING_ORDER = PADDING_KEYSTREAM_SIZE << 2

DEFAULT_PADDING_ORDER = 8

DEFAULT_PADDING_MAX_PERCENT = 20

MAC_SIZE = 64
MAC_KEYSTREAM_SIZE = MAC_SIZE * 2

DEFAULT_NUM_ROUNDS = 1

DEFAULT_KEYSTREAM_BLOCK_SIZE_M = 32
DEFAULT_KEYSTREAM_BLOCK_SIZE = DEFAULT_KEYSTREAM_BLOCK_SIZE_M * M

DEFAULT_DK_LEN_M = 4
DEFAULT_DK_LEN = DEFAULT_DK_LEN_M * M

DEFAULT_METADATA_SIZE = 512
MAX_METADATA_SIZE = 16 * K

METADATA_DIV_BYTE = b'\xff'

WIN32 = bool(platform == 'win32')

END = BOL = ITA = ERR = OK = WAR = ''

if not WIN32:
    END = '\033[0m'
    BOL = '\033[1m'  # bold
    ITA = '\033[3m'  # italic
    ERR = '\033[1;3;97;101m'  # bold italic white text, red bg
    OK = '\033[1;32m'  # bold green

MENU = f"""
                        {BOL}MENU{END}
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    0. Exit               1. Get info
    2. Encrypt            3. Decrypt
    4. Hide               5. Unhide
    6. Encrypt and hide   7. Unhide and decrypt
    8. Create w/ urandom  9. Overwrite w/ urandom
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{BOL}Please enter [0-9]:{END} """

INFO = f'{ITA}I: tird is a tool for encrypting and hiding file contents ' \
    f'among random data\nI: more info: https://github.com/hakavlad/tird{END}'

if __name__ == '__main__':
    main()
