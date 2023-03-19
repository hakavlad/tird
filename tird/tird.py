#!/usr/bin/env python3

from getpass import getpass
from hashlib import blake2b, scrypt, shake_256
from operator import itemgetter
from os import fsync, path, urandom, walk
from signal import SIGINT, signal
from sys import byteorder, exit
from time import monotonic


def signal_handler(signum, frame):
    """
    """
    print('\nE: got signal {}'.format(signum))
    exit(1)


def print_positions():
    """
    """
    ift = od['i'].tell()
    oft = od['o'].tell()
    print('Positions: if={}, of={}'.format(ift, oft))


def eprint(i_list):
    """
    """
    for i in i_list:
        print(' ', i)


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


def blake2b_digest(data):
    """
    """
    m = blake2b(digest_size=BLAKE_DIGEST_SIZE)
    m.update(data)
    return m.digest()


def blake2b_file_digest(f_object, f_size):
    """
    """
    m = blake2b(digest_size=BLAKE_DIGEST_SIZE)

    n = f_size // M
    r = f_size % M

    try:
        for _ in range(n):
            data = f_object.read(M)
            m.update(data)
        data = f_object.read(r)
        m.update(data)
    except OSError as e:
        print(e)
        return None

    return m.digest()


def get_file_size(f_path):
    """
    """
    try:
        with open(f_path, 'rb') as f:
            try:
                f.seek(0, 2)
            except Exception as e:
                print(e)
                return None
            try:
                position = f.tell()
            except Exception as e:
                print(e)
                return None
            return position
    except Exception as e:
        print(e)
        return None


def get_input_file(mode):
    """
    """
    if mode == 2:
        i = 'Read from (file to encrypt): '
    elif mode == 3:
        i = 'Read from (file to decrypt): '
    elif mode == 4:
        i = 'Read from (file to encrypt and hide): '
    elif mode in (5, 7):
        i = 'Read from (container): '
    elif mode == 6:
        i = 'Read from (file to hide): '
    else:
        print('E: invalid mode')
        exit(1)

    while True:
        i_file = input(i)

        if i_file == '':
            print('E: input file is not set')
            continue

        i_file = path.realpath(i_file)
        i_size = get_file_size(i_file)
        if i_size is None:
            continue

        try:
            i_object = open(i_file, 'rb')
            break
        except Exception as e:
            print('E: {}'.format(e))

    return i_file, i_size, i_object


def get_output_file_c(mode):
    """
    """
    if mode == 2:
        i = 'Write to (encrypted file): '
    elif mode in (3, 5):
        i = 'Write to (decrypted file): '
    elif mode in (7, 8):
        i = 'Write to (output file): '
    else:
        print('E: invalid mode')
        exit(1)

    while True:
        o_file = input(i)

        if o_file == '':
            print('E: output file is not set')
            continue

        o_file = path.realpath(o_file)
        if path.exists(o_file):
            print('E: this file already exists')
            continue

        try:
            o_object = open(o_file, 'wb')
            break
        except Exception as e:
            print('E: {}'.format(e))

    return o_file, o_object


def get_output_file_w(i_file, i_size, mode):
    """
    """
    if mode == 4:
        i = 'Write over (container): '
    elif mode == 6:
        i = 'Write over (container): '
    elif mode == 9:
        i = 'Write over (file to overwrite): '
    else:
        print('E: invalid mode')
        exit(1)

    while True:
        o_file = input(i)

        if o_file == '':
            print('E: output file is not set')
            continue

        o_size = get_file_size(o_file)
        if o_size is None:
            continue

        o_file = path.realpath(o_file)

        if o_file == i_file:
            print('E: input and output files should not be at the same path!')
            continue

        if o_size < i_size:
            print('E: output file must be not smaller than input file')
            continue

        try:
            o_object = open(o_file, 'rb+')
            break
        except Exception as e:
            print(e)
            continue

    return o_file, o_size, o_object


def get_init_pos(max_init_pos, fix):
    """
    """
    while True:
        if fix:
            init_pos = input('Initial position, default=0,\n'
                             '    valid values are [0; {}]: '.format(
                                 max_init_pos))
            if init_pos == '':
                init_pos = 0
        else:
            init_pos = input('Initial position, valid values are '
                             '[0; {}]: '.format(
                                 max_init_pos))
            if init_pos == '':
                print('E: initial position is not set')
                continue

        try:
            init_pos = int(init_pos)
        except Exception:
            print('E: invalid value')
            continue

        if init_pos > max_init_pos or init_pos < 0:
            print('E: invalid initial position')
            continue

        return init_pos


def get_final_pos(min_pos, max_pos, fix):
    """
    """
    while True:
        if fix:
            final_pos = input('Final position, default={},\n'
                              '    valid values are [{}; {}]: '.format(
                                  max_pos, min_pos, max_pos))
            if final_pos == '':
                final_pos = max_pos
        else:
            final_pos = input('Final position, valid values are '
                              '[{}; {}]: '.format(min_pos, max_pos))

        try:
            final_pos = int(final_pos)
        except Exception:
            print('E: invalid value')
            continue

        if final_pos < min_pos or final_pos > max_pos:
            print('E: invalid value')
            continue

        return final_pos


def get_metadata_bytes():
    """
    """
    meta_utf = input('Metadata (optional, up to {} bytes): '.format(
        od['metadata_size']))
    if meta_utf == '':
        m_bytes = urandom(od['metadata_size'])
    else:
        m_bytes = meta_utf.encode()
        m_bytes = m_bytes[:od['metadata_size']]
        m_bytes = m_bytes.ljust(od['metadata_size'], b' ')
    if meta_utf != '':
        print('I: metadata as it will be shown:', metadata_to_utf(m_bytes))
    return m_bytes


def get_mac():
    """
    """
    while True:
        add_mac = input('Add MAC (0|1): ')
        if add_mac in ('', '0', '1'):
            break
        print('E: invalid value')
        continue

    if add_mac in ('', '0'):
        return False

    return True


def show_metadata():
    """
    """
    while True:
        show_meta = input('Show metadata (1|0): ')
        if show_meta in ('', '0', '1'):
            break
        print('E: invalid value')
        continue

    if show_meta in ('', '1'):
        return True

    return False


def get_output_file_size():
    """
    """
    while True:
        o_size = input('Output file size in bytes: ')

        if o_size == '':
            print('E: output file is not set')
            continue

        try:
            o_size = int(o_size)
        except Exception as e:
            print(e)
            continue

        return o_size


def do_continue(fix):
    """
    """
    while True:
        do_cont = input('Output file will be (partially) overwritten{}.\n'
                        'Do you want to continue? (y|n): '.format(fix))
        if do_cont in ('y', 'Y'):
            return True
        if do_cont in ('n', 'N'):
            return False


def ow_by_random():
    """
    """
    a = """Overwrite with
1 - random bytes (default)
2 - specific bytes
: """

    while True:
        b = input(a)

        if b not in ('', '1', '2'):
            print('E: invalid input')
            continue

        if b in ('', '1'):
            return True

        return False


def get_ow_byte():
    """
    """
    a = 'Byte value (a number from the range [0; 255]): '

    while True:
        b = input(a)

        try:
            b = int(b)
        except ValueError:
            print('E: invalid input')
            continue

        if b < 0 or b > 255:
            print('E: invalid input')
            continue

        return b


def wiper_data_handler(o_object, init_pos, data_size, owbr, ow_byte):
    """
    """
    o_object.seek(init_pos)

    num_chunks = data_size // CHUNK_SIZE
    rem_size = data_size % CHUNK_SIZE

    if not owbr and num_chunks >= 1:
        ow_chunk = ow_byte * CHUNK_SIZE

    print('I: writing/fsyncing...')

    fix = '/fsynced'

    w_sum = 0
    not_fsync_sum = 0

    T0 = monotonic()
    t0 = T0

    for _ in range(num_chunks):
        if owbr:
            chunk = urandom(CHUNK_SIZE)
        else:
            chunk = ow_chunk

        try:
            o_object.write(chunk)
        except OSError as e:
            print(e)
            print()
            return 1

        w_len = len(chunk)
        w_sum += w_len
        not_fsync_sum += w_len

        if not_fsync_sum >= MIN_FSYNC_SIZE:
            o_object.flush()
            fsync(o_object.fileno())
            not_fsync_sum = 0

            if monotonic() - t0 >= MIN_PRINT_INTERVAL:
                print_progress(w_sum, data_size, T0, fix=fix)
                t0 = monotonic()

    if owbr:
        chunk = urandom(rem_size)
    else:
        chunk = ow_byte * rem_size

    try:
        o_object.write(chunk)
    except OSError as e:
        print(e)
        print()
        return 1

    w_len = len(chunk)
    w_sum += w_len

    o_object.flush()
    fsync(o_object.fileno())

    print_progress(w_sum, data_size, T0, fix=fix)


def hider_data_handler(mode, i_object, o_object, init_pos, data_size):
    """
    """
    if mode == 6:
        o_object.seek(init_pos)
        not_fsync_sum = 0
    else:
        i_object.seek(init_pos)

    m = blake2b(digest_size=HIDER_DIGEST_SIZE)

    T0 = monotonic()
    t0 = T0

    w_sum = 0

    num_chunks = data_size // CHUNK_SIZE
    rem_size = data_size % CHUNK_SIZE

    for _ in range(num_chunks):

        try:
            i_data = i_object.read(CHUNK_SIZE)
        except OSError as e:
            print(e)
            return 1

        try:
            o_object.write(i_data)
        except OSError as e:
            print(e)
            return 1

        m.update(i_data)

        w_len = len(i_data)
        w_sum += w_len

        if mode == 6:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:
                o_object.flush()
                fsync(o_object.fileno())
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
    except OSError as e:
        print(e)
        return 1

    try:
        o_object.write(i_data)
    except OSError as e:
        print(e)
        return 1

    m.update(i_data)

    w_len = len(i_data)
    w_sum += w_len

    if mode == 6:
        o_object.flush()
        fsync(o_object.fileno())
        print_progress(w_sum, data_size, T0, fix='/fsynced')
    else:
        print_progress(w_sum, data_size, T0, fix='')

    message_checksum = m.hexdigest()

    if mode == 6:
        print('Remember these values to retrieve the message from '
              'the container in the future:')
        print('    Initial position: {}, Final position: {}'.format(
            init_pos, o_object.tell()))

    print('Message checksum:', message_checksum)


def print_progress(written_sum, data_size, T0, fix):
    """
    """
    if data_size == 0:
        print('I: written 0 bytes')
        return

    t = monotonic() - T0
    if t > 0:
        print('I: written{} {} bytes, {} MiB, {}% in {}s, avg {} '
              'MiB/s'.format(
                  fix,
                  written_sum,
                  round(written_sum / M, 1),
                  round(written_sum / data_size * 100, 1),
                  round(t, 1),
                  round(written_sum / M / t, 1)))
    else:
        print('I: written{} {} bytes, {} MiB, {}% in {}s'.format(
            fix,
            written_sum,
            round(written_sum / M, 1),
            round(written_sum / data_size * 100, 1),
            round(t, 1)))


def metadata_to_utf(m):
    """
    """
    return [m.decode('utf-8', 'ignore').rstrip()]


def rand_bytes_to_padding(rand_bytes):
    """
    """
    int_rand_bytes = int.from_bytes(
        rand_bytes, byteorder='big')

    rand_max_var = 256 ** len(rand_bytes)
    padding_var = 2 ** od['padding_order']
    divider = rand_max_var // padding_var
    rand_padding = int_rand_bytes // divider
    return rand_padding


def get_salt_list_list(i_size, final_pos, mode):
    """
    """
    salt_list_list = []

    if mode in (2, 4):
        for _ in range(od['num_rounds']):
            salt_list = []
            for _ in range(3):
                salt_list.append(urandom(SALT_SIZE))
            salt_list_list.append(salt_list)
    elif mode in (3, 5):
        try:
            salts_start = od['i'].read(od['salts_start_size'])
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()

            return

        if od['debug']:
            print('')
            print_positions()

        cur_pos = od['i'].tell()

        if mode == 3:
            new_pos = i_size - od['salts_fin_size']
        else:
            new_pos = final_pos - od['salts_fin_size']

        try:
            od['i'].seek(new_pos)
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()

            return

        if od['debug']:
            print('')
            print_positions()

        try:
            salts_fin = od['i'].read(od['salts_fin_size'])
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()
            return

        if od['debug']:
            print('')
            print_positions()

        od['i'].seek(cur_pos)

        if od['debug']:
            print('')
            print_positions()

        y_list = []

        c = 0
        for i in range(od['salts_size']):
            # print(i, c)

            if i % 2 == 0:
                y_list.append(salts_start[c:c + 1])
            else:
                y_list.append(salts_fin[c:c + 1])
                c += 1

        salts = b''.join(y_list)

        z_list = []

        start, fin = 0, SALT_SIZE

        for i in range(od['num_rounds'] * 3):
            z_list.append(salts[start:fin])
            start, fin = start + SALT_SIZE, fin + SALT_SIZE

        salt_list_list = []

        start, fin = 0, 3
        for i in range(od['num_rounds']):
            salt_list_list.append(z_list[start:fin])
            start, fin = start + 3, fin + 3
    else:
        print('E: unexpected mode')
        exit(1)

    return salt_list_list


def get_two_salts(salt_list_list):
    """
    """
    s_list = []

    for salt_list in salt_list_list:
        s_list.extend(salt_list)

    salts = b''.join(s_list)
    salts_len = len(salts)

    salts_start_list = []
    salts_fin_list = []

    for i in range(salts_len):
        b = salts[i:i + 1]

        if i % 2 == 0:
            salts_start_list.append(b)
        else:
            salts_fin_list.append(b)

    salts_start = b''.join(salts_start_list)
    salts_fin = b''.join(salts_fin_list)

    return salts_start, salts_fin


def get_first_rk_list_list(for_kdf_key_list_list, salt_list_list):
    """
    """
    rk_list_list = []

    for i in range(od['num_rounds']):

        if od['debug']:
            print('\nKeys derivation {}/{}...'.format(i + 1, od['num_rounds']))

        salt_list = salt_list_list[i]
        key_list = for_kdf_key_list_list[i]

        if od['debug']:
            print('')
            eprint(salt_list)

            print('', )
            eprint(key_list)

        # print()

        dk_digest_list = []

        for i2 in range(3):

            if od['debug']:
                print('Get new dk...')

            salt = salt_list[i2]

            if od['debug']:
                print('  ', salt)

            key = key_list[i2]

            if od['debug']:
                print('  ', key)

            dk = scrypt(key, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, dklen=od['dk_len'])

            dk_digest = blake2b_digest(dk)

            if od['debug']:
                print('  dk_digest', dk_digest)

            dk_digest_list.append(dk_digest)

        rk_list_list.append(dk_digest_list)

    return rk_list_list


def get_updated_rk_list_list(rk_list_list, keystream_chunk):
    """
    """
    new_rk_list_list = []

    for rk_list in rk_list_list:
        new_rk_list = []
        for rk in rk_list:
            new_rk = blake2b_digest(rk + keystream_chunk)
            new_rk_list.append(new_rk)
        new_rk_list_list.append(new_rk_list)

    if od['debug']:
        print('old rk_list_list:')
        eprint(rk_list_list)
        print('new rk_list_list:')
        eprint(new_rk_list_list)

    return new_rk_list_list


def get_keystream_block(rk_list_list):
    """
    """

    if od['debug']:
        print()
        print('')

        t0 = monotonic()

    rk_list = rk_list_list[0]
    mixed_block = get_mixed_block(rk_list)

    if od['num_rounds'] == 1:
        if od['debug']:
            print('')
            t1 = monotonic()
            t = t1 - t0
            print('t', t)
        return mixed_block

    mixed_block_int = int.from_bytes(mixed_block, byteorder)

    for rk_list in rk_list_list[1:]:
        mixed_block_x = get_mixed_block(rk_list)
        mixed_block_x_int = int.from_bytes(mixed_block_x, byteorder)

        mixed_block_int = mixed_block_int ^ mixed_block_x_int

    keystream_block = mixed_block_int.to_bytes(od['block_size'], byteorder)

    if od['debug']:
        print('')
        t1 = monotonic()
        t = t1 - t0
        print('t', t)

    return keystream_block


def get_mixed_block(rk_list):
    """
    """
    block = shake_256_digest(rk_list[0], od['block_size'])
    block_tear = shake_256_digest(rk_list[1], od['block_tear_size'])
    block_mix = shake_256_digest(rk_list[2], od['block_mix_size'])

    chunks_dict = {}
    block_mix_position = 0
    byte_num = 0
    read_pos = 0

    while True:
        rnd = block_tear[byte_num] + MIN_CHUNK_SIZE
        rnd_chunk = block[read_pos:read_pos + rnd]

        if not rnd_chunk:
            break

        read_pos += rnd
        byte_num += 1

        while True:
            new_pos = block_mix_position + MIX_BYTES_SIZE
            mix_bytes = block_mix[block_mix_position:new_pos]
            block_mix_position = new_pos

            if mix_bytes not in chunks_dict:
                chunks_dict[mix_bytes] = rnd_chunk
                break

    if od['debug']:
        print('sorting {} chunks...'.format(len(chunks_dict)))

    sorted_list = sorted(chunks_dict.items(), key=itemgetter(0))

    rnd_list = []
    for rnd_chunk in sorted_list:
        rnd_list.append(rnd_chunk[1])

    mixed_block = b''.join(rnd_list)

    return mixed_block


def pp_to_list(pp):
    """
    """
    pp = pp.encode()
    pp_len = len(pp)
    pp_digest = blake2b_digest(pp)
    return [True, None, pp, pp_len, pp_digest]


def keyfile_to_list(f_path):
    """
    """
    f_size = get_file_size(f_path)

    if f_size is None:
        return None

    print('I: keyfile size: {} bytes, real path: "{}"'.format(f_size, f_path))
    print('I: hashing the keyfile...')

    if f_size > 0:
        with open(f_path, 'rb') as f:
            f_digest = blake2b_file_digest(f, f_size)
        if f_digest is None:
            return None
        return [False, f_path, None, f_size, f_digest]

    return [False, f_path, None, 0, ZERO_DIGEST]


def dir_to_list_list(d_path):
    """
    """
    f_list_list = []
    size_sum = 0
    print('I: scanning the directory', d_path)

    for root, _, files in walk(d_path):
        for f in files:
            k_file = path.join(root, f)
            f_size = get_file_size(k_file)

            if f_size is None:
                return None

            size_sum += f_size

            f_list = [False, k_file, None, f_size, None]
            f_list_list.append(f_list)

    f_list_list_len = len(f_list_list)

    print(
        'I: found {} files, total size: {} bytes'.format(
            f_list_list_len,
            size_sum))

    if f_list_list_len == 0:
        return []

    print('I: hashing files in the directory...')

    for i in range(f_list_list_len):
        f_list = f_list_list[i]
        with open(f_list[1], 'rb') as f:
            f_digest = blake2b_file_digest(f, f_list[3])
            if f_digest is None:
                return None
        f_list_list[i][4] = f_digest

    return f_list_list


def get_k_list_list():
    """
    """
    k_list_list = []

    while True:
        print()
        k_file = input('Keyfile (optional): ')

        if k_file == '':
            break

        k_file = path.realpath(k_file)

        if not path.exists(k_file):
            print('E: {} does not exist'.format(k_file))
            print('E: keyfile NOT accepted!')
            continue

        if path.isdir(k_file):

            dir_list = dir_to_list_list(k_file)

            if dir_list is None:
                print('E: keyfiles NOT accepted!')
                continue
            if dir_list == []:
                print('E: nothing to accept!')
            else:
                k_list_list.extend(dir_list)
                print('I: keyfiles accepted!')

        else:
            file_list = keyfile_to_list(k_file)
            if file_list is None:
                print('E: keyfile NOT accepted!')
            else:
                k_list_list.append(file_list)
                print('I: keyfile accepted!')
            continue

    while True:
        print()
        pp0 = getpass('Passphrase (optional): ')
        if pp0 == '':
            break

        pp1 = getpass('Verify passphrase: ')
        if pp0 == pp1:
            pp_list = pp_to_list(pp0)
            k_list_list.append(pp_list)
            print('I: passphrase accepted!')
        else:
            print('E: passphrase verification failed!')

            pp_list = pp_to_list(pp0)
            k_list_list.append(pp_list)

    if od['debug']:
        print()
        print('keyfiles and passphrases:')
        eprint(k_list_list)
        print()

    k_list_list.sort(key=itemgetter(4))

    return k_list_list


def get_for_kdf_key_list_list():
    """
    """
    k_list_list = get_k_list_list()
    keys_total_size = 0
    m = blake2b(digest_size=BLAKE_DIGEST_SIZE)

    for k_list in k_list_list:
        k_size = k_list[3]
        k_digest = k_list[4]
        keys_total_size += k_size
        m.update(k_digest)

    if od['debug']:
        print('D: received {} key elements with a total size of {} '
              'bytes'.format(len(k_list_list), keys_total_size))

        print()

    basic_key = m.digest()
    total_block_num = od['num_rounds'] * 3

    base_block_size = keys_total_size // total_block_num
    ext_block_size = base_block_size + 1
    ext_block_num = keys_total_size % total_block_num
    base_block_num = total_block_num - ext_block_num

    if od['debug']:
        print('ext_block_size: {}, ext_block_num: {}'.format(
            ext_block_size, ext_block_num))
        print('base_block_size: {}, base_block_num: {}'.format(
            base_block_size, base_block_num))

    m = blake2b(digest_size=BLAKE_DIGEST_SIZE)

    digest_tuple_list = []

    r_sum = 0
    block_r_sum = 0
    cur_block_num = 0
    cur_block_size = base_block_size

    if ext_block_num > 0:
        cur_block_size = ext_block_size

    cur_block_rem_size = cur_block_size
    stop = False

    for key_list in k_list_list:
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
                    try:
                        key_data = f.read(cur_block_rem_size)
                    except OSError as e:
                        print(e)
                        return

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

                cur_block_num += 1
                block_r_sum = 0
                m = blake2b(digest_size=BLAKE_DIGEST_SIZE)

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
                    try:
                        key_data = f.read(cur_block_size)
                    except OSError as e:
                        print(e)
                        return
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
                m = blake2b(digest_size=BLAKE_DIGEST_SIZE)

            if stop:
                break

            if not is_pp:
                try:
                    key_data = f.read(key_rem_size)
                except OSError as e:
                    print(e)
                    od['i'].close()
                    od['o'].close()
                    return
            else:
                new_pos = key_pos + key_rem_size
                key_data = pp_data[key_pos:new_pos]
                key_pos = new_pos

            m.update(key_data)

            key_data_len = len(key_data)
            block_r_sum += key_data_len
            r_sum += key_data_len

            cur_block_rem_size = cur_block_rem_size - key_data_len
            key_rem_size = key_rem_size - key_data_len  # OK???
        else:
            if not is_pp:
                try:
                    key_data = f.read(key_rem_size)
                except OSError as e:
                    print(e)
                    od['i'].close()
                    od['o'].close()
                    return
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
        for digest_tuple in digest_tuple_list:
            print(' ', digest_tuple[::-1])

    for_kdf_key_list = []

    for i in range(total_block_num):
        try:
            part_key = digest_tuple_list[i][0]
        except IndexError:
            part_key = ZERO_DIGEST
        for_kdf_key_list.append(basic_key + part_key)

    for_kdf_key_list_list = []  # ...l_list
    start, fin = 0, 3
    for i in range(od['num_rounds']):
        for_kdf_key_list_list.append(for_kdf_key_list[start:fin])
        start, fin = start + 3, fin + 3

    if od['debug']:
        print()
        print('for_kdf_key_list_list:')
        eprint(for_kdf_key_list_list)

    return for_kdf_key_list_list


def is_debug():
    """
    """
    while True:
        debug = input('  Debug (0|1): ')
        if debug in ('', '0'):
            return False
        if debug == '1':
            return True
        else:
            print('  E: invalid value')
            continue


def get_num_rounds():
    """
    """
    while True:
        num_rounds = input('  Number of rounds (default={}): '.format(
            DEFAULT_NUM_ROUNDS))

        if num_rounds in ('', str(DEFAULT_NUM_ROUNDS)):
            return DEFAULT_NUM_ROUNDS

        try:
            num_rounds = int(num_rounds)
        except Exception:
            print('  E: invalid value')
            continue

        if num_rounds < 1:
            print('  E: invalid value; must be >= 1')
            continue

        return num_rounds


def get_block_size():
    """
    """
    while True:
        block_size_m = input('  Keystream block size (default={}): '.format(
            DEFAULT_BLOCK_SIZE_M))

        if block_size_m in ('', str(DEFAULT_BLOCK_SIZE_M)):
            return DEFAULT_BLOCK_SIZE_M * M

        try:
            block_size_m = int(block_size_m)
        except Exception:
            print('  E: invalid value')
            continue

        if block_size_m < 1 or block_size_m > 2047:
            print('  E: invalid value; must be >= 1 and <= 2047')
            continue

        return block_size_m * M


def get_padding_order():
    """
    """
    print('  W: high padding order values can lead to disk space exhaustion!')
    while True:
        padding_order = input('  Padding order (default={}): '.format(
            DEFAULT_PADDING_ORDER))

        if padding_order in ('', str(DEFAULT_PADDING_ORDER)):
            return DEFAULT_PADDING_ORDER

        try:
            padding_order = int(padding_order)
        except Exception:
            print('  E: invalid value')
            continue

        if padding_order < 0 or padding_order > 64:
            print('  E: invalid value; must be >= 0 and <= 64')
            continue

        return padding_order


def get_dk_len():
    """
    """
    while True:
        dk_len_k = input('  Derived key length (default={}): '.format(
            DEFAULT_DK_LEN_K))

        if dk_len_k in ('', str(DEFAULT_DK_LEN_K)):
            return DEFAULT_DK_LEN_K * K

        try:
            dk_len_k = int(dk_len_k)
        except Exception:
            print('  E: invalid value')
            continue

        if dk_len_k < 1:
            print('  E: invalid value; must be >= 1')
            continue

        return dk_len_k * K


def get_metadata_size():
    """
    """
    while True:
        metadata_size = input('  Metadata size (default={}): '.format(
            DEFAULT_METADATA_SIZE))

        if metadata_size in ('', str(DEFAULT_METADATA_SIZE)):
            return DEFAULT_METADATA_SIZE

        try:
            metadata_size = int(metadata_size)
        except Exception:
            print('  E: invalid value')
            continue

        if metadata_size < 0:
            print('  E: invalid value; must be >= 0')
            continue

        return metadata_size


def set_custom_options():
    """
    """
    custom = is_custom()
    print('I: custom options:', custom)

    if custom:
        od['debug'] = is_debug()
        od['num_rounds'] = get_num_rounds()
        od['block_size'] = get_block_size()
        od['padding_order'] = get_padding_order()
        od['dk_len'] = get_dk_len()
        od['metadata_size'] = get_metadata_size()
    else:
        od['debug'] = False
        od['num_rounds'] = DEFAULT_NUM_ROUNDS
        od['block_size'] = DEFAULT_BLOCK_SIZE
        od['padding_order'] = DEFAULT_PADDING_ORDER
        od['dk_len'] = DEFAULT_DK_LEN
        od['metadata_size'] = DEFAULT_METADATA_SIZE

    od['salts_size'] = SALT_SIZE * 3 * od['num_rounds']
    od['salts_fin_size'] = od['salts_size'] // 2
    od['salts_start_size'] = od['salts_size'] - od['salts_fin_size']
    od['block_tear_size'] = int(
        (od['block_size'] / (MIN_CHUNK_SIZE + (255 / 2))) * 1.05)
    od['block_mix_size'] = od['block_tear_size'] * MIX_BYTES_SIZE
    od['input_block_size'] = od['block_size'] - OUT_OF_INPUT_BLOCK_SIZE
    od['rk_keysream_size'] = (OUT_OF_INPUT_BLOCK_SIZE -
                              PADDING_KEYSTREAM_SIZE - MAC_SIZE -
                              od['metadata_size'])
    od['padding_start_pos'] = od['input_block_size']
    od['padding_fin_pos'] = od['padding_start_pos'] + PADDING_KEYSTREAM_SIZE
    od['mac_start_pos'] = od['padding_fin_pos']
    od['mac_fin_pos'] = od['mac_start_pos'] + MAC_SIZE
    od['meta_start_pos'] = od['mac_fin_pos']
    od['meta_fin_pos'] = od['meta_start_pos'] + od['metadata_size']
    od['rk_start_pos'] = od['meta_fin_pos']
    od['rk_fin_pos'] = od['rk_start_pos'] + od['rk_keysream_size']


def is_custom():
    """
    """
    while True:
        custom = input('Custom options (0|1): ')
        if custom in ('', '0'):
            return False
        if custom == '1':
            return True
        else:
            print('E: invalid value')
            continue


def get_info():
    """
    """
    print('I: tird: this is random data\n')


def cryptohider(mode):
    """
    """
    set_custom_options()

    final_pos = None

    for_kdf_key_list_list = get_for_kdf_key_list_list()

    if for_kdf_key_list_list is None:
        return

    i_file, i_size, od['i'] = get_input_file(mode)
    print('I: input file real path (in quotes):\n    "{}"'.format(
        i_file))
    print('I: input file size: {} bytes, {} MiB'.format(
        i_size, round(i_size / M, 1)))
    print()

    min_data_size = od['salts_size'] + od['metadata_size'] + MAC_SIZE

    if mode in (3, 5):
        if i_size < min_data_size:
            print('E: invalid input values combination')

            od['i'].close()
            return

    if mode in (2, 3):
        o_file, od['o'] = get_output_file_c(mode)
    elif mode == 4:
        o_file, o_size, od['o'] = get_output_file_w(i_file, i_size, mode)
        max_init_pos = (
            o_size - i_size - min_data_size - 2 ** od['padding_order'] * 2)
    else:  # 5
        o_file, od['o'] = get_output_file_c(mode)
        max_init_pos = i_size - min_data_size

    print('I: output file real path (in quotes):\n    "{}"'.format(
        o_file))

    if mode == 4:
        print('I: output file size: {} bytes, {} MiB'.format(
            o_size, round(o_size / M, 1)))

    if mode in (4, 5):
        init_pos = get_init_pos(max_init_pos, fix=False)
        print('I: initial position:', init_pos)
        print()

    if mode == 5:
        final_pos = get_final_pos(
            min_pos=init_pos +
            min_data_size,
            max_pos=i_size,
            fix=False)
        print('I: final position:', final_pos)

    if mode in (2, 4):
        meta = get_metadata_bytes()
    else:  # 3, 5
        show_meta = show_metadata()
        print('I: show metadata: {}'.format(show_meta))

    if mode in (2, 4):
        MAC = get_mac()
        print('I: add MAC: {}'.format(MAC))
    else:  # 3, 5
        MAC = True

    if mode == 4:
        if not do_continue(fix=''):
            print('I: stop!\n')
            return

    if od['debug']:
        print('')
        print_positions()

    if mode == 4:
        od['o'].seek(init_pos)
    if mode == 5:
        od['i'].seek(init_pos)
    if mode in (4, 5):
        if od['debug']:
            print('')
            print_positions()

    T0 = monotonic()
    t0 = T0

    w_sum = 0

    if mode == 4:
        not_fsync_sum = 0

    if od['debug']:
        print('...')

    salt_list_list = get_salt_list_list(i_size, final_pos, mode)

    if salt_list_list is None:
        return

    if mode in (2, 4):
        salts_start, salts_fin = get_two_salts(salt_list_list)

        try:
            od['o'].write(salts_start)
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()
            return

        w_len = len(salts_start)
        w_sum += w_len

        if mode == 4:
            not_fsync_sum += w_len

        if od['debug']:
            print_positions()

    if od['debug']:
        print('')

    if od['debug']:
        print('')

    rk_list_list = get_first_rk_list_list(
        for_kdf_key_list_list, salt_list_list)

    if od['debug']:
        print()
        print('')
        eprint(rk_list_list)
        print()

    print('I: data processing...')

    if od['debug']:
        print('')

    keystream_block_counter = 0
    keystream_block = get_keystream_block(rk_list_list)

    padding_keystream = keystream_block[od['padding_start_pos']:od[
        'padding_fin_pos']]

    padding_keystream_start = padding_keystream[:PADDING_KEYSTREAM_SIZE // 2]
    rand_padding_start = rand_bytes_to_padding(padding_keystream_start)

    if od['debug']:
        print('rand_padding_start', rand_padding_start)

    padding_keystream_fin = padding_keystream[-PADDING_KEYSTREAM_SIZE // 2:]
    rand_padding_fin = rand_bytes_to_padding(padding_keystream_fin)

    if od['debug']:
        print('rand_padding_fin', rand_padding_fin)

    if mode in (2, 4):
        content_size = i_size
    elif mode == 3:
        content_size = (i_size - od['salts_size'] - rand_padding_start -
                        rand_padding_fin - od['metadata_size'] - MAC_SIZE)
    else:  # 5
        content_size = (final_pos - init_pos - od['salts_size'] -
                        rand_padding_start - rand_padding_fin -
                        od['metadata_size'] - MAC_SIZE)

    if od['debug']:
        print('content size:', content_size)

    if mode in (2, 4):
        output_data_size = (od['salts_size'] + rand_padding_start + i_size +
                            od['metadata_size'] + MAC_SIZE + rand_padding_fin)
    else:  # 3, 5
        output_data_size = content_size

    if od['debug']:
        print('output data size:', output_data_size)

    if output_data_size < 0:
        print('output data size:', output_data_size)
        print('')

        od['i'].close()
        od['o'].close()
        return

    if mode in (2, 4):
        p_num_blocks = rand_padding_start // CHUNK_SIZE
        p_rem_size = rand_padding_start % CHUNK_SIZE

        for _ in range(p_num_blocks):
            chunk = urandom(CHUNK_SIZE)

            try:
                od['o'].write(chunk)
            except OSError as e:
                print(e)
                od['i'].close()
                od['o'].close()
                return

            w_len = len(chunk)
            w_sum += w_len

            if mode == 4:
                not_fsync_sum += w_len
                if not_fsync_sum >= MIN_FSYNC_SIZE:
                    od['o'].flush()
                    fsync(od['o'].fileno())
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
            print(e)
            od['i'].close()
            od['o'].close()

            return

        w_len = len(chunk)
        w_sum += w_len

        if mode == 4:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:
                od['o'].flush()
                fsync(od['o'].fileno())
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
        print('rand_padding_start')
        print_positions()
        print()

    num_blocks = content_size // od['input_block_size']
    rem_size = content_size % od['input_block_size']

    if MAC:
        plaintext_m = blake2b(digest_size=MAC_SIZE)

    if od['debug']:
        print()

    for _ in range(num_blocks):
        if keystream_block_counter > 0:
            keystream_block = get_keystream_block(rk_list_list)

        keystream_block_counter += 1

        rk_keystream = keystream_block[od['rk_start_pos']:od['rk_fin_pos']]
        rk_list_list = get_updated_rk_list_list(rk_list_list, rk_keystream)

        try:
            input_block = od['i'].read(od['input_block_size'])
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()
            return

        output_block = xor(input_block, keystream_block)

        try:
            od['o'].write(output_block)
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()
            return

        w_len = len(output_block)
        w_sum += w_len

        if mode == 4:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:
                od['o'].flush()
                fsync(od['o'].fileno())
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
            print('', len(output_block))
            print_positions()

        if MAC:
            if mode in (2, 4):
                plaintext_m.update(input_block)
            else:  # 3, 5
                plaintext_m.update(output_block)

                exit(1)  # ??

    if keystream_block_counter > 0:
        keystream_block = get_keystream_block(rk_list_list)

    keystream_block_counter += 1

    try:
        input_block = od['i'].read(rem_size)
    except OSError as e:
        print(e)
        od['i'].close()
        od['o'].close()
        return

    output_block = xor(input_block, keystream_block)

    try:
        od['o'].write(output_block)
    except OSError as e:
        print(e)
        od['i'].close()
        od['o'].close()
        return

    w_len = len(output_block)
    w_sum += w_len

    if mode == 4:
        not_fsync_sum += w_len
        if not_fsync_sum >= MIN_FSYNC_SIZE:
            od['o'].flush()
            fsync(od['o'].fileno())
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
        print(':', len(output_block))
        print_positions()

    if MAC:
        if mode in (2, 4):
            plaintext_m.update(input_block)
        else:  # 3, 5
            plaintext_m.update(output_block)

        if od['debug']:
            print('')

    if od['debug']:
        print()

    if od['debug']:
        print('')

    if mode in (3, 5):
        try:
            meta = od['i'].read(od['metadata_size'])
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()
            return

    meta_keystream = keystream_block[od['meta_start_pos']:od['meta_fin_pos']]
    meta_out = xor(meta, meta_keystream)

    if od['debug']:
        print('')

    if mode in (2, 4):
        try:
            od['o'].write(meta_out)
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()
            return

        w_len = len(meta_out)
        w_sum += w_len

        if mode == 4:
            not_fsync_sum += w_len

        if od['debug']:
            print(':', len(meta_out))
    else:  # 3, 5
        if show_meta:
            meta_utf = metadata_to_utf(meta_out)
            print('I: metadata:', meta_utf)

    if MAC:
        if mode in (2, 4):
            plaintext_m.update(meta)
        else:  # 3, 5
            plaintext_m.update(meta_out)

    if od['debug']:
        print('')
        print_positions()

    if od['debug']:
        print('')

    if MAC:
        found_mac = plaintext_m.digest()
        mac_keystream = keystream_block[od['mac_start_pos']:od['mac_fin_pos']]
        xored_mac = xor(found_mac, mac_keystream)

        if od['debug']:
            print('', found_mac.hex(), xored_mac.hex())

    if mode in (2, 4):
        if MAC:
            try:
                od['o'].write(xored_mac)
            except OSError as e:
                print(e)
                od['i'].close()
                od['o'].close()
                return

            w_len = len(xored_mac)
            w_sum += w_len

            if mode == 4:
                not_fsync_sum += w_len

            if od['debug']:
                print(':', len(xored_mac))
                print('', found_mac.hex())
        else:
            fake_mac = urandom(MAC_SIZE)

            try:
                od['o'].write(fake_mac)
            except OSError as e:
                print(e)
                od['i'].close()
                od['o'].close()

                return

            w_len = len(fake_mac)
            w_sum += w_len

            if mode == 4:
                not_fsync_sum += w_len

            if od['debug']:
                print('', fake_mac.hex())
    else:  # 3, 5
        try:
            read_mac = od['i'].read(MAC_SIZE)
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()
            return

        if od['debug']:
            print('read_mac', read_mac.hex())

        restored_mac = xor(read_mac, mac_keystream)

        if od['debug']:
            print('restored_mac', restored_mac.hex())

        if found_mac == restored_mac:
            print('MAC is valid: True')
        else:
            print('MAC is valid: False')

    if od['debug']:
        print('')
        print_positions()
        print()

    if od['debug']:
        print('total keystream_block_counter', keystream_block_counter)
        print('')

    if mode in (2, 4):
        p_num_blocks = rand_padding_fin // M
        p_rem_size = rand_padding_fin % M
        for _ in range(p_num_blocks):

            chunk = urandom(CHUNK_SIZE)

            try:
                od['o'].write(chunk)
            except OSError as e:
                print(e)
                od['i'].close()
                od['o'].close()
                return

            w_len = len(chunk)
            w_sum += w_len

            if mode == 4:
                not_fsync_sum += w_len
                if not_fsync_sum >= MIN_FSYNC_SIZE:
                    od['o'].flush()
                    fsync(od['o'].fileno())
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
            print(e)
            od['i'].close()
            od['o'].close()

            return

        w_len = len(chunk)
        w_sum += w_len

        if mode == 4:
            not_fsync_sum += w_len
            if not_fsync_sum >= MIN_FSYNC_SIZE:
                od['o'].flush()
                fsync(od['o'].fileno())
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
        print('')
        print_positions()
        print()

    if mode in (2, 4):
        if od['debug']:
            print('')

        try:
            od['o'].write(salts_fin)
        except OSError as e:
            print(e)
            od['i'].close()
            od['o'].close()
            return

        w_len = len(salts_fin)
        w_sum += w_len

        if mode == 4:
            od['o'].flush()
            fsync(od['o'].fileno())
            print_progress(w_sum, output_data_size, T0, fix='/fsynced')
        else:
            print_progress(w_sum, output_data_size, T0, fix='')

        if od['debug']:
            print('')
            print_positions()
            print()

        if mode == 4:
            print('Remember these values to retrieve the message '
                  'from the container in the future:')
            print('    Initial position: {}, Final position: {}'.format(
                init_pos, od['o'].tell()))

    if mode == 4:
        print_progress(w_sum, output_data_size, T0, fix='/fsynced')
    else:
        print_progress(w_sum, output_data_size, T0, fix='')

    if od['debug']:
        print('w_sum:', w_sum)
        print('output data size:', output_data_size)

    if w_sum != output_data_size:
        print()

    od['i'].close()
    od['o'].close()
    print()


def hider(mode):
    """
    """
    i_file, i_size, i_object = get_input_file(mode)
    print('I: input file real path (in quotes):\n    "{}"'.format(
        i_file))
    print('I: input file size: {} bytes, {} MiB'.format(
        i_size, round(i_size / M, 1)))

    if mode == 6:
        o_file, o_size, o_object = get_output_file_w(
            i_file, i_size, mode)
        max_init_pos = o_size - i_size
    else:
        o_file, o_object = get_output_file_c(mode)
        max_init_pos = i_size - 1

    print('I: output file real path (in quotes):\n    "{}"'.format(
        o_file))

    if mode == 6:
        print('I: output file size: {} bytes, {} MiB'.format(
            o_size, round(o_size / M, 1)))

    init_pos = get_init_pos(max_init_pos, fix=False)
    print('I: initial position:', init_pos)

    if mode == 6:
        data_size = i_size

        if not do_continue(fix=''):
            print('I: stop!\n')
            return
    else:
        final_pos = get_final_pos(min_pos=init_pos, max_pos=i_size, fix=False)
        print('I: final position:', final_pos)
        data_size = final_pos - init_pos
        print('I: data size to extract:', data_size)

    if mode == 6:
        print('I: reading, writing, fsyncing...')
    else:
        print('I: reading, writing...')

    res = hider_data_handler(mode, i_object, o_object, init_pos, data_size)

    i_object.close()
    o_object.close()

    if res != 1:
        print('OK\n')


def randgen(mode):
    """
    """
    o_file, o_object = get_output_file_c(mode)
    print('I: output file real path (in quotes):\n    "{}"'.format(
        o_file))

    o_size = get_output_file_size()
    print('I: output file size: {} bytes, {} MiB'.format(
        o_size, round(o_size / M, 1)))

    num_chunks = o_size // CHUNK_SIZE
    rem_size = o_size % CHUNK_SIZE

    print('I: writing data...')

    fix = ''

    T0 = monotonic()
    t0 = T0

    w_sum = 0

    for _ in range(num_chunks):
        chunk = urandom(CHUNK_SIZE)

        try:
            o_object.write(chunk)
        except OSError as e:
            o_object.close()
            print(e)
            print()
            return

        w_len = len(chunk)
        w_sum += w_len

        if monotonic() - t0 >= MIN_PRINT_INTERVAL:
            print_progress(w_sum, o_size, T0, fix)
            t0 = monotonic()

    chunk = urandom(rem_size)

    try:
        o_object.write(chunk)
    except OSError as e:
        o_object.close()
        print(e)
        print()
        return

    w_len = len(chunk)
    w_sum += w_len

    print_progress(w_sum, o_size, T0, fix)

    o_object.close()

    print('OK')
    print()


def wiper(mode):
    """
    """
    o_file, o_size, o_object = get_output_file_w(
        i_file='', i_size=0, mode=mode)
    print('I: output file real path (in quotes):\n    "{}"'.format(
        o_file))

    print('I: output file size: {} bytes, {} MiB'.format(
        o_size, round(o_size / M, 1)))

    if o_size == 0:
        print('I: nothing to overwrite')
        return

    init_pos = get_init_pos(max_init_pos=o_size, fix=True)
    print('I: initial position:', init_pos)

    if init_pos == o_size:
        print('I: nothing to overwrite')
        return

    final_pos = get_final_pos(min_pos=init_pos, max_pos=o_size, fix=True)
    print('I: final position:', final_pos)

    data_size = final_pos - init_pos
    print('I: data size to write:', data_size)

    if data_size == 0:
        print('I: nothing to overwrite')
        return

    owbr = ow_by_random()

    if owbr:
        ow_byte = None
        fix = ' with random bytes'
    else:
        ow_byte_num = get_ow_byte()
        ow_byte_hex = hex(ow_byte_num)[2:].rjust(2, '0').upper()
        ow_byte = ow_byte_num.to_bytes(1, 'big')
        print('I: byte: {}, decimal num: {}, hexadecimal num: {}'.format(
            ow_byte, ow_byte_num, ow_byte_hex))
        fix = ' with {} bytes'.format(ow_byte)

    if not do_continue(fix):
        o_object.close()
        return

    res = wiper_data_handler(o_object, init_pos, data_size, owbr, ow_byte)
    o_object.close()
    if res != 1:
        print('OK')


def get_mode():
    """
    """
    while True:
        mode_info = """Select the action to take
0 - exit
1 - get info
2 - encrypt file
3 - decrypt file
4 - encrypt and hide file
5 - decrypt and unhide file
6 - hide file (without  encryption)
7 - unhide file (without decryprion)
8 - create file with random data
9 - overwrite file with random or specific bytes
: """
        mode = input(mode_info)

        if mode == '0':
            print('I: exit')
            exit()

        if mode == '1':
            get_info()
            continue

        if mode == '2':
            print('I: mode: encrypt file')
            return 2

        if mode == '3':
            print('I: mode: decrypt file')
            return 3

        if mode == '4':
            print('I: mode: encrypt and hide file')
            return 4

        if mode == '5':
            print('I: mode: decrypt and unhide file')
            return 5

        if mode == '6':
            print('I: mode: hide file (without  encryption)')
            return 6

        if mode == '7':
            print('I: mode: unhide file (without decryprion)')
            return 7

        if mode == '8':
            print('I: mode: create file with random data')
            return 8

        if mode == '9':
            print('I: mode: overwrite file with random or specific bytes')
            return 9

        print('E: invalid mode\n')


def main():
    """
    """
    signal(SIGINT, signal_handler)

    while True:
        mode = get_mode()

        if mode in (2, 3, 4, 5):
            cryptohider(mode)

        if mode in (6, 7):
            hider(mode)

        if mode == 8:
            randgen(mode)

        if mode == 9:
            wiper(mode)

        print()
        od.clear()


od = {}


K = 1024
M = K * K

BLAKE_DIGEST_SIZE = 64
ZERO_DIGEST = blake2b_digest(b'')

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1

CHUNK_SIZE = M
MIN_PRINT_INTERVAL = 4
MIN_FSYNC_SIZE = M * 256
HIDER_DIGEST_SIZE = 20

SALT_SIZE = 64

MIN_CHUNK_SIZE = 128

MIX_BYTES_SIZE = 4

OUT_OF_INPUT_BLOCK_SIZE = 16 * K

PADDING_KEYSTREAM_SIZE = 16

MAC_SIZE = 64

DEFAULT_NUM_ROUNDS = 1

DEFAULT_BLOCK_SIZE_M = 32
DEFAULT_BLOCK_SIZE = DEFAULT_BLOCK_SIZE_M * M

DEFAULT_PADDING_ORDER = 8

DEFAULT_DK_LEN_K = 4096
DEFAULT_DK_LEN = DEFAULT_DK_LEN_K * K

DEFAULT_METADATA_SIZE = 256


if __name__ == '__main__':
    main()
