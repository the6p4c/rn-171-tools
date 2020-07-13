import argparse
import os
import struct
import sys

def read_block(f, block_idx):
    BLOCK_LEN = 0x1000

    f.seek(block_idx * BLOCK_LEN, os.SEEK_SET)
    block = f.read(BLOCK_LEN)
    assert len(block) == BLOCK_LEN, f'block {block_idx:02x} was not 0x1000 long'
    return block

def read_file(f, block_idx):
    data = []

    # first block is a special case: extract the filename
    block = read_block(f, block_idx)
    filename_len = block[14]
    filename = block[15:][:filename_len]
    filename = ''.join([chr(b) for b in filename])

    # remaining data in block is part of the file
    data.extend(block[15:][filename_len:])

    # now follow the chain
    while True:
        next_block = block[1]
        if next_block == 0xff:
            break
        block = read_block(f, next_block)
        data.extend(block[4:])

    return (filename, data)

def read_generic(f, block_idx):
    data = []

    block = read_block(f, block_idx)
    data.extend(block[4:])

    while True:
        next_block = block[1]
        if next_block == 0xff:
            break
        block = read_block(f, next_block)
        data.extend(block[4:])

    return data

def parse_args():
    parser = argparse.ArgumentParser(description='RN-171 filesystem extractor')
    subparsers = parser.add_subparsers(dest='cmd')

    parser_extract = subparsers.add_parser('extract')
    parser_extract.add_argument('file', type=argparse.FileType('rb'))
    parser_extract.add_argument('output_dir')

    return parser.parse_args()

def main():
    args = parse_args()

    if args.cmd == 'extract':
        fs_file = args.file
        output_directory = args.output_dir

        l = os.stat(fs_file.name).st_size
        assert l % 0x1000 == 0

        num_blocks = l // 0x1000
        for i in range(num_blocks):
            block = read_block(fs_file, i)
            if block[0] == i:
                # this is a programmed block
                block_type = block[7]
                flags = block[6] ^ 0xFF
                print(f'block {i:02x} is programmed (type = {block_type:02x}, flags = {flags:02x})')
                #print(f'\tblock header: ' + ' '.join([f'{b:02x}' for b in block[4:][:12]]))
                if block_type == 0x02:
                    print(f'\tblock is a file')

                    filename, data = read_file(fs_file, i)
                    print(f'\textracting {filename}')
                    with open(os.path.join(output_directory, filename), 'xb') as f:
                        f.write(bytes(data))
                elif block_type == 0xba:
                    print(f'\tblock is an image')

                    print(f'\traw image header: ' + ' '.join([f'{b:02x}' for b in block[7:][:22]]))
                    load_address = struct.unpack('>I', block[9:][:4])[0]
                    entry_point = struct.unpack('>I', block[15:][:4])[0]
                    print(f'\tload address: {load_address:08X}')
                    print(f'\tentry point: {entry_point:08X}')
                else:
                    print(f'\tunknown block type; ignoring')

if __name__ == '__main__':
    main()
