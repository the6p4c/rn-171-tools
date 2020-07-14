import argparse
from makeelf import elf
import os
import struct
import sys

def tag_len_to_int(get_byte):
    data_len = 0
    idx = 0
    while True:
        len_component = get_byte(idx)

        if idx == 0:
            shift = 0
        elif idx == 1:
            shift = 6
        else:
            shift = 6 + 7 * (idx - 1)

        data_len |= (len_component & 0x7f) << shift

        idx += 1

        if len_component & 0x80 != 0x80:
            break
    return data_len

class TagFlashFilesystem:
    def __init__(self, f):
        self.f = f

    def read_from(self, address, count):
        self.f.seek(address)
        return self.f.read(count)

    def read_chain_data(self, block_idx):
        self.f.seek(block_idx * 0x1000, os.SEEK_SET)
        start, nextt = struct.unpack('BB', self.f.read(2))
        return start, nextt

    def is_block_start_of_chain(self, block_idx):
        start, nextt = self.read_chain_data(block_idx)
        return start == block_idx

class FileReader:
    def __init__(self, fs, block_idx):
        self.fs = fs
        self.address = block_idx * 0x1000 + 4

    def _read_byte(self):
        b = ord(self.fs.read_from(self.address, 1))

        curr_block_idx = (self.address & 0xfffff000) >> (3 * 4)
        curr_inner_address = self.address & 0xfff
        if curr_inner_address == 0xfff:
            # we're right at the end of a block
            start, nextt = self.fs.read_chain_data(curr_block_idx)
            self.address = nextt * 0x1000 + 4
        else:
            self.address += 1

        return b

    def _read_tag(self):
        if self.address & 0xfff == 0:
            return None

        tag_type = self._read_byte()
        if tag_type == 0xff:
             return None

        data_len = tag_len_to_int(lambda idx: self._read_byte())

        data = []
        for i in range(data_len):
            data.append(self._read_byte())

        return tag_type, data

    def read(self):
        f = {}
        while True:
            tag = self._read_tag()
            if tag is None:
                break

            tag_type, data = tag
            f[tag_type] = data
        return f

def parse_args():
    parser = argparse.ArgumentParser(description='RN-171 filesystem extractor')
    subparsers = parser.add_subparsers(dest='cmd', required=True)

    parser_extract = subparsers.add_parser('extract', help='extract the filesystem to a directory')
    parser_extract.add_argument('file', type=argparse.FileType('rb'))
    parser_extract.add_argument('output_dir')
    parser_extract.add_argument('--raw-binaries', action='store_true', help='dump binaries as raw bytes instead of inside an ELF container')

    parser_extract = subparsers.add_parser('insert', help='insert an ELF file into the filesystem')
    parser_extract.add_argument('new_file', type=argparse.FileType('rb'))
    parser_extract.add_argument('fs_in', type=argparse.FileType('rb'))
    parser_extract.add_argument('fs_out', type=argparse.FileType('wb'))

    return parser.parse_args()

def dump_file(output_directory, filename, f):
    with open(os.path.join(output_directory, filename), 'wb') as f_out:
        f_out.write(bytes(f[0x1e]))

def dump_binary(output_directory, filename, f, use_elf):
    entry_point = struct.unpack('>I', bytes(f[0xb5]))[0]
    print(f'\t[tag 0xb5] entry point = 0x{entry_point:08x}')

    load_address = struct.unpack('>I', bytes(f[0xba]))[0]
    print(f'\t[tag 0xba] load address = 0x{load_address:08x}')

    checksum = struct.unpack('>I', bytes(f[0xbc]))[0]
    print(f'\t[tag 0xbc] checksum = 0x{checksum:08x}')

    if use_elf:
        elf_file = elf.ELF(e_machine=elf.EM.EM_SPARC)
        elf_file.Elf.Ehdr.e_entry = entry_point

        section_text = elf_file.append_section('.text', bytes(f[0xb1]), load_address)
        elf_file.Elf.Shdr_table[section_text].sh_flags = elf.SHF.SHF_ALLOC | elf.SHF.SHF_EXECINSTR

        out_bytes = bytes(elf_file)
    else:
        out_bytes = bytes(f[0xb1])

    with open(os.path.join(output_directory, filename), 'wb') as f_out:
        f_out.write(bytes(out_bytes))

    tag20 = f.get(0x20)
    if tag20 is not None:
        with open(os.path.join(output_directory, f'{filename}.strtab'), 'wb') as f_out:
            f_out.write(bytes(tag20))

def cmd_extract(args):
    fs_file = args.file
    output_directory = args.output_dir
    use_elf = not args.raw_binaries

    l = os.stat(fs_file.name).st_size
    assert l % 0x1000 == 0

    fs = TagFlashFilesystem(fs_file)

    num_blocks = l // 0x1000
    for block_idx in range(num_blocks):
        if fs.is_block_start_of_chain(block_idx):
            print(f'block {block_idx}:')

            f = FileReader(fs, block_idx).read()
            tags = [(tag, len(f[tag])) for tag in sorted(f.keys())]
            tags = [f'{tag:02x} ({data_len} bytes)' for tag, data_len in tags]
            tags = ', '.join(tags)
            print(f'\ttags: {tags}')

            filename = f.get(0x01)
            if filename is not None:
                filename = ''.join([chr(b) for b in filename])
                print(f'\t[tag 0x01] filename = {filename}')

            flags = f.get(0x03)
            if flags is not None:
                flags = flags[0] ^ 0xFF
                print(f'\t[tag 0x03] flags = 0x{flags:02x} = 0b{flags:08b}')

            if flags == 0x00:
                # regular file?
                dump_file(output_directory, filename, f)
            elif flags == 0x03:
                # binary?
                dump_binary(output_directory, filename, f, use_elf)
            else:
                # no idea
                print(f'\t!!! unknown file type, not dumping')

def prepare_tags(new_file):
    elf_file, b = elf.ELF.from_bytes(new_file.read())
    section_text_header, section_text = elf_file.get_section_by_name('.text')

    tags = {}

    # filename
    tags[0x01] = new_file.name.encode('ascii')
    # flags
    tags[0x03] = struct.pack('>B', 0x03 ^ 0xFF)
    # image data
    tags[0xb1] = section_text
    # entry point
    tags[0xb5] = struct.pack('>I', elf_file.Elf.Ehdr.e_entry)
    # load address
    tags[0xba] = struct.pack('>I', section_text_header.sh_addr)
    # checksum (invalid)
    tags[0xbc] = b'\0\0\0\0'

    return tags

def tags_to_data(tags):
    data = []
    for tag_type, tag_data in tags.items():
        data.append(tag_type)

        l = len(tag_data)
        tag_len_bytes = [l & 0x3f]

        if l > 0x3f:
            l >>= 6
            tag_len_bytes.append(l & 0x7f)

            while l > 0x7f:
                l >>= 7
                tag_len_bytes.append(l & 0x7f)

        for i in range(len(tag_len_bytes) - 1):
            tag_len_bytes[i] |= 0x80

        assert len(tag_data) == tag_len_to_int(lambda idx: tag_len_bytes[idx])

        data.extend(tag_len_bytes)
        data.extend(tag_data)

    return bytes(data)

def cmd_insert(args):
    new_file = args.new_file
    fs_in = args.fs_in
    fs_out = args.fs_out

    l = os.stat(fs_in.name).st_size
    assert l % 0x1000 == 0

    fs = TagFlashFilesystem(fs_in)

    free_blocks = []
    num_blocks = l // 0x1000
    for block_idx in range(num_blocks):
        start, nextt = fs.read_chain_data(block_idx)
        if start == 0xff:
            free_blocks.append(block_idx)

    tags = prepare_tags(new_file)
    data = tags_to_data(tags)

    free_block_idx = 1
    first_block = free_blocks[0]
    this_block = first_block
    new_blocks = {}
    bytes_remaining = len(data)
    while bytes_remaining > 0:
        bytes_to_write = min(0x1000 - 4, bytes_remaining)

        next_block = free_blocks[free_block_idx]
        if bytes_remaining - bytes_to_write == 0:
            next_block = 0xff

        header = struct.pack('>BBBB', first_block, next_block, 0xff, 0xff)
        body = data[:bytes_to_write]
        padding = bytes([0xFF] * (0x1000 - 4 - bytes_to_write))
        data_to_write = header + body + padding

        new_blocks[this_block] = data_to_write

        this_block = next_block
        free_block_idx += 1
        bytes_remaining -= bytes_to_write
        data = data[bytes_to_write:]

    for block_idx in range(num_blocks):
        if block_idx in new_blocks.keys():
            fs_out.write(new_blocks[block_idx])
        else:
            fs_in.seek(0x1000 * block_idx, os.SEEK_SET)
            fs_out.write(fs_in.read(0x1000))
def main():
    args = parse_args()

    if args.cmd == 'extract':
        cmd_extract(args)
    elif args.cmd == 'insert':
        cmd_insert(args)

if __name__ == '__main__':
    main()
