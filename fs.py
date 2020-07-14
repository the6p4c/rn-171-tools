import argparse
from makeelf import elf
import os
import struct
import sys

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

        data_len = 0
        idx = 0
        while True:
            len_component = self._read_byte()

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

    parser_extract = subparsers.add_parser('extract')
    parser_extract.add_argument('file', type=argparse.FileType('rb'))
    parser_extract.add_argument('output_dir')

    return parser.parse_args()

def dump_file(output_directory, filename, f):
    with open(os.path.join(output_directory, filename), 'wb') as f_out:
        f_out.write(bytes(f[0x1e]))

def dump_binary(output_directory, filename, f):
    entry_point = struct.unpack('>I', bytes(f[0xb5]))[0]
    print(f'\t[tag 0xb5] entry point = 0x{entry_point:08x}')

    load_address = struct.unpack('>I', bytes(f[0xba]))[0]
    print(f'\t[tag 0xba] load address = 0x{load_address:08x}')

    checksum = struct.unpack('>I', bytes(f[0xbc]))[0]
    print(f'\t[tag 0xbc] checksum = 0x{checksum:08x}')

    elf_file = elf.ELF(e_machine=elf.EM.EM_SPARC)
    elf_file.Elf.Ehdr.e_entry = entry_point

    section_text = elf_file.append_section('.text', bytes(f[0xb1]), load_address)
    elf_file.Elf.Shdr_table[section_text].sh_flags = elf.SHF.SHF_ALLOC | elf.SHF.SHF_EXECINSTR

    with open(os.path.join(output_directory, filename), 'wb') as f_out:
        f_out.write(bytes(elf_file))

    tag20 = f.get(0x20)
    if tag20 is not None:
        with open(os.path.join(output_directory, f'{filename}.strtab'), 'wb') as f_out:
            f_out.write(bytes(tag20))

def main():
    args = parse_args()

    if args.cmd == 'extract':
        fs_file = args.file
        output_directory = args.output_dir

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
                    dump_binary(output_directory, filename, f)
                else:
                    # no idea
                    print(f'\t!!! unknown file type, not dumping')

if __name__ == '__main__':
    main()
