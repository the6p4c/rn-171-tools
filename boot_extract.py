import argparse
import struct

def main():
    parser = argparse.ArgumentParser(description='RN-171 boot loader extractor')
    parser.add_argument('in_file', type=argparse.FileType('rb'))
    parser.add_argument('out_file', type=argparse.FileType('wb'))
    args = parser.parse_args()

    in_file = args.in_file
    out_file = args.out_file
    in_file.read(0x8b)

    while True:
        header = in_file.read(5)
        #assert len(header) == 5, 'header too short'
        if len(header) != 5:
            break

        block_len = header[0] + 1
        address = struct.unpack('>I', header[1:])[0]

        print(f'0x{address:08x}, 0x{block_len:x} bytes')
        out_file.write(in_file.read(block_len))

if __name__ == '__main__':
    main()
