import argparse
import readline
import serial
import struct
import time

def read_bytes(ser, address, count_words):
    assert count_words > 0 and count_words <= 0x40, f'invalid count_words {count_words}'

    opcode = 0x80 | (count_words - 1)
    ser.write(struct.pack('>BI', opcode, address))

    data = []
    for i in range(count_words):
        data.extend(list(struct.unpack('BBBB', ser.read(4))))
    return data

def main():
    parser = argparse.ArgumentParser(description='G2C547/G2C543 bootloader shell')
    parser.add_argument('bootloader_payload', type=argparse.FileType('rb'))
    parser.add_argument('port')
    args = parser.parse_args()

    ser = serial.Serial(args.port, 115200, timeout=2)
    print('sending wakeup')
    ser.write(b'\x55')

    time.sleep(0.1)

    print('sending bootloader payload')
    while True:
        chunk = args.bootloader_payload.read(0x1000)
        if len(chunk) == 0:
            break

        ser.write(chunk)

    running = True
    while running:
        full_cmd = input('> ')
        cmds = full_cmd.split(';')
        for cmd in cmds:
            cmd = cmd.strip().split(' ')

            if len(cmd) == 0:
                continue
            
            cmd, args = cmd[0], cmd[1:]

            if len(cmd) == 0:
                continue

            if cmd == 'q' or cmd == 'quit' or cmd == 'exit':
                running = False
                break
            elif cmd == 'r' or cmd == 'read':
                if len(args) not in [1, 2]:
                    print('usage: read address [count_words]')
                    continue
                
                address = int(args[0], 16)
                if address < 0 or address > 0xffffffff:
                    print('invalid address')
                    continue

                count_words = 1
                if len(args) == 2:
                    count_words = int(args[1])
                    if count_words <= 0:
                        print('invalid count_words')
                        continue

                orig_address = address

                data = []
                while count_words > 0:
                    count_words_now = min(count_words, 0x40)
                    data.extend(read_bytes(ser, address, count_words_now))

                    count_words -= count_words_now
                    address += count_words_now * 4

                data = ' '.join([f'{b:02x}' for b in data])
                print(f'address {orig_address:08x} = {data}')
            elif cmd == 'd' or cmd == 'dump':
                if len(args) != 3:
                    print('usage: dump address count_words filename')
                    continue

                address = int(args[0], 16)
                if address < 0 or address > 0xffffffff:
                    print('invalid address')
                    continue

                count_words = int(args[1])
                if count_words <= 0:
                    print('invalid count_words')
                    continue
                last_address = address + count_words - 1
                if last_address > 0xffffffff:
                    print('invalid count_words (out of bounds read)')
                    continue

                filename = args[2]
                print(f'dumping to {filename}')
                with open(filename, 'wb') as f:
                    while count_words > 0:
                        count_words_now = min(count_words, 0x40)
                        f.write(bytes(read_bytes(ser, address, count_words_now)))

                        count_words -= count_words_now
                        address += count_words_now * 4
                        print(f'{count_words} words remaining')
                print('dump complete')
            elif cmd == 'w' or cmd == 'write':
                if len(args) != 2:
                    print('usage: write address value')
                    continue
                
                address = int(args[0], 16)
                if address < 0 or address > 0xffffffff:
                    print('invalid address')
                    continue

                value = int(args[1], 16)
                if value < 0 or value > 0xffffffff:
                    print('invalid value')
                    continue

                ser.write(struct.pack('>BII', 0xC0, address, value))
                print(f'wrote {address:08x} = {value:08x}')
            else:
                print('unknown command')

if __name__ == '__main__':
    main()
