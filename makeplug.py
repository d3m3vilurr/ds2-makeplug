import struct
import random
import common

FIRMWARE_FILENAME = 'ds2_firmware.dat'

def encrypt(sf, ff, of, addr0=0x80002000,addr1=0x80002000):
    with open(sf, 'rb') as s:
        s = s.read()
    with open(ff, 'rb') as f:
        f = f.read()

    header = common.Header()
    header.prog_size = len(s)
    header.addr0 = addr0
    header.addr1 = addr1
    header.firm_offset = (header.prog_size  + 0x3ff) & 0xfffffe00
    header.firm_size = len(f)

    buf = header.pack()
    buf += s
    buf += common.NULL_BUF[:header.firm_offset - len(buf)]
    buf += f

    out = ''
    a = random.randint(0, 2**32) ^ 0x79fa8917
    for x in xrange(0, len(buf), 0x200):
        k = a ^ ((x >> 24) + (x >> 16) + (x >> 8) + x)
        d = buf[x:x + 0x200]
        if len(d) < 0x200:
            d += common.NULL_BUF[:0x200 - len(d)]
        out += common.block_encrypt(x, k, d)

    with open(of, 'wb') as w:
        w.write(out)

if __name__ == '__main__':
    import os
    import sys
    import argparse

    def str2int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='makeplug')
    parser.add_argument('bin', metavar='BIN_FILENAME', type=str)
    parser.add_argument('plg', metavar='PLUGIN_FILENAME', type=str)
    parser.add_argument('--addr0', dest='addr0', type=str2int,
                        default=0x80002000)
    parser.add_argument('--addr1', dest='addr1', type=str2int,
                        default=0x80002000)
    parser.add_argument('--firm', dest='firm', type=str)

    args = parser.parse_args()

    print hex(args.addr0), hex(args.addr1)
    if '.' not in args.plg or args.plg[-4:] != '.plg':
        args.plg += '.plg'

    if not args.firm:
        firm = os.path.join(os.path.split(sys.argv[0])[0], FIRMWARE_FILENAME)
    else:
        firm = args.firm
    ret = encrypt(args.bin, firm, args.plg, args.addr0, args.addr1)
