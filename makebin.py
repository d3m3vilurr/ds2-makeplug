import os
import struct
import common

def decrypt(sf, of, ff=None):
    with open(sf, 'rb') as s:
        s = s.read()

    b = struct.unpack('I', s[0:4])[0]
    a = b ^ 0x8b12bab6 ^ 0
    tmp = ''
    for x in xrange(0, len(s), 0x200):
        k = a ^ ((x >> 24) + (x >> 16) + (x >> 8) + x)
        d = s[x : x + 0x200]
        if len(d) < 0x200:
            d += common.NULL_BUF[:0x200 - len(d)]
        tmp += common.block_decrypt(x, k, d)

    header = common.Header()
    header.unpack(tmp[0:0x200])

    if not header.sanity:
        raise IOError('checksum mismatch')

    print 'addr0: 0x%x' % header.addr0
    print 'addr1: 0x%x' % header.addr1

    with open(of, 'wb') as w:
        w.write(tmp[0x200:0x200 + header.prog_size])

    if not ff:
        return

    with open(ff, 'wb') as w:
        w.write(tmp[header.firm_offset:])

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='makebin')
    parser.add_argument('plg', metavar='PLUGIN_FILENAME', type=str)
    parser.add_argument('bin', metavar='BIN_FILENAME', type=str)
    parser.add_argument('--dumpfirm', dest='firm', type=str)

    args = parser.parse_args()

    if '.' not in args.bin or args.bin[-4:] != '.bin':
        args.bin += '.bin'

    decrypt(args.plg, args.bin, args.firm)
