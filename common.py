import struct
import ctypes

ror = lambda val, r_bits, max_bits=32: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

NULL_BUF = '\x00' * 0x200


class Header(ctypes.Structure):

    _fields_ = [('checksum0', ctypes.c_uint),
                ('checksum1', ctypes.c_uint),
                ('checksum2', ctypes.c_uint),
                ('checksum3', ctypes.c_uint),
                ('unknown', ctypes.c_uint),
                ('prog_size', ctypes.c_uint),
                ('addr0', ctypes.c_uint),
                ('addr1', ctypes.c_uint),
                ('firm_offset', ctypes.c_uint),
                ('firm_size', ctypes.c_uint)]

    def __init__(self):
        self.checksum0 = 0x8b12bab6
        self.checksum1 = 0x93d7de9b
        self.checksum2 = 0xcdd8d0d2
        self.checksum3 = 0x7e5deb16
        self.unknown = 512

    @property
    def sanity(self):
        return self.checksum0 == 0x8b12bab6 and \
                self.checksum1 == 0x93d7de9b and \
                self.checksum2 == 0xcdd8d0d2 and \
                self.checksum3 == 0x7e5deb16 and \
                self.unknown == 512

    def pack(self):
        return buffer(self)[:] + NULL_BUF[:0x200 - ctypes.sizeof(self)]

    def unpack(self, buf):
        ctypes.memmove(ctypes.addressof(self), buf,
                       ctypes.sizeof(self))

def block_encrypt(p, k, buf):
    aa = k
    bb = (ror(p, 7) + p) & 0xffffffff
    cc = ror(bb, 2)
    dd = (cc + bb) & 0xffffffff
    ee = 0
    out = ''
    for x in xrange(0, len(buf), 4):
        v = struct.unpack('I', buf[x:x + 4])[0]
        a = v ^ aa ^ dd ^ ee
        aa = ror(aa, 10)
        ee = ror(a, 15)
        dd = (dd + 0x561a9c1a) & 0xffffffff
        cc = a
        out += struct.pack('I', a)
    return out

def block_decrypt(p, k, buf):
    aa = k
    bb = (ror(p, 7) + p) & 0xffffffff
    cc = ror(bb, 2)
    dd = (cc + bb) & 0xffffffff
    ee = 0
    out = ''
    for x in xrange(0, len(buf), 4):
        a = struct.unpack('I', buf[x:x + 4])[0]
        v = a ^ aa ^ dd ^ ee
        aa = ror(aa, 10)
        ee = ror(a, 15)
        dd = (dd + 0x561a9c1a) & 0xffffffff
        cc = a
        out += struct.pack('I', v)
    return out
