#! /usr/bin/python

from ctypes import *
import socket
import struct


class IP(Structure):
    _fields_ = [
        ("version",          c_ubyte, 4),
        ("ihl",              c_ubyte, 4),
        ("tos",              c_ubyte, 8),
        ("len",              c_ushort,16),
        ("id",               c_ushort,16),
        ("offset",           c_ushort,16),
        ("ttl",              c_ubyte, 8),
        ("protocol_num",     c_ubyte, 8),
        ("sum",              c_ushort,16),
        ("src",              c_uint32,32),
        ("dst",              c_uint32,32)
        ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {
                1:"ICMP",
                6:"TCP",
                17:"UDP"
                }
        
        # Human Readble form
        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class TCP(Structure):
    _fields_ = [
        ("src_port",      c_ushort, 16),
        ("dst_port",      c_ushort, 16),
        ("seq",           c_uint32, 32),
        ("ack",           c_uint32, 32),
        ("offset_reserved", c_ubyte, 4),
        ("flags",         c_ubyte, 8),
        ("window",        c_ushort, 16),
        ("checksum",      c_ushort, 16),
        ("urg_ptr",       c_ushort, 16)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass

class UDP(Structure):
    _fields_ = [
        ("src_port",      c_ushort, 16),
        ("dst_port",      c_ushort, 16),
        ("len",           c_ushort, 16),
        ("checksum",      c_ushort, 16)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass

