from ctypes import *

lib = ctypes.CDLL('./bench.so')  # Or hello.so if on Linux.
main = lib.main

class _Params(Structure):
    _fields_ = [
        ('qi', _Luint64),
        ('pi', _Luint64),

        ('logN', c_int),
        ('logSlots', c_int),
        
        ('scale', c_double),
        ('sigma', c_double)
    ]