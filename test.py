#!/usr/bin/env python
# coding: utf-8

# In[1]:


from ctypes import *
import numpy as np
_so = cdll.LoadLibrary('./mkckks.so')


# In[2]:


class _Ldouble(Structure):
    _fields_ = [
        ('data', POINTER(c_double)),
        ('size', c_size_t)
    ]

class _Luint64(Structure):
    _fields_ = [
        ('data', POINTER(c_ulonglong)),
        ('size', c_size_t)
    ]

# class _Params(Structure):
#     _fields_ = [
#         ('qi', _Luint64),
#         ('pi', _Luint64),

#         ('logN', c_int),
#         ('logSlots', c_int),
#         ('gamma', c_int),

#         ('scale', c_double),
#         ('sigma', c_double)
#     ]
    
class _ParametersLiteral(Structure):
    _fields_ = [
        ('qi', _Luint64),
        ('pi', _Luint64),

        ('logN', c_int),
        ('logSlots', c_int),

        ('scale', c_double),
        ('sigma', c_double)
    ]
    
class _Poly(Structure):
    _fields_ = [
        ('coeffs', POINTER(_Luint64)),
        ('IsNTT', c_bool),
        ('IsMForm', c_bool),
        ('size', c_size_t)
    ]

# class _PolyPair(Structure):
#     _fields_ = [
#         ('p0', _Poly),
#         ('p1', _Poly)
#     ]
    
class _PolyQP(Structure):
    _fields_ = [
        ('Q', POINTER(_Poly)),
        ('P', POINTER(_Poly))
    ]

class _PolyQPPair(Structure):
    _fields_ = [
        ('qp0', _PolyQP),
        ('qp1', _PolyQP)
    ]
    
class _Share(Structure):
    _fields_ = [
        ('data', POINTER(_Poly)),
        ('size', c_size_t)
    ]
    
class _Ciphertext(Structure):
    _fields_ = [
        ('data', POINTER(_Poly)),
        ('size', c_size_t),
        ('idxs', POINTER(c_int)),
        ('scale', c_double),
        # ('isNTT', c_bool)
    ]

class _Data(Structure):
    _fields_ = [
        ('data', POINTER(_Ciphertext)),
        ('size', c_size_t)
    ]

class _MPHEServer(Structure):
    _fields_ = [
        # ('params', _Params),
        ('paramsLiteral', _ParametersLiteral),
        ('crs', _Poly),
        ('sk', _PolyQP),
        ('pk', _PolyQPPair),

        # ('secretKey', _Poly),
        ('data', _Data),
        ('idx', c_int),
    ]



# In[3]:


_newMPHEServer = _so.newMPHEServer
_newMPHEServer.restype = POINTER(_MPHEServer)

# _genCRS = _so.genCRS
# _genCRS.argtypes = [ POINTER(_Params) ]
# _genCRS.restype = POINTER(_Poly)

_encryptFromPk = _so.encryptFromPk
_encryptFromPk.argtypes = [ POINTER(_PolyQPPair), POINTER(c_double), c_size_t, c_int]
_encryptFromPk.restype = POINTER(_Ciphertext)

_partialDecrypt = _so.partialDecrypt
_partialDecrypt.argtypes = [ POINTER(_PolyQP), POINTER(_Ciphertext), c_int]
_partialDecrypt.restype = POINTER(_Ciphertext)

_ringQAddLvl = _so.ringQAddLvl
_ringQAddLvl.argtypes = [ POINTER(_Ciphertext), c_int, POINTER(_Ciphertext), c_int]
_ringQAddLvl.restype = POINTER(_Ciphertext)

_decodeAfterPartialDecrypt = _so.decodeAfterPartialDecrypt
_decodeAfterPartialDecrypt.argtypes = [ POINTER(_Ciphertext) ]
_decodeAfterPartialDecrypt.restype = POINTER(_Ldouble)

_addCTs = _so.addCTs
_addCTs.argtypes = [ POINTER(_Ciphertext), POINTER(_Ciphertext)]
_addCTs.restype = POINTER(_Ciphertext)

_multiplyCTConst = _so.multiplyCTConst
_multiplyCTConst.argtypes = [ POINTER(_Ciphertext), c_double]
_multiplyCTConst.restype = POINTER(_Ciphertext)



# -----------------

# class _MPHEClient(Structure):
#     _fields_ = [
#         ('params', _Params),
#         ('crs', _Poly),
#         ('secretKey', _Poly),
#         ('decryptionKey', _Poly)
#     ]



### Wrapper Classes (pickle-able) ###

# class Params:
#     def __init__(self, _params):
#         self.qi = _Conversion.from_luint64(_params.qi)
#         self.pi = _Conversion.from_luint64(_params.pi)
#         self.logN = _params.logN
#         self.logSlots = _params.logSlots
#         self.scale = _params.scale
#         self.sigma = _params.sigma
    
#     # So we can send to Lattigo
#     def make_structure(self):
#         _params = _Params()
        
#         _params.qi = _Conversion.to_luint64(self.qi)
#         _params.pi = _Conversion.to_luint64(self.pi)
#         _params.logN = self.logN
#         _params.logSlots = self.logSlots
#         _params.scale = self.scale
#         _params.sigma = self.sigma

#         return _params

class ParametersLiteral:
    def __init__(self, _paramsLiteral):
        self.qi = _Conversion.from_luint64(_paramsLiteral.qi)
        self.pi = _Conversion.from_luint64(_paramsLiteral.pi)
        self.logN = _paramsLiteral.logN
        self.logSlots = _paramsLiteral.logSlots
        self.scale = _paramsLiteral.scale
        self.sigma = _paramsLiteral.sigma
    
    # So we can send to Lattigo
    def make_structure(self):
        _paramsLiteral = _ParametersLiteral()
        
        _paramsLiteral.qi = _Conversion.to_luint64(self.qi)
        _paramsLiteral.pi = _Conversion.to_luint64(self.pi)
        _paramsLiteral.logN = self.logN
        _paramsLiteral.logSlots = self.logSlots
        _paramsLiteral.scale = self.scale
        _paramsLiteral.sigma = self.sigma

        return _paramsLiteral

# use self.data instead of value used in go to be compatible with helper func to_list_with_conv() 
class Ciphertext:
    def __init__(self, _ct):
        self.data = [ None ] * _ct.size
        self.idxs = [ None ] * _ct.size

        for i in range(_ct.size):
            # self.data[i] = _Conversion.from_poly(_ct.data[i])
            self.data[i] = Poly(_ct.data[i])
            self.idxs[i] = _ct.idxs[i]
        self.scale = _ct.scale
        # self.idx = _ct.idx
        # self.isNTT = _ct.isNTT
    
    # So we can send to Lattigo
    def make_structure(self):
        _ct = _Ciphertext()

        data = [ None ] * len(self.data)
        idxs = [ None ] * len(self.idxs)
        for i in range(len(self.data)):
            data[i] = self.data[i].make_structure()
            idxs[i] = self.idxs[i]

        _ct.size = len(data)
        _ct.data = (_Poly * _ct.size)(*data)
        _ct.scale = self.scale
        _ct.idxs = (c_int * _ct.size)(*idxs)
        # _ct.idx = self.idx
        # _ct.isNTT = self.isNTT

        return _ct

class Poly:
    def __init__(self, _poly):
        self.coeffs = [ None ] * _poly.size
        
        for i in range(_poly.size):
            self.coeffs[i] = _Conversion.from_luint64(_poly.coeffs[i])
        
        
        self.IsNTT = _poly.IsNTT
        self.IsMForm = _poly.IsMForm
    
    # So we can send to Lattigo
    def make_structure(self):
        _poly = _Poly()

        coeffs = [ None ] * len(self.coeffs)
        
        for i in range(len(self.coeffs)):
            coeffs[i] = _Conversion.to_luint64(self.coeffs[i])
        
        _poly.size = len(coeffs)
        _poly.coeffs = (_Luint64 * _poly.size)(*coeffs)
        _poly.IsNTT = self.IsNTT
        _poly.IsMForm = self.IsMForm

        return _poly

class PolyQP:
    def __init__(self, _polyQP):
        # self.coeffs = [ None ] * _poly.size
        
        # for i in range(_poly.size):
        #     self.coeffs[i] = _Conversion.from_luint64(_poly.coeffs[i])
        
        
        self.Q = Poly(_polyQP.Q.contents)
        self.P = Poly(_polyQP.P.contents)
    
    # So we can send to Lattigo
    def make_structure(self):
        _polyQP = _PolyQP()
        
        _polyQP.Q.contents = self.Q.make_structure()
        _polyQP.P.contents = self.P.make_structure()

        return _polyQP

# Server that has Multi-Party Homomorphic Encryption functionality
class MPHEServer:
    def __init__(self, server_id):
        _server_ptr = _newMPHEServer(server_id)
        _server = _server_ptr.contents

        self.paramsLiteral = ParametersLiteral(_server.paramsLiteral)
        # self.crs = _Conversion.from_poly(_server.crs)
        self.sk = PolyQP(_server.sk)
        self.pk = _Conversion.from_polyQPpair(_server.pk)
        # self.sk = _Conversion.from_polyQP(_server.sk)
        # self.pk = _Conversion.from_polyQPpair(_server.pk)
        # self.secret_key = _Conversion.from_poly(_server.secretKey)
        self.data = []  # NOTE: always have this as decryptable by secret_key
        self.idx = _server.idx
    
    def encryptFromPk(self, data):
        # params = self.params.make_structure()
        # sk = _Conversion.to_poly(self.secret_key)
        pk = _Conversion.to_polyQPpair(self.pk)

        data_ptr = (c_double * len(data))(*data)
        enc_ct = _encryptFromPk(byref(pk), data_ptr, len(data), self.idx)

        # self.data = _Conversion.from_data(enc_ct.contents)
        self.data = Ciphertext(enc_ct.contents)

        return self.data
    
    def partialDecrypt(self, ciphertext):
        # params = self.params.make_structure()
        sk = self.sk.make_structure()
        # ct = _Conversion.to_data(self.data)
        ct = ciphertext.make_structure()

        partial_dec_ct = _partialDecrypt(byref(sk), byref(ct), self.idx)
        # dec_data = _Conversion.to_list(dec_data.contents)

        return Ciphertext(partial_dec_ct.contents)

    def ringAddLvl(self, ct1, ct1_idx, ct2, ct2_idx):
        op1 = ct1.make_structure()
        op2 = ct2.make_structure()
        op1 = _ringQAddLvl(op1, ct1_idx, op2, ct2_idx)

        return Ciphertext(op1.contents)

    def decodeAfterPartialDecrypt(self, ciphertext):
        ct = ciphertext.make_structure()
        res = _decodeAfterPartialDecrypt(ct)
        return _Conversion.from_ldouble(res.contents)

    def addCTs(self, ct1, ct2):
        op1 = ct1.make_structure()
        op2 = ct2.make_structure()
        res = _addCTs(op1, op2)
        return Ciphertext(res.contents)

    def multiplyCTConst(self, ct1, const):
        op1 = ct1.make_structure()
        res = _multiplyCTConst(op1, const)
        return Ciphertext(res.contents)

        
    # def gen_crs(self):
    #     params = self.params.make_structure()

    #     crs = _genCRS(byref(params))
    #     self.crs = _Conversion.from_poly(crs.contents)

    #     return self.crs
    
    def col_key_gen(self, ckg_shares):
        params = self.params.make_structure()
        sk = _Conversion.to_poly(self.secret_key)
        crs = _Conversion.to_poly(self.crs)
        shares_ptr = _Conversion.to_ptr(ckg_shares, _Conversion.to_share, _Share)
        
        cpk = _colKeyGen(byref(params), byref(sk), byref(crs), shares_ptr, len(ckg_shares))

        return _Conversion.from_polypair(cpk.contents)

    def col_key_switch(self, agg, cks_shares):
        params = self.params.make_structure()
        data = _Conversion.to_data(agg)
        shares_ptr = _Conversion.to_ptr(cks_shares, _Conversion.to_share, _Share)

        switched_data = _colKeySwitch(byref(params), byref(data), shares_ptr, len(cks_shares))
        self.data = _Conversion.from_data(switched_data.contents)

    def aggregate(self, updates):
        params = self.params.make_structure()
        data_ptr = _Conversion.to_ptr(updates, _Conversion.to_data, _Data)

        agg = _aggregate(byref(params), data_ptr, len(updates))

        return _Conversion.from_data(agg.contents)

    def average(self, n):
        params = self.params.make_structure()
        data = _Conversion.to_data(self.data)

        avg_data = _mulByConst(byref(params), byref(data), 1/n)
        self.data = _Conversion.from_data(avg_data.contents)

    # DEBUG: Decrypts its data then prints contents
    def print_data(self):
        params = self.params.make_structure()
        sk = _Conversion.to_poly(self.secret_key)
        ct = _Conversion.to_data(self.data)

        dec_data = _decrypt(byref(params), byref(sk), byref(ct))
        dec_data = _Conversion.to_list(dec_data.contents)

        print('Decrypted SERVER data:\n\t', dec_data)

# # Client that has Multi-Party Homomorphic Encryption functionality
# class MPHEClient:
#     def __init__(self):
#         _client_ptr = _newMPHEClient()
#         _client = _client_ptr.contents
        
#         self.params = Params(_client.params)
#         self.crs = []
#         self.secret_key = []
#         self.decryption_key = []

#         # EXTRA: for demonstration only
#         self.data = np.array([ 0.0, 0.0 ])
#         self.update = np.array([ 0.0, 0.0])
    
#     def define_scheme(self, params, dk):
#         self.params = params
#         self.decryption_key = dk

#     def gen_key(self):
#         params = self.params.make_structure()

#         sk = _genSecretKey(byref(params))
#         self.secret_key = _Conversion.from_poly(sk.contents)

#     def encrypt(self, public_key, data):
#         params = self.params.make_structure()
#         pk = _Conversion.to_polypair(public_key)

#         data_ptr = (c_double * len(data))(*data)
#         enc_data = _encryptFromPk(byref(params), byref(pk), data_ptr, len(data))

#         return _Conversion.from_data(enc_data.contents)

#     def decrypt(self, data):
#         params = self.params.make_structure()
#         sk = _Conversion.to_poly(self.decryption_key)
#         ct = _Conversion.to_data(data)

#         dec_data = _decrypt(byref(params), byref(sk), byref(ct))
#         dec_data = _Conversion.to_list(dec_data.contents)

#         return dec_data
    
#     def gen_ckg_share(self):
#         params = self.params.make_structure()
#         sk = _Conversion.to_poly(self.secret_key)
#         crs = _Conversion.to_poly(self.crs)

#         ckg_share = _genCKGShare(byref(params), byref(sk), byref(crs))

#         return _Conversion.from_share(ckg_share.contents)
    
#     def gen_cks_share(self, agg):
#         params = self.params.make_structure()
#         sk = _Conversion.to_poly(self.secret_key)
#         data = _Conversion.to_data(agg)

#         cks_share = _genCKSShare(byref(params), byref(sk), byref(data))

#         return _Conversion.from_share(cks_share.contents)

# Performs conversion between Structures (which contain pointers) to pickle-able classes
class _Conversion:
    # (FYI) Convert to numpy array: https://stackoverflow.com/questions/4355524/getting-data-from-ctypes-array-into-numpy

    # Generic array type Structure to list

    def to_list(_l):
        l = [ None ] * _l.size

        for i in range(_l.size):
            l[i] = _l.data[i]
        
        return l

    def to_list_with_conv(_l, conv):
        l = [ None ] * _l.size

        for i in range(_l.size):
            l[i] = conv(_l.data[i])
        
        return l

    def to_ptr(l, conv, t):
        lt = [ None ] * len(l)

        for i in range(len(l)):
            lt[i] = conv(l[i])
        
        return (t * len(lt))(*lt)

    ### _Luint64 (list of uint64)

    def from_luint64(_luint64):
        return _Conversion.to_list(_luint64)

    def to_luint64(l):
        luint64 = _Luint64()

        luint64.size = len(l)
        luint64.data = (c_ulonglong * luint64.size)(*l)

        return luint64

    ### _Ldouble (list of double)

    def from_ldouble(_ldouble):
        return _Conversion.to_list(_ldouble)

    def to_ldouble(l):
        ldouble = _Ldouble()

        ldouble.size = len(l)
        ldouble.data = (c_ulonglong * ldouble.size)(*l)

        return _ldouble
    
    # _Poly (list of Coefficients (Luint64))
        
    # def from_poly(_poly):
    #     coeffs = [ None ] * _poly.size

    #     for i in range(_poly.size):
    #         coeffs[i] = _Conversion.from_luint64(_poly.coeffs[i])

        
        
    #     return coeffs
    
    # def to_poly(coeffs):
    #     list_luint64 = [ None ] * len(coeffs)

    #     for i in range(len(coeffs)):
    #         list_luint64[i] = _Conversion.to_luint64(coeffs[i])
        
    #     _poly = _Poly()
    #     _poly.size = len(list_luint64)
    #     _poly.coeffs = (_Luint64 * _poly.size)(*list_luint64)

    #     return _poly

    # _PolyPair (list[2] of Poly)
    
    def from_polyQPpair(_qpp):
        qpp = [ None ] * 2

        qpp[0] = PolyQP(_qpp.qp0)
        qpp[1] = PolyQP(_qpp.qp1)
        
        return qpp

    def to_polyQPpair(qpp):        
        _qpp = _PolyQPPair()

        if len(qpp) != 2:
            print('ERROR: Only a list of size 2 makes a pair (not {})'.format(len(qpp)))
            return None

        _qpp.qp0 = qpp[0].make_structure()
        _qpp.qp1 = qpp[1].make_structure()

        return _qpp
        
    # def from_polypair(_pp):
    #     pp = [ None ] * 2

    #     pp[0] = _Conversion.from_poly(_pp.p0)
    #     pp[1] = _Conversion.from_poly(_pp.p1)
        
    #     return pp

    # def to_polypair(pp):        
    #     _pp = _PolyPair()

    #     if len(pp) != 2:
    #         print('ERROR: Only a list of size 2 makes a pair (not {})'.format(len(pp)))
    #         return None

    #     _pp.p0 = _Conversion.to_poly(pp[0])
    #     _pp.p1 = _Conversion.to_poly(pp[1])

    #     return _pp

    ### _Share (list of Poly)

    def from_share(_share):        
        return _Conversion.to_list_with_conv(_share, _Conversion.from_poly)

    def to_share(share):
        list_poly = [ None ] * len(share)

        for i in range(len(share)):
            list_poly[i] = _Conversion.to_poly(share[i])
        
        _share = _Share()
        _share.size = len(list_poly)
        _share.data = (_Poly * _share.size)(*list_poly)

        return _share

    ### _Data (list of Ciphertext)

    def from_data(_data):
        return _Conversion.to_list_with_conv(_data, Ciphertext)
    
    def to_data(data):
        list_ciphertext = [ None ] * len(data)

        for i in range(len(data)):
            list_ciphertext[i] = data[i].make_structure()
        
        _data = _Data()
        _data.size = len(list_ciphertext)
        _data.data = (_Ciphertext * _data.size)(*list_ciphertext)

        return _data


# In[4]:


server = MPHEServer(server_id=0) # id for FL server has to be 0
client_1 = MPHEServer(server_id=1) # id for FL client starts from 1
client_2 = MPHEServer(server_id=2)


# In[5]:


weights1 = [ 0.1, 0.2, 2.1, -2.2 ]
weights2 = [ 0.2, 0.3, 1.2, -1.2 ]


# In[6]:


ct1 = client_1.encryptFromPk(weights1)
ct2 = client_2.encryptFromPk(weights2)
ct3 = server.addCTs(ct1, ct2)


# In[7]:


ct4 = server.multiplyCTConst(ct1, 2.5)


# In[8]:


ct3_pd1 = client_1.partialDecrypt(ct3)
ct3_pd2 = client_2.partialDecrypt(ct3)


# In[9]:


ct3_pd_agg = server.ringAddLvl(ct3_pd1,0, ct3_pd1, 1)
ct3_pd_agg = server.ringAddLvl(ct3_pd_agg,0, ct3_pd2, 2)


# In[10]:


dec_ct3 = server.decodeAfterPartialDecrypt(ct3_pd_agg)
print(dec_ct3[:10])
print(np.round(dec_ct3, 2)[:10])


# In[11]:


ct4_pd1 = client_1.partialDecrypt(ct4)
ct4_agg = server.ringAddLvl(ct4_pd1,0, ct4_pd1, 1)


# In[12]:


dec_ct4 = server.decodeAfterPartialDecrypt(ct4_agg)
print(dec_ct4[:10])
print(np.round(dec_ct4, 2)[:10])


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




