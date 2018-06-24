# encoding:utf-8
import hashlib
import ctypes
import ctypes.util
import sys
import ConfigParser
import base58_encode as b58

inifile = ConfigParser.SafeConfigParser()
inifile.read('../config.ini')
target = inifile.get('setting', 'target')
count_max = inifile.getint('setting', 'count')
version = inifile.getint('setting', 'version')

print('[setting]')
print('target : ' + target)
print('prefix : ' + str(version))
print('Find ' + str(count_max) + ' address')
print('Search Start!!')

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

count = 0

while count < count_max:
    # sslでsecp256k1の新しい鍵を作る
    ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
    secp256k1 = ssl.EC_KEY_new_by_curve_name(714)
    ssl.EC_KEY_generate_key(secp256k1)
    
    # get pubkey
    size = ssl.i2o_ECPublicKey(secp256k1, 0)
    mb = ctypes.create_string_buffer(size)
    ssl.i2o_ECPublicKey(secp256k1, ctypes.byref(ctypes.pointer(mb)))
    pubkey = mb.raw.rjust(32, chr(0))
    
    # get privkey
    bn = ssl.EC_KEY_get0_private_key(secp256k1);
    bytes = (ssl.BN_num_bits(bn) + 7) / 8
    mb = ctypes.create_string_buffer(bytes)
    n = ssl.BN_bn2bin(bn, mb)
    secret = mb.raw
    
    # アドレスをsha256でダイジェスト取得してさらにRIPEMD-160でダイジェスト取得
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(pubkey).digest())
    hash160 = h1.digest()

    # base58 encode
    address = b58.base58_encode(hash160, version)
    secretkey = b58.base58_encode(secret, 128+version)

    if address.startswith(target):
        print(address,secretkey)
        count += 1

    ssl.EC_KEY_free(secp256k1)

print('Search End!!')