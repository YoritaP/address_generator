#encoding:utf-8
import hashlib
import ctypes
import ctypes.util
import sys
import base58_encode as b58

target = '1Yorita'

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

while True:
    #sslでsecp256k1の新しい鍵を作る
    ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
    secp256k1 = ssl.EC_KEY_new_by_curve_name(714)
    ssl.EC_KEY_generate_key(secp256k1)
    
    #アドレス用のpubkeyを得る
    size = ssl.i2o_ECPublicKey(secp256k1, 0)
    mb = ctypes.create_string_buffer(size)
    ssl.i2o_ECPublicKey(secp256k1, ctypes.byref(ctypes.pointer(mb)))
    pubkey = mb.raw.rjust(32, chr(0))
    
    #秘密鍵を得る
    bn = ssl.EC_KEY_get0_private_key(secp256k1);
    bytes = (ssl.BN_num_bits(bn) + 7) / 8
    mb = ctypes.create_string_buffer(bytes)
    n = ssl.BN_bn2bin(bn, mb)
    secret = mb.raw
    
    #アドレスをsha256でダイジェスト取得してさらにRIPEMD-160でダイジェスト取得
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(pubkey).digest())
    hash160 = h1.digest()

    #base58にエンコード
    version = 0
    address = b58.base58_encode(hash160, version)
    secretkey = b58.base58_encode(secret, 128+version)

    if address.startswith(target):
        print(address,secretkey)


    ssl.EC_KEY_free(secp256k1)
