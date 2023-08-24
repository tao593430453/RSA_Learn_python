# PKCS#1 v2.2(2016年) rfc8017
# MGF1 (mask generation function) 掩码生成函数
# RSAES-OAEP-ENCRYPT RSAES-OAEP-DECRYPT
# RSASSA-PSS-SIGN RSASSA-PSS-VERIFY
import hashlib
import math
import typing
import random
import base64
import Auxiliary_function

if typing.TYPE_CHECKING:
    HashType = hashlib._Hash
else:
    HashType = typing.Any

default_crypto_random = random.SystemRandom()

class RSA_PKCS_v2_2:
    def __init__(self):
        self.Auxiliary_function_instance = Auxiliary_function.Aux_function()

    # 加密解密
    def _mgf1(self, mgf_seed: bytes, mask_len: int, hash_class: HashType = hashlib.sha256) -> bytes:
        h_len = hash_class().digest_size
        if mask_len > ((2**32)* h_len):
            raise ValueError('Mask too long')
        
        T = b''
        for i in range(0, math.ceil(mask_len/h_len)):
            c = self.Auxiliary_function_instance.i2osp(i, 4)
            T = T + hash_class(mgf_seed + c).digest()
        return T[:mask_len]
    
    def oaep_encrypt(self, n: int, e: int, message: bytes, label: bytes = b'',
        hash_class: HashType = hashlib.sha256, mgf = _mgf1, seed = None,
        rnd = default_crypto_random) -> str:
        
        message = message.encode('utf-8')
        hash = hash_class()
        h_len = hash.digest_size
        k = n.bit_length() // 8
        max_message_length = k - 2 * h_len - 2
        # check length
        if len(message) > max_message_length:
            raise ValueError('Message too long')
        # EME-OAEP encoding
        hash.update(label)
        label_hash = hash.digest()

        ps = b'\0' * int(max_message_length - len(message))
        db = b''.join((label_hash, ps, b'\x01', message))

        if not seed:
            seed = self.Auxiliary_function_instance.i2osp(rnd.getrandbits(h_len * 8), h_len)

        # 这个地方换成类之后 不知道为啥搞不通，换成类的方法直接调用了
        # db_mask = mgf(seed, k - h_len - 1, hash_class = hash_class)
        db_mask = self._mgf1(seed, k - h_len - 1, hash_class = hash_class)
        masked_db = self.Auxiliary_function_instance.string_xor(db, db_mask)

        # 这个地方换成类之后 不知道为啥搞不通，换成类的方法直接调用了
        # seed_mask = mgf(masked_db, h_len, hash_class = hash_class)
        seed_mask = self._mgf1(masked_db, h_len, hash_class = hash_class)
        masked_seed = self.Auxiliary_function_instance.string_xor(seed, seed_mask)

        em = b''.join((b'\x00', masked_seed, masked_db))
        # encrypt
        m = self.Auxiliary_function_instance.os2ip(em)
        c = pow(m, e, n)
        
        return base64.b64encode(self.Auxiliary_function_instance.int2bytes(c))
    
    def oaep_decrypt(self, n: int, d: int, message: str, label: bytes = b'', hash_class = hashlib.sha256,
        mgf = _mgf1) -> bytes:
    
        hash = hash_class()
        h_len = hash.digest_size
        k = n.bit_length() // 8
        # check length
        message = base64.b64decode(message)
        if len(message) != k or k < 2 * h_len + 2:
            raise ValueError('Decryption error')
        
        # RSA decryption
        #c = os2ip(message)
        c = self.Auxiliary_function_instance.bytes2int(message)
        m = pow(c, d, n)
        em = self.Auxiliary_function_instance.i2osp(m, k)

        # EME-OAEP decoding
        hash.update(label)
        label_hash = hash.digest()
        y, masked_seed, masked_db = em[0], em[1: h_len + 1],em[1 + h_len:]

        if y != b'\x00' and y != 0:
            raise ValueError('Decryption error')
        
        # 这个地方换成类之后 不知道为啥搞不通，换成类的方法直接调用了
        # seed_mask = mgf(masked_db, h_len)
        seed_mask = self._mgf1(masked_db, h_len)
        seed = self.Auxiliary_function_instance.string_xor(masked_seed, seed_mask)

        # 这个地方换成类之后 不知道为啥搞不通，换成类的方法直接调用了
        # db_mask = mgf(seed, k - h_len -1)
        db_mask = self._mgf1(seed, k - h_len -1)
        db = self.Auxiliary_function_instance.string_xor(masked_db, db_mask)

        label_hash_prime, rest = db[:h_len], db[h_len:]
        i = rest.find(b'\x01')

        if i == -1:
            raise ValueError('Decryption Error')
        
        if rest[:i].strip(b'\x00') != b'':
            print(rest[:i].strip(b'\x00'))
            raise ValueError('Decryption Error')
        
        if label_hash_prime != label_hash:
            raise ValueError('Decryption Error')
        
        m = rest[i+1:]
        return m.decode('utf-8')
    
    # 签名验签
    def _emsa_pss_encode(self, m: bytes, embits: int, hash_class: HashType = hashlib.sha256,
        mgf = _mgf1, salt = None, s_len = None, rnd = default_crypto_random) -> bytes:
        '''
        Encode a message using the PKCS v2 pss padding.

        m - the message to encode.
        embit - the length of the padded message.     为啥这个地方长度是提前输进去的
        mgf - a mask generating function, default is mgf1, the mask generating
        function proposed in the PKCS#1 v2 standard.
        hash_class - the hash algorithm to use to compute the digest of the message,
        must conform to the hashlib class interface.
        salt - a fixed salt string to use, if None, a random string of length
        s_len - the length of the salt string when using a random generator to 
        create it, if None the length of the digest is used.
        rnd - the random generator used to compute the salt string

        Return value: the padded message
        '''

        m_hash = hash_class(m).digest()
        h_len = len(m_hash)

        if salt is not None:
            s_len = len(salt)
        else:
            if s_len is None:
                s_len = h_len
            salt = self.Auxiliary_function_instance.i2osp(rnd.getrandbits(s_len*8),s_len)
        
        em_len = math.ceil(embits / 8)
        if em_len < h_len + s_len + 2:
            raise ValueError('Encoding Error')
        
        m_prime = (b'\x00' * 8) + m_hash + salt
        h = hash_class(m_prime).digest()

        ps = b'\x00' * (em_len - s_len - h_len - 2)
        db = ps + b'\x01' + salt
        # db_mask = mgf(h, em_len - h_len -1)
        db_mask = self._mgf1(h, em_len - h_len -1)
        masked_db = self.Auxiliary_function_instance.string_xor(db, db_mask)

        octets, bits = (8 * em_len - embits) // 8, (8 * em_len - embits) % 8
        # replace first 'octets' bytes
        masked_db = (b'\x00' * octets) + masked_db[octets:]
        new_byte = self.Auxiliary_function_instance._and_byte(masked_db[octets], 255 >> bits)
        masked_db = masked_db[:octets] + new_byte + masked_db[octets+1:]

        return masked_db + h + b'\xbc'
    
    def _emsa_pss_verify(self, m: bytes, em: bytes, embits: int, hash_class = hashlib.sha256, mgf = _mgf1, s_len = None) -> bool:
        '''
        Verify that a message padded using the PKCS#1 v2 PSS algorithm matched a given
        message string.

        m - the message to match
        em - the padded message
        embits - the length in bits of the padded message
        hash_class - the hash algorithm used to compute the digest of the message
        mgf - the mask generation function
        s_len - the length of the salt, if None the length of the digest is used

        Return: Ture if the message matches,False otherwise.
        '''

        #1 cannot veritfy, does not know the max input length of hash_class
        #2 length check
        m_hash = hash_class(m).digest()
        h_len = len(m_hash)

        if s_len is None:
            s_len = h_len
        em_len = math.ceil(embits / 8)
        #3 em_len check
        if em_len < h_len + s_len +2:
            return False
        #4 bc check
        if not self.Auxiliary_function_instance._byte_eq(em[-1], b'\xbc'):
            return False
        #5 get masked_db and h
        masked_db, h = em[:em_len - h_len - 1], em[em_len - h_len - 1: -1]
        #6 zero check
        octets, bits = (8 * em_len - embits) // 8, (8 * em_len - embits) % 8
        zero = masked_db[:octets] + self.Auxiliary_function_instance._and_byte(masked_db[octets], ~(255 >> bits))

        for c in zero:
            if not self.Auxiliary_function_instance._byte_eq(c, b'\x00'):
                return False
        #7 get db_mask
        # db_mask = mgf(h, em_len - h_len - 1)
        db_mask = self._mgf1(h, em_len - h_len - 1)
        #8 get db
        db = self.Auxiliary_function_instance.string_xor(masked_db, db_mask)
        #9 set leftmost db to zero
        new_byte = self.Auxiliary_function_instance._and_byte(db[octets], 255 >> bits)
        db = (b'\x00' * octets) + new_byte + db[octets+1:]
        #10 ps check
        for c in db[:em_len - h_len - s_len - 2]:
            if not self.Auxiliary_function_instance._byte_eq(c, b'\x00'):
                return False
        # \x01 check
        if not self.Auxiliary_function_instance._byte_eq(db[em_len-h_len-s_len-2], b'\x01'):
            return False
        #11 get salt
        salt = db[-s_len:]
        #12 get m'
        m_prime = (b'\x00' * 8) + m_hash + salt
        #13 get h'
        h_prime = hash_class(m_prime).digest()
        #14 hash check
        return self.Auxiliary_function_instance.constant_compare(h_prime, h)
    
    def pss_sign(self, n: int, d: int, message: bytes, hash_class = hashlib.sha256,
        mgf = _mgf1, rnd = default_crypto_random) -> bytes:
        '''
        Sign message using private_key and the PKCS#1 2.0 RSASSA-PSS algorithm.

        private_key - the private key to use.
        message - the byte string to sign.
        emsa_pss_encode - the encoding to use, default to EMSA-PSS encoding.
        hash_class - the hash algorithme to use, default is SHA-1.
        mgf1 - the mask generating function to use, default to MGF1.
        rnd - a random number generator to use for the PSS encoding.
        '''
        message = message.encode('utf-8')
        mod_bits = n.bit_length()
        embits = mod_bits - 1
        em = self._emsa_pss_encode(message, embits)
        m = self.Auxiliary_function_instance.os2ip(em)
        s = pow(m, d, n)
        # return self.Auxiliary_function_instance.i2osp(s, mod_bits // 8)
        return base64.b64encode(self.Auxiliary_function_instance.int2bytes(s))
    
    def pss_verify(self, n: int, e: int, message: bytes, signature: bytes, hash_class = hashlib.sha256, mgf = _mgf1) -> bool:
        '''
        Verify message using public_key and the PKCS#1 2.0 RSASSA-PSS algorithm.

        public_key - the publice key to use.
        message - the byte string to verify.
        signature - the byte string of message sign.
        emsa_pss_verify - the verify to use, default to EMSA-PSS verify.
        hash_class - the hash algorithme to use, default is SHA-1.
        mgf1 - the mask generating function to use, default to MGF1.
        rnd - a random number generator to use for the PSS encoding.
        '''
        message = message.encode('utf-8')
        mod_bits = n.bit_length()
        # s = self.Auxiliary_function_instance.os2ip(signature)
        s = self.Auxiliary_function_instance.bytes2int(base64.b64decode(signature))
        m = pow(s, e, n)
        embits = mod_bits - 1
        em_len = math.ceil(embits / 8)
        em = self.Auxiliary_function_instance.i2osp(m, em_len)
        
        return self._emsa_pss_verify(message, em, embits)
    
if __name__ == "__main__":
    msg = '---嘻嘻龙赫赫炉子---'

    demo = RSA_PKCS_v2_2()
    Auxiliary_function_instance = Auxiliary_function.Aux_function()

    e = 0x10001
    n = 0xcbef678443afef6c4bcd656318fab06d230f63b7fec924da47c43d37dde2fbe6bf1bd0ea28e7b2ec4d445ce5b44a95f9fc306d6fb20d52aab49db366322087e460af44ba2605b19deca55ecc4ee1ba33e375c38424e5340e4fe71601259b9e732180db44490de3bfa09adf8e1e70834fe54e43d661f934a7fe2eacff83262f4bc2b150c98b8e627897f2a9a72274a1b823ba06e86d9f04582168682c1e8bf45aa508ed6a5b66a830edebe52af3159c1b40a4e20d60450a1f8d06a821d7d76d5d4b90f2a7213df2b5d82c184fb1305739344be6ca7b98983699f01d104a6ade122ba608acb1e31aedcb1cfc5144d653450defb1b7f3f41f163103564a640d0c5f
    p = 0xf4da4eed6642b3814e58f2ba3d8348fba5aead2c76b8e8cda96f7b47988a345298751f153d5fbbb30f4ca4dc96ad9457f1f0b3201d203e68a55dff851af0dcd74427b16390f66cadbaaed884ad423f282c8016d400ab709ebfe62da16cf11eafec69b682821d172c42a9cdfcd1054a8225a9089d1bd493ca6c672c520518f221
    q = 0xd538367696f88484e58ddfd0768a0df83dffeb7adb68efbb0c99f63420f9d82c524cc0edd2206dff6c2b77d2ec19b964b4f25cc0ce9984a0b2f95abd11df2d39632b22ce4ca4b3c0c025c61d935fd138a5404d03b3ed68873c8108ae02a60cb7170e4a99b1e37d4125a3ef7767f5155b148e7cd1a7b1c1292af358cd41cb2e7f
    d = 0x3aaa7b27f464d7465b24122788d70d0bc84b340f892f09f7f52f41c121869b9a8c9d8ee2ddb391a822ae28df3797413fb1c9a8a1ba21d5072080414c83dd11daa3e9a7a6b92b68261b1e937fc8ad6ce86265cd41e56f3e2363df0158811e1c5dd8647e2f4da8be3cb111fc7fa0c8132e57b3c51616071f9bb8266b43f1d17947194b6d0da0fcd1b82889b36f0d5f8f85973af293ae39baf1a75ca130ab4fb3e664d6edc72a717b301af2add8bcbcfa1482bcdc1e47c48d45991059219fccb74723f46ec4a31962ce7ece9c45459cd84a8546c6fbda3d56148c8d067cb236b62e4097c53b4ecb6c8fe05ce823a4b6b875c4d53580347b50ebd5325841c3d8b2c1

    # 加密解密测试
    print('RSAOEAP加密')
    m1 = demo.oaep_encrypt(n, e, msg)
    # # 如果你想看16进制的加密结果就放开下面的注释
    # m_1 = base64.b64decode(m1)
    # assert len(m_1) == n.bit_length() // 8
    # m_1 = Auxiliary_function_instance.bytes2int(m_1)
    # print('16进制的加密结果 =',hex(m_1))
    print('加密结果(base64) =', m1)
    print('pass')

    m2 = demo.oaep_decrypt(n, d, m1)
    print('RSAOEAP解密')
    print('解密结果 =',m2)
    assert msg == m2
    print('pass')

    # 签名验签测试
    sig = demo.pss_sign(n, d, msg)
    print('RSA PSS 签名测试')
    # 签名结果的长度应该位256
    assert len(base64.b64decode(sig)) == n.bit_length() // 8
    print('签名结果 =', sig)
    print('pass')

    flag = demo.pss_verify(n, e, msg, sig)
    print('RSA PSS 验签测试')
    print('验签结果 =', flag)

    
    # # MGF1测试
    # seed = (
    #     b"\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2" b"\xf0\x6c\xb5\x8f"
    # )
    # db = (
    #     b"\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90"
    #     b"\xaf\xd8\x07\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    #     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    #     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    #     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    #     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd4\x36\xe9\x95\x69"
    #     b"\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49"
    # )
    # masked_db = (
    #     b"\xdc\xd8\x7d\x5c\x68\xf1\xee\xa8\xf5\x52\x67\xc3\x1b\x2e\x8b\xb4"
    #     b"\x25\x1f\x84\xd7\xe0\xb2\xc0\x46\x26\xf5\xaf\xf9\x3e\xdc\xfb\x25"
    #     b"\xc9\xc2\xb3\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb\x4c\xdc\xfe\x4f\xf4"
    #     b"\x77\x28\xb4\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a\xb4\x8d\x28\x69\xd5"
    #     b"\x02\x41\x21\x43\x58\x11\x59\x1b\xe3\x92\xf9\x82\xfb\x3e\x87\xd0"
    #     b"\x95\xae\xb4\x04\x48\xdb\x97\x2f\x3a\xc1\x4f\x7b\xc2\x75\x19\x52"
    #     b"\x81\xce\x32\xd2\xf1\xb7\x6d\x4d\x35\x3e\x2d"
    # )

    # db_mask = demo._mgf1(seed, mask_len = len(db), hash_class = hashlib.sha1)
    # expected_db_mask = (
    #     b"\x06\xe1\xde\xb2\x36\x9a\xa5\xa5\xc7\x07\xd8\x2c\x8e\x4e\x93\x24"
    #     b"\x8a\xc7\x83\xde\xe0\xb2\xc0\x46\x26\xf5\xaf\xf9\x3e\xdc\xfb\x25"
    #     b"\xc9\xc2\xb3\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb\x4c\xdc\xfe\x4f\xf4"
    #     b"\x77\x28\xb4\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a\xb4\x8d\x28\x69\xd5"
    #     b"\x02\x41\x21\x43\x58\x11\x59\x1b\xe3\x92\xf9\x82\xfb\x3e\x87\xd0"
    #     b"\x95\xae\xb4\x04\x48\xdb\x97\x2f\x3a\xc1\x4e\xaf\xf4\x9c\x8c\x3b"
    #     b"\x7c\xfc\x95\x1a\x51\xec\xd1\xdd\xe6\x12\x64"
    # )
    # print("mgf1 test1")
    # assert db_mask == expected_db_mask
    # print("pass")

    # seed_mask = demo._mgf1(masked_db, mask_len=len(seed), hash_class=hashlib.sha1)
    # expected_seed_mask = (
    #     b"\x41\x87\x0b\x5a\xb0\x29\xe6\x57\xd9\x57\x50\xb5\x4c\x28\x3c\x08" b"\x72\x5d\xbe\xa9"
    # )

    # print("mgf1 test2")
    # assert seed_mask == expected_seed_mask
    # print('pass')
