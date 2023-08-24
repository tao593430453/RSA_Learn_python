# PKCS#1(Public Key Cryptography Standards #1)密码学标准
# 使用RSA做数据加密、签名的时候，需要遵循的编解码标准
# PKCS#1 v1.5(1998年) rfc2313
# PKCS#1 V2.1(2003年) rfc3447
# PKCS#1 v2.2(2016年) rfc8017
###############################################################
# PKCS#1 v2.2符号(即字符串表示的意思，应该是与V1.5公用)
# n:RSA模数 见密钥生成时的5个参数中的n
# φ(n):φ(n)=(p-1)*(q-1)
# e:公钥指数 3<=e<=(n-1),gcd(e,φ(n))=1  gcd最大公约数.见RSA_01
# d:私钥指数 e位d在φ(n)的逆元
# M:消息的八位字符串表示 m:消息的整数表示,0<=m<=(n-1)
# C:密文的八位字符串表示 c:密文的整数表示,0<=c<=(n-1)
# S:签名的八位字符串表示 s:签名的整数表示,0<=s<=(n-1)
# EM:经过一定编码规则的消息传，八进制八位串i富川
# a||b:讲字符串b拼接在a后
# len(X):表示计算八位串的长度，即字节长度
# truncate(下标l)(X):表示取X最左边的1个字节，如果不足1个字节在最高位填充0补齐
###############################################################
# 数据转换
# I2OSP:整数转八位字符串，高位在左 OS2IP:八位字符串转整数
###############################################################
# 加密RSAEP: c = m^e mod n
# 解密RSADP: m = c^d mod n
# 签名RSASP1: s = m^d mod n
# 验签RSAVP1: m = s^e mod n
###############################################################
# 关于编码方案可以参考 https://blog.csdn.net/samsho2/article/details/84255173
###############################################################
import os
import typing
import base64
import hashlib
import Auxiliary_function

if typing.TYPE_CHECKING:
    HashType = hashlib._Hash
else:
    HashType = typing.Any

# ASN.1 code that describe the hash algorithm used. ASN.1哈希id 签名的时候使用
HASH_ASN1 = {
    "MD5": b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    "SHA-1": b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    "SHA-224": b"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c",
    "SHA-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    "SHA-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
}

HASH_METHODS: typing.Dict[str, typing.Callable[[], HashType]] = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
}

class RSA_PKCS_v1_5:
    def __init__(self):
        self.Auxiliary_function_instance = Auxiliary_function.Aux_function()

    # EME-PKCS1-V1.5
    # len(PS) >= 8
    # PS is nonzero random data
    # 填充,PS为随机生成的非0 M为消息的八位字符串表示
    def _pad_for_encryption(self, message: bytes, target_length: int) -> bytes:
        """
        Pads the message for encryption, returning the padded message.
        return: 00 02 PS 00 M.
        """ 
        
        max_msglength = target_length - 11
        msglength = len(message)

        if msglength > max_msglength:
            raise OverflowError("%i bytes needed for message, but there is only space for %i" %(msglength,max_msglength))

        # Get random padding
        padding = b""
        padding_length = target_length - msglength - 3
        
        # 循环填充，直到padding的长度够标准
        while len(padding) < padding_length:
            needed_bytes = padding_length - len(padding)

            # 生成指定数量的随机字节数
            new_padding = os.urandom(needed_bytes + 5)
            # str_data = ''.join(['%02x' % b for b in new_padding])
            # print(str_data)
            new_padding = new_padding.replace(b"\x00",b"")
            padding  = padding + new_padding[:needed_bytes]

        assert len(padding) == padding_length
        
        return b"".join([b"\x00\x02", padding, b"\x00", message])
    
    # EMSA-PKCS1v1.5
    # len(PS) > 8
    # PS is 0xFF
    def _pad_for_signing(self, message: bytes, target_length: int) -> bytes:
        """return: 00 01 PS 00 M."""
        max_msglength = target_length - 11
        msglength = len(message)

        if msglength > max_msglength:
            raise OverflowError("%i bytes needed for message, but there is only space for %i" %(msglength,max_msglength))
        padding_length = target_length - msglength - 3

        return b"".join([b"\x00\x01", padding_length * b"\xff", b"\x00", message])
    
    def _find_method_hash(self, clearsig: bytes) -> str:
        """
        Finds the hash method.
        :param clearsig: full padded ASN1 and hash.
        :return: the used hash method.
        :raise VerificationFailed: when the hash method cannot be found.
        """

        for (hashname,asn1code) in HASH_ASN1.items():
            if asn1code in clearsig:
                return hashname
        
        raise ValueError("Verification failed")
    
    def compute_hash(self, message: bytes, method_name: str) -> bytes:
        """Returns the message digest."""
        if method_name not in HASH_METHODS:
            raise ValueError("Invalid hash method: %s" %method_name)
        
        method = HASH_METHODS[method_name]
        hasher = method()

        hasher.update(message)

        return hasher.digest()
    
    # RSA加密
    def rsa_encryption(self, msg: str, n: int, e: int) -> str:
        '''Returns the encryption result of message(base64 type).'''
        klen = n.bit_length() // 8
        message = msg.encode('utf-8')

        # 填充
        em = self._pad_for_encryption(message, klen)
        m = self.Auxiliary_function_instance.bytes2int(em)
        # 模
        c = pow(m, e, n)

        return base64.b64encode(self.Auxiliary_function_instance.int2bytes(c))
    
    # RSA解密
    def rsa_decryption(self, enc_msg: str, n: int, d: int) ->str:
        '''Return decryption result(utf-8 type).'''
        klen = n.bit_length()  // 8

        c = self.Auxiliary_function_instance.bytes2int(base64.b64decode(enc_msg))
        m = pow(c, d, n)
        em = self.Auxiliary_function_instance.int2bytes(m, klen)

        # 加密填充的逆过程
        if em[:2] != b"\x00\x02":
            return ""
        
        sep_idx = em.find(b"\x00", 2)
        if sep_idx < 10:
            return ""
        
        return em[sep_idx + 1:].decode('utf-8')
    
    # RSA签名
    def rsa_sign(self, message: str, n: int, d: int, hash_method: HashType = "SHA-256") -> str:
        '''Return the message signature result(base64 type)'''
        if hash_method not in HASH_ASN1:
            raise ValueError("Invalid hash method %s" %hash_method)
        asn1code = HASH_ASN1[hash_method]

        klen = n.bit_length() // 8

        # Encrypt the hash with the private key
        h = self.compute_hash(message.encode('utf-8'), hash_method)
        t = asn1code + h

        em = self._pad_for_signing(t, klen)
        m = self.Auxiliary_function_instance.bytes2int(em)

        c = pow(m, d, n)

        return base64.b64encode(self.Auxiliary_function_instance.int2bytes(c))
    
    def rsa_verify(self, message: str, signature: str, n: int, e: int) -> bool:
        '''Return verify result,true or false.'''
        klen = n.bit_length() // 8

        signature = base64.b64decode(signature)
        c = self.Auxiliary_function_instance.bytes2int(signature)
        m = pow(c, e, n)
        em = self.Auxiliary_function_instance.int2bytes(m, klen)

        # Get the hash method
        method_name = self._find_method_hash(em)
        message_hash = self.compute_hash(message.encode('utf-8'), method_name)

        # Reconstruct the expected padded hash
        t = HASH_ASN1[method_name] + message_hash
        em2 = self._pad_for_signing(t, klen)

        if len(signature) != klen:
            return False
        
        # Compare with the signed one
        if em2 != em:
            return False
        
        return True
    
if __name__ == "__main__":
    demo = RSA_PKCS_v1_5()
    Auxiliary_function_instance = Auxiliary_function.Aux_function()

    msg = "---嘻嘻龙赫赫炉子---"

    n = 0x8fc5a68d1b1a11294ae4778ba3482244000c3ed53114c8b0af5e74ab6a8b452aa9e24dc75868bd2b21f6f09b424ea1bfd07d0acc62b0293f4aded5a621f637e0385cda10e2d33310b3ed6938e112ccc2597849f13fcc2f42bb17c36a3e05f704292147621bacd5290a7b96d3d0601476f3a44782062cf7de38a0b7f50fc742deb1b2caedcd5a3af6c76e1ff88ad3aa3b59bd73f2411037875769167833385644a2aa9dcae50bf3d3d52681a0271c349a335e303890ad302f84d7434797e5c7f285a1a0cbe1c242a8215b67201dc114e1a5ec80155258d5993d6c4de36e436f23cbc9a515bc8618c16423855c323c75fad0c9dabbe9b021f07a81c01529e23f47
    d = 0x2ad4b31d6e69819b4f986894ccfbfc594dba582da305921430ea6ecf725a332cd697789c5e963564d8257ce0840c70db77fd086e8327ffe1bf284b75c6c0573d110d785977797bc90a113c3b99b1c416521927ce1b37750ce837d81b9a86a46434ec991b7d2b2c05a1fdd79d1a82c515fad782061658e72eb1563b866079f3ae1472b19abe5c6bc341848b2ef205938ee818b7d1d27ad5a0e037e541d78ac4aa385772fa5ba08e2bc7b0782a7f9153c82fcf4cff8f4697f4b834a6db6e3e92865b24611ef3cc4204e57b09a0813e224b5dcb209a4c2399d198fa4eea0b4d0de13645bb0dde405c574be8151fa4af6b3d2366ab91d447267ef6240be1848b7321
    e = 0x10001
    p = 0xb9b0dc817733b8e0ca56c582057baa1a63178d8463100747181461c47e01c49fb8806d6c97628c62c7bccaa5a90a9e429d4e1082176539098e6db447f23e26b5b7f3436d81f5b66ae7c89f6bd0b768a882843f150ef67e4814b95be8aa2445ef112e750213ab86a4ba7d678a319ac77077f668221fd17c2460ebf537a39fcfb1718a3ea401a57deb
    q = 0xc63592ab93cd010a3ca15cba1556d3774098c3244d279aed9724da18ed664609c5b6fb5507d98dfb113307c82d7c0076b42b64d050dd0508eea274aa523ef6187ccd69a977641c4555888c5169df33c278dea7addf825622cf1f38ef55a7ad864fc89c1a512886644661f98b9e5243cb9689a706e4330115

    m1 = demo.rsa_encryption(msg, n, e)
    print("RSA加密后的密文 = ", m1)
    m_1 = Auxiliary_function_instance.bytes2int(base64.b64decode(m1))
    print("RSA加密后的hex密文 = ", hex(m_1))

    m2 = demo.rsa_decryption(m1, n, d)
    print("RSA解密后的铭文 = ", m2)

    assert m2 == msg
    print("RSA加解密pass")

    h1 = demo.rsa_sign(msg, n, d)
    print("RSA签名结果 = ", h1)

    h2 = demo.rsa_verify(msg, h1, n, e)
    print("RSA验签结果 = ", h2)
        
