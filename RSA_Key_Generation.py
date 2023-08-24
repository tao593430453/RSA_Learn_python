# This document mainly contains the classes used to generate a pair of public and private keys
# 这个文档主要包含了生成一对公私钥使用的类
# rsa密钥生成
# 1.计算2个大质数：p、q
# 2.计算n=p*q
# 3.计算φ(n)=(p-1)(q-1)
# 4.选取整数e与φ(n)互质，一般取e = 65537 = 2^16 + 1
# 5.计算e mod φ(n)的逆元d,即ed ≡ 1 mod φ(n) 使用扩展欧几里得算法
# 6.(n,e)即为公钥 e为公钥指数
# 7.(n,d)即为私钥 d为私钥指数

import os
import struct
import Auxiliary_function
import random
import typing

class RSAKeyGeneration:
    DEFAULT_EXPONENT = 65537 #0x10001

    def __init__(self):
        self.Auxiliary_function_instance = Auxiliary_function.Aux_function()

    def _generates_random_bytes(self, nbits: int) -> bytes:
        '''
            Generates a random number of nbit length, type is bytes.
        '''
        nbytes, rbits = divmod(nbits, 8)
        randomdata = os.urandom(nbytes)

        if rbits > 0:
            randomvalue = ord(os.urandom(1))
            randomvalue >>= 8 - rbits
            randomdata = struct.pack("B", randomvalue) + randomdata
        
        return randomdata
    
    def _generates_random_int(self, nbits: int) -> int:
        '''
            Generates a random number of nbit length.
        '''
        randomdata = self._generates_random_bytes(nbits)
        value = self.Auxiliary_function_instance.bytes2int(randomdata)

        value |= 1 << (nbits - 1)
        
        return value
    
    def _generates_random_odd_int(self,nbits: int) -> int:
        '''
            Generates a random odd number of nbit length.
        '''
        value = self._generates_random_int(nbits)

        return value | 1

    def _get_primality_testing_rounds(self, number : int) -> int:
        '''
            Returns minimun number of rounds for miller-Rabin primality testing,
            base on number bitsize.

            See: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.185-4.pdf
        '''
        bitsize = number.bit_length()

        if bitsize >= 1536:
            return 3
        if bitsize >= 1024:
            return 4
        if bitsize >= 512:
            return 7
        
        return 10
    
    def _miller_rabin_primality_testing(self, n: int, k: int) -> bool:
        '''
        Details see https://zhuanlan.zhihu.com/p/349360074
        '''
        if n < 3:
            return False
        
        d = n - 1
        r = 0

        while not(d & 1):
            r += 1
            d >>= 1

        for _ in range(k):
            a = random.randint(2, n - 1)

            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == 1:
                    return False
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _is_prime(self, number: int) -> bool:
        """
        judge a number is prime.
        """
        if number < 10:
            return number in {2, 3, 5, 7}
        
        if not (number & 1):
            return False
        
        k = self._get_primality_testing_rounds(number)

        return self._miller_rabin_primality_testing(number, k + 1)
    
    def getprime(self, nbits: int) -> int:
        """
        get a prime number.
        """
        assert nbits > 3
        while True:
            integer = self._generates_random_odd_int(nbits)

            if self._is_prime(integer):
                return integer
            
    def _find_p_q(self, nbits : int) -> typing.Tuple[int, int]:
        """
        Look for a pair of large prime numbers.
        """
        total_bits = nbits * 2

        shift = nbits // 16
        pbits = nbits + shift
        qbits = nbits - shift

        p = self.getprime(pbits)
        q = self.getprime(qbits)

        change_p = False
        while True:
            found_size = (p * q).bit_length()

            if( p != q) and (total_bits == found_size):
                break

            if change_p:
                p = self.getprime(pbits)
            else:
                q = self.getprime(qbits)
            
            change_p = not change_p

        return max(p, q), min(p, q)
    
    def gen_keys(self, nbits: int, exponent: int = DEFAULT_EXPONENT) -> typing.Tuple[int, int, int, int, int]:
        """
        return (n, p, q, e, d),
        (n,e) is Public key,
        (n,d) is Private key, 
        n=p*q , p and q are prime factors of n.
        """
        (p, q) = self._find_p_q(nbits // 2)

        n = p * q

        phi_n = (p - 1)*(q - 1)
        e = exponent

        x = pow(e, -1, phi_n)

        d = x % phi_n

        assert e * d % phi_n == 1

        return n, e, d, p, q
    
    # The following functions are only created for testing 
    def _gen_prime_tbl(self, number: int):
        prime_tbl = [2, 3, 5, 7]
        for i in range(11, number):
            for p in prime_tbl:
                if i % p == 0:
                    break
                else:
                    prime_tbl.append(i)

        return prime_tbl

    def _is_prime2(self, number: int, prime_ble) -> bool:
        for p in prime_ble:
            if number % p == 0:
                return False
        return True

if __name__ == '__main__':
    demo = RSAKeyGeneration()
    
    # print("米勒拉宾素性测试")
    # # 这个很耗时间 如果没有必要其实可以不用跑
    # tbl = demo._gen_prime_tbl(1 << 16)
    # for i in range(10000):
    #     p = demo.getprime(32)
    #     print(i)
    #     assert p.bit_length() == 32
    #     assert demo._is_prime2(p, tbl) == True
    # print("pass")

    # print("生成大质数P、Q")
    # p, q = demo._find_p_q(1024)
    # assert (p * q).bit_length() == 2048
    # print("pass")
    
    print("生成RSA公钥、私钥")
    n, e, d, p, q = demo.gen_keys(2048)
    print("n = 0x%x" % n)
    print("e = 0x%x" % e)
    print("d = 0x%x" % d)
    print("p = 0x%x" % p)
    print("q = 0x%x" % q)
    print("pass")
