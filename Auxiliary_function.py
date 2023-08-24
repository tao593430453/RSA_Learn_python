# The file contains all the auxiliary functions used in this project.
# 这个文件中包含了该项目中的所有的辅助函数
import math
import binascii

class Aux_function:
    def bytes2int(self, raw_bytes: bytes) -> int:
        '''
        Converts a bytes type to int.
        '''
        return int.from_bytes(raw_bytes, "big", signed = False)
    
    def int2bytes(self, number: int, fill_size: int = 0) -> bytes:
        '''
        Converts a int type to bytes.
        '''
        if number < 0:
            raise ValueError("Number must be an unsigned integer: %d" % number)
        
        bytes_required = max(1, math.ceil(number.bit_length() / 8))

        if fill_size > 0:
            return number.to_bytes(fill_size, "big")
        
        return number.to_bytes(bytes_required, "big")
    
    def i2osp(self, x: int, x_len: int) -> bytes:
        '''
        I2OSP 将一个非负整型值转换为一个特定长度的八位字节的字串。
        '''
        if x > 256**x_len:
            raise ValueError("Interget too large")
        
        h = hex(x)[2:]
        if h[-1] == "L":
            h = h[:-1]
        if len(h) & 1 == 1:
            h = '0%s' %h
        x = binascii.unhexlify(h)
        return b'\x00' * int(x_len - len(x)) + x

    def os2ip(self, x: bytes) -> int:
        '''
        OS2IP 将一个八位字节的字串转换为一个非负整数。
        '''
        h = binascii.hexlify(x)
        return int(h,16)

    def string_xor(self, a: bytes, b: bytes) -> bytes:
        '''
        string按位异或
        '''
        return bytes(x ^ y for (x, y) in zip(a, b))
    
    def _and_byte(self, a: bytes, b: bytes) ->bytes:
        '''
        bytes与
        '''
        return bytes([a & b])

    def _byte_eq(self, a: bytes, b: bytes) ->bytes:
        '''
        判断2个bytes是否相等
        '''
        return bytes([a]) == b

    def constant_compare(self, a: bytes, b: bytes) -> bool:
        '''
        判断2个bytes是否完全相等
        '''
        result = True
        for x, y in zip(a, b):
            result &= (x == y)
        return result
    
if __name__ == '__main__':
    Demo = Aux_function()
    number = int(1234567)
    
    temp = Demo.int2bytes(number)
    print(temp)

    temp = Demo.bytes2int(temp)
    print(temp)

    
