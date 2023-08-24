import base64
import Auxiliary_function
import typing

# 把字节按照第len位截断，并返回前后2个bytes
class analysis_pem:
    def __init__(self):
        self.Auxiliary_function_instance = Auxiliary_function.Aux_function()

    def decompose_data(self, len: int, data: bytes) ->typing.Tuple[bytes, bytes]:
        temp1 = data[:len]
        temp2 = data[len:]
        return temp1,temp2

    def analyze_data(self, flag: int, data: bytes) ->typing.Tuple[int, bytes]:
        if flag == 0x82:
            # 获取数据长度的int类型
            num_len = int.from_bytes(data[:2],byteorder='big')
            # 裁剪前2个长度位
            data = data[2:]
            result_number = data[:num_len]
            result_number = self.Auxiliary_function_instance.bytes2int(result_number)
            return result_number,data[num_len:]
        elif flag < 0x80:
            result_number = data[:flag]
            result_number = self.Auxiliary_function_instance.bytes2int(result_number)
            return result_number,data[flag:]
        elif flag == 0x81:
            # 获取数据长度的int类型
            num_len = data[0]
            # 裁剪前1个长度位
            data = data[1:]
            result_number = data[:num_len]
            result_number = self.Auxiliary_function_instance.bytes2int(result_number)
            return result_number,data[num_len:]
        else:
            raise ValueError("Num length error")
        
    # 解析pem文件请看 https://github.com/xiangyuecn/RSA-csharp n, e, d, p , q, dp, dq, InverseQx
    # 只做了pkcs8的解析，如果是pkcs1的请先去 http://tool.chacuo.net/cryptrsapkcs1pkcs8 转换一下
    def get_private_key_from_pem(self, path: str,) ->typing.Tuple[int, int, int, int, int, int, int, int]:
        with open(path, 'r') as file:
            # 以行为单位取文件
            pem_data = file.readlines()
        #去掉第一行和最后一行去掉回车拼接成一个大的字符串
        pem_data = pem_data[1:-1]
        pem_data = ''.join(pem_data)
        pem_data = pem_data.replace('\n','')

        # 转换为16进制类型
        bytes_data = base64.b64decode(pem_data)
        # print(bytes_data)
        
        # temp1 总长度 下面的注释自动加temp1,temp1解释的是 注释里的内容,bytes是裁剪注释后内容后剩下的内容
        temp1, bytes_data = self.decompose_data(4, bytes_data)

        # 固定版本号 020100
        temp1, bytes_data = self.decompose_data(3, bytes_data)

        # pkcs8固定内容0ID，在这里判断输入的是不是pcsk8的pem文件，如果不是报错退出
        temp1, bytes_data = self.decompose_data(15, bytes_data)
        temp1 = self.Auxiliary_function_instance.bytes2int(temp1)
        if temp1 != 0x300d06092a864886f70d0101010500:
            raise ValueError(".pem is not PCSK8" )

        # 固定4个字节剩下的长度
        temp1, bytes_data = self.decompose_data(4, bytes_data)
        
        # 固定4个字节剩下的长度+固定版本号 版本号为_0x020100,严格来说应该在解析数据前判断一下长度对不对，但是感觉没有必要
        temp1, bytes_data = self.decompose_data(7, bytes_data)

        # 解析n，这一块是照着256字节长度的私钥做的，如果解析不了其他长度的pem文件可能需要看情况修改后面的内容
        # 先判断第temp的第一个字节是不是02，再根据第二个字节判断长度进行相对应的操作,下面相同吗
        temp1, bytes_data = self.decompose_data(2, bytes_data)
        if temp1[0] != 0x02:
            raise ValueError("parsing n Error")
        n, bytes_data= self.analyze_data(temp1[1],bytes_data)

        # 解析e
        temp1, bytes_data = self.decompose_data(2, bytes_data)
        if temp1[0] != 0x02:
            raise ValueError("parsing e Error")
        e, bytes_data = self.analyze_data(temp1[1],bytes_data)

        # 解析d
        temp1, bytes_data = self.decompose_data(2, bytes_data)
        if temp1[0] != 0x02:
            raise ValueError("parsing d Error")
        d, bytes_data = self.analyze_data(temp1[1],bytes_data)

        # 解析p
        temp1, bytes_data = self.decompose_data(2, bytes_data)
        if temp1[0] != 0x02:
            raise ValueError("parsing p Error")
        p, bytes_data = self.analyze_data(temp1[1],bytes_data)

        # 解析q
        temp1, bytes_data = self.decompose_data(2, bytes_data)
        if temp1[0] != 0x02:
            raise ValueError("parsing q Error")
        q, bytes_data = self.analyze_data(temp1[1],bytes_data)

        # 解析dp  d mod (p-1) 下面3个数据并不影响解密和验签的结果，但是可以加快解密和验签的速度，在本demo中是没有添加快速的解密验签方法，如果需要使用需要重构解密和验签函数，如果你需要把它移植到单片机中，则需要弄一下，其他的时候并不需要
        temp1, bytes_data = self.decompose_data(2, bytes_data)
        if temp1[0] != 0x02:
            raise ValueError("parsing dp Error")
        dp, bytes_data = self.analyze_data(temp1[1],bytes_data)

        # 解析dq d mod (q-1)
        temp1, bytes_data = self.decompose_data(2, bytes_data)
        if temp1[0] != 0x02:
            raise ValueError("parsing dq Error")
        dq, bytes_data = self.analyze_data(temp1[1],bytes_data)

        # 解析InverseQ (1/q) mod p
        temp1, bytes_data = self.decompose_data(2, bytes_data)
        if temp1[0] != 0x02:
            raise ValueError("parsing InverseQ Error")
        InverseQ, bytes_data = self.analyze_data(temp1[1],bytes_data)

        # 测试调试用 可以移到上面的任何一个地方检查analyze_data的返回结果
        # temp_str = RSA_Key_Generation.bytes2int(temp1)
        # print(hex(InverseQ))
        # # print(hex(temp_str))
        # print("***********")
        # bytes_data_str = RSA_Key_Generation.bytes2int(bytes_data)
        # print(hex(bytes_data_str))

        return n, e, d, p , q, dp, dq, InverseQ

if __name__ == "__main__":
    demo = analysis_pem()
    n, e, d, p , q, dp, dq, InverseQ = demo.get_private_key_from_pem("D:\\vscode_program\\python\\161014-01-SecurityAccess.pem")
    print('n =',hex(n))
    print('e =',hex(e))
    print('d =',hex(d))
    print('p =',hex(p))
    print('q =',hex(q))


    
