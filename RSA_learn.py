# 汇聚了其他几个文件的总文件，这个类主要实现了pkcs#1 v1.5的加解密(RSAESPKCS1-v1.5)，签名验签(RSASSA-PKCS1-v1.5)
# pkcs#1 v2.2的加解密(RSAES-OAEP)签名验签(RSASSA-PSS)，用之前请详细阅读README.md

from analysis_pem import *
from RSA_Key_Generation import *
from RSA_PKCS_v1_5 import *
from RSA_PKCS_v2_2 import *
from Auxiliary_function import *

class RSA_Learn:
    def __init__(self):
        self.n = None
        self.d = None
        self.e = None
        self.p = None
        self.q = None

    def Print_RSA_parameters(self):
        if self.n is not None and self.d is not None and self.e is not None and self.p is not None and self.q is not None:         
            print("n = 0x%x" % self.n)
            print("e = 0x%x" % self.e)
            print("d = 0x%x" % self.d)
            print("p = 0x%x" % self.p)
            print("q = 0x%x" % self.q)
        else:
            print('缺少n,e,d,p,q参数,得全部输入才能打印')

    def Get_key_from_private_key(self, path: str):
        analysis_pem_instance = analysis_pem()
        self.n, self.e, self.d, self.p , self.q, _, _, _ = analysis_pem_instance.get_private_key_from_pem(path)
    
    def Generate_key(self, nbits: int = 2048):
        RSA_key_generation_instance = RSAKeyGeneration()
        self.n, self.e, self.d, self.p , self.q = RSA_key_generation_instance.gen_keys(nbits)

    def Encrypt_data(self, padding: str, data_to_enc: str) -> str:
        if padding == 'PKCS1':
            RSA_PKCS_v1_5_instance = RSA_PKCS_v1_5()
            Enc_Data = RSA_PKCS_v1_5_instance.rsa_encryption(data_to_enc, self.n, self.e)
            return Enc_Data
        elif padding == 'OAEP':
            RSA_PKCS_v2_2_instance = RSA_PKCS_v2_2()
            Enc_Data = RSA_PKCS_v2_2_instance.oaep_encrypt(self.n, self.e, data_to_enc)
            return Enc_Data
        else:
            return 'Padding type error, it only support PKCS1 or OAEP.'
        
    def Decrypt_data(self, padding: str, data_to_dec: str) -> str:
        if padding == 'PKCS1':
            RSA_PKCS_v1_5_instance = RSA_PKCS_v1_5()
            Dec_Data = RSA_PKCS_v1_5_instance.rsa_decryption(data_to_dec, self.n, self.d)
            return Dec_Data
        elif padding == 'OAEP':
            RSA_PKCS_v2_2_instance = RSA_PKCS_v2_2()
            Dec_Data = RSA_PKCS_v2_2_instance.oaep_decrypt(self.n, self.d, data_to_dec)
            return Dec_Data
        else:
            return 'Padding type error, it only support PKCS1 or OAEP.'
    
    def Sign_data(self, padding: str, data_to_sign: str, hash_method: HashType = 'SHA-256') -> str:
        if padding == 'PKCS1':
            RSA_PKCS_v1_5_instance = RSA_PKCS_v1_5()
            sign_result = RSA_PKCS_v1_5_instance.rsa_sign(data_to_sign, self.n, self.d)
            return sign_result
        elif padding == 'PSS':
            RSA_PKCS_v2_2_instance = RSA_PKCS_v2_2()
            sign_result = RSA_PKCS_v2_2_instance.pss_sign(self.n, self.d, data_to_sign)
            return sign_result
        else:
            return 'Padding type error, it only support PKCS1 or PSS.'
        
    def Verify_data(self, padding: str, data_to_verify: str, sign_data: str) -> bool:
        if padding == 'PKCS1':
            RSA_PKCS_v1_5_instance = RSA_PKCS_v1_5()
            sign_result = RSA_PKCS_v1_5_instance.rsa_verify(data_to_verify, sign_data, self.n, self.e)
            return sign_result
        elif padding == 'PSS':
            RSA_PKCS_v2_2_instance = RSA_PKCS_v2_2()
            sign_result = RSA_PKCS_v2_2_instance.pss_verify(self.n, self.e, data_to_verify, sign_data)
            return sign_result
        else:
            return 'Padding type error, it only support PKCS1 or PSS.'


if __name__ == '__main__':
    path = "D:\\vscode_program\\python\\private_key.pem"
    Auxiliary_function_instance = Auxiliary_function.Aux_function()

    ### 使用demo
    demo = RSA_Learn()

    ### 1.首先得给类的n,d,e,p,q赋值,下面3中方法取一种即可
    ### 可以直接通过赋值的方式进行，这只是个例子，下面的值长度不够用的，应该会报错，没试过
    # demo.n = 0x12345
    # demo.e = 789
    # demo.d = 456
    # demo.p = 123
    # demo.q = 234
    # demo.Print_RSA_parameters()

    ### 也可以通过私钥文件获取
    ### 这里只支持读私钥，私钥里包含了公钥信息，主要还是懒得做了，这个项目主要用于学习和测试，不推荐实际项目调用
    # demo.Get_key_from_private_key(path)
    # demo.Print_RSA_parameters()

    ### 也可以通过生成一组rsa参数的方式，不过不支持转换成pem等其他格式，原因是我用不上就懒得写
    ### 可以生成自定义长度的密钥，默认为2048bit=256byte,整个项目我都只测试256字节长度的密钥，其它长度能不能用不知道
    demo.Generate_key()
    # # demo.Generate_key(1024)
    demo.Print_RSA_parameters()

    ### 2. 获取RSA参数后就能进行加密解密、签名验签操作了
    ### 加密，仅支持pkcsv1.5-pkcs1和pkcsv2.2-OAEP, 哈希的方式都为sha-256直接默认了，如果想用其他哈希就自己修改该代码吧
    ### 其他的哈希我没有测试过，所以在这里就直接定死为sha-256了，pkcsv2.2-OAEP的MGFHash也是sha-256
    ### 加密结果默认为base64格式，如果你需要看hex形式的得转换
    Encrypt_PKCS1_5_Result = demo.Encrypt_data('PKCS1','你好啊')
    print('加密结果base64格式 =',Encrypt_PKCS1_5_Result) # 打印base64格式的结果
    Encrypt_OAEP_Result = demo.Encrypt_data('OAEP','你好啊')   
    print('加密结果str(hex)格式 =', hex(Auxiliary_function_instance.bytes2int(base64.b64decode(Encrypt_OAEP_Result))))

    ### 解密，仅支持pkcsv1.5-pkcs1和pkcsv2.2-OAEP
    Encrypt_PKCS1_5_Result = demo.Decrypt_data('PKCS1', Encrypt_PKCS1_5_Result)
    print('PKCS1.5解密结果 =',Encrypt_PKCS1_5_Result)
    ### 解密的输入数据应位base64格式，如果不对请转换，这里假设是int格式,hex其实就是int格式，所以直接复制0x***赋值也行
    Encrypt_OAEP_Result = Auxiliary_function_instance.bytes2int(base64.b64decode(Encrypt_OAEP_Result))
    Encrypt_OAEP_Result = base64.b64encode(Auxiliary_function_instance.int2bytes(Encrypt_OAEP_Result))
    Decrypt_Result = demo.Decrypt_data('OAEP',Encrypt_OAEP_Result)
    print('OAEP解密结果 =',Decrypt_Result)

    ### 签名,仅支持RSASSA-PKCS1-v1.5和RSASSA-PSS, Hash=sha.256, RSASSA-PSS=sha.256
    ### 签名结果默认为base64格式，如果你需要看hex形式的得转换
    message = '你好啊'
    Sign_PKCS1_5_Result = demo.Sign_data('PKCS1', message)
    print('签名结果base64格式 =',Sign_PKCS1_5_Result) # 打印base64格式的结果
    Sign_PSS_Result = demo.Sign_data('PSS', message)
    print('签名结果str(hex)格式 =', hex(Auxiliary_function_instance.bytes2int(base64.b64decode(Sign_PSS_Result))))

    ### 验签，仅支持RSASSA-PKCS1-v1.5和RSASSA-PSS, Hash=sha.256, RSASSA-PSS=sha.256，验签结果为True or False
    Verify_PKCS1_5_Result = demo.Verify_data('PKCS1', message, Sign_PKCS1_5_Result)
    print('PKCS1.5验签结果 =',Verify_PKCS1_5_Result)
    Verify_PSS_Result = demo.Verify_data('PSS', message, Sign_PSS_Result)
    print('PSS验签结果 =', Verify_PSS_Result)
