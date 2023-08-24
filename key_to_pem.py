# 这是一个单独的文件，跟其他的没有关系，如果你相用RSA参数生成pem就用这个，再此之前需要安装库。
# 不过不推荐用这个，生成pem的方法很多，直接通过网页即可，要简便很多，硬要用这个也可以

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# 假设 n, e 和 d 已知
e = 0x10001
n = 0x8fc5a68d1b1a11294ae4778ba3482244000c3ed53114c8b0af5e74ab6a8b452aa9e24dc75868bd2b21f6f09b424ea1bfd07d0acc62b0293f4aded5a621f637e0385cda10e2d33310b3ed6938e112ccc2597849f13fcc2f42bb17c36a3e05f704292147621bacd5290a7b96d3d0601476f3a44782062cf7de38a0b7f50fc742deb1b2caedcd5a3af6c76e1ff88ad3aa3b59bd73f2411037875769167833385644a2aa9dcae50bf3d3d52681a0271c349a335e303890ad302f84d7434797e5c7f285a1a0cbe1c242a8215b67201dc114e1a5ec80155258d5993d6c4de36e436f23cbc9a515bc8618c16423855c323c75fad0c9dabbe9b021f07a81c01529e23f47
p = 0xb9b0dc817733b8e0ca56c582057baa1a63178d8463100747181461c47e01c49fb8806d6c97628c62c7bccaa5a90a9e429d4e1082176539098e6db447f23e26b5b7f3436d81f5b66ae7c89f6bd0b768a882843f150ef67e4814b95be8aa2445ef112e750213ab86a4ba7d678a319ac77077f668221fd17c2460ebf537a39fcfb1718a3ea401a57deb
q = 0xc63592ab93cd010a3ca15cba1556d3774098c3244d279aed9724da18ed664609c5b6fb5507d98dfb113307c82d7c0076b42b64d050dd0508eea274aa523ef6187ccd69a977641c4555888c5169df33c278dea7addf825622cf1f38ef55a7ad864fc89c1a512886644661f98b9e5243cb9689a706e4330115
d = 0x2ad4b31d6e69819b4f986894ccfbfc594dba582da305921430ea6ecf725a332cd697789c5e963564d8257ce0840c70db77fd086e8327ffe1bf284b75c6c0573d110d785977797bc90a113c3b99b1c416521927ce1b37750ce837d81b9a86a46434ec991b7d2b2c05a1fdd79d1a82c515fad782061658e72eb1563b866079f3ae1472b19abe5c6bc341848b2ef205938ee818b7d1d27ad5a0e037e541d78ac4aa385772fa5ba08e2bc7b0782a7f9153c82fcf4cff8f4697f4b834a6db6e3e92865b24611ef3cc4204e57b09a0813e224b5dcb209a4c2399d198fa4eea0b4d0de13645bb0dde405c574be8151fa4af6b3d2366ab91d447267ef6240be1848b7321
phi = (p - 1) * (q - 1)
dmp1 = d % (p - 1)
dmq1 = d % (q - 1)
iqmp = pow(q, -1, p)

public_num = rsa.RSAPublicNumbers(e, n)
private_key = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_num).private_key(default_backend())
public_key = private_key.public_key()

# 转换为 PEM 格式
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 将 PEM 格式的公钥和私钥写入文件
with open("private_key.pem", "wb") as f:
    f.write(pem_private_key)

with open("public_key.pem", "wb") as f:
    f.write(pem_public_key)
