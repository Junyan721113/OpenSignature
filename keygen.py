import cryptography.hazmat.primitives.asymmetric as asym
from cryptography.hazmat.primitives import serialization
import os
import getpass

# 定义密钥生成函数的返回值，代表错误类型
SUCCESS = 0
KEYNAME_EXISTS = 1
KEYNAME_INVALID = 2
PASSWD_INVALID = 3


def genRSA(keyname: str, passwd: str):
    passwd = passwd.encode("utf-8")
    # 创建RSA密钥对
    private_key = asym.rsa.generate_private_key(public_exponent=65537,
                                                key_size=4096)

    # 判断是否存在重名文件
    if os.path.exists("./secrets/" + keyname + "_private_encrypted.pem"):
        return KEYNAME_EXISTS
    if os.path.exists("./keys/" + keyname + "_public.pem"):
        return KEYNAME_EXISTS

    # 判断密钥名是否合法
    if not keyname.isalnum():
        return KEYNAME_INVALID

    # 判断密码是否过短
    if len(passwd) < 6:
        return PASSWD_INVALID

    # 保存私钥
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passwd)
    )
    with open("./secrets/" + keyname + "_private_encrypted.pem", "wb") as f:
        f.write(pem)

    # 保存公钥
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("./keys/" + keyname + "_public.pem", "wb") as f:
        f.write(pem)

    return SUCCESS


def console_main(language):
    if language == "1":
        keyname_text = "【消息】首先, 给你的密钥取一个响当当的名字: "
        passwd_text = "【消息】然后, 给你的密钥设置一个不少于 6 位的密码！\n【消息】输入的文字不会显示在屏幕上哦: "
        keyname_exist_text = "【失败】已经有人起了这个名字啦，请换一个吧: "
        keyname_invalid_text = "【失败】名字怪怪的哦，请换一个吧: "
        passwd_invalid_text = "【失败】密码太短啦，请换一个吧: "
        success_text = "【成功】密钥生成完成! 请在 keys 文件夹中查看公钥, secrets 文件夹中查看私钥!\n不要把私钥告诉别人哦!"
    else:
        keyname_text = "[Info] First, give your key a name: "
        passwd_text = "[Info] Then, set a password for your key!\n[Info] The input text will not be displayed on the screen: "
        keyname_exist_text = "[Fail] Someone has already taken this name, please change it: "
        keyname_invalid_text = "[Fail] The name is weird, please change it: "
        passwd_invalid_text = "[Fail] The password is too short, please change it: "
        success_text = "[Done] The key is generated successfully! Please check the public key in the keys folder and the private key in the secrets folder!\nDon't tell anyone your private key!"

    ret = -1

    while ret != SUCCESS:
        if ret == KEYNAME_EXISTS:
            print(keyname_exist_text)
        elif ret == KEYNAME_INVALID:
            print(keyname_invalid_text)
        elif ret == PASSWD_INVALID:
            print(passwd_invalid_text)

        keyname = input(keyname_text)
        passwd = getpass.getpass(passwd_text)  # 隐藏输入密码
        ret = genRSA(keyname, passwd)

    print(success_text)


if __name__ == "__main__":
    # 中英文提示
    language = input("中文请输入 1，English please input 2: ")
    console_main(language)
