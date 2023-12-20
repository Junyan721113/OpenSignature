from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import getpass

# 定义签名函数的返回值，代表错误类型
SUCCESS = 0
KEYFILE_INVALID = 1
INFILE_INVALID = 2
PASSWD_INVALID = 3


def sign_file(keyfile: str, passwd: str, infile: str):
    passwd = passwd.encode("utf-8")
    # 判断私钥文件是否存在
    if not os.path.exists(keyfile):
        return KEYFILE_INVALID

    # 判断待签名文件是否存在
    if not os.path.exists(infile):
        return INFILE_INVALID

    # 加载私钥
    with open(keyfile, "rb") as keyfile_opened:
        try:
            private_key = serialization.load_pem_private_key(
                keyfile_opened.read(),
                password=passwd
            )
        except ValueError:
            return PASSWD_INVALID

    # 待签名的数据
    with open(infile, "rb") as infile_opened:
        in_file_raw = infile_opened.read()

    # 创建签名
    signature = private_key.sign(
        in_file_raw,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # print("Signature: ", signature)
    # print("Signature Length: ", len(signature))

    # 提取文件扩展名
    infile_name = infile.split(".")[-2]
    infile_ext = infile.split(".")[-1]

    # 保存签名后的文件
    with open(infile_name + ".signed." + infile_ext, "wb") as f:
        f.write(in_file_raw + signature)

    return SUCCESS


def console_main(language):
    if language == "1":
        keyfile_text = "【消息】请输入私钥名称: "
        passwd_text = "【消息】请输入密码: "
        infile_text = "【消息】请输入待签名的文件路径: "
        keyfile_invalid_text = "【失败】私钥文件不存在!"
        infile_invalid_text = "【失败】待签名的文件不存在!"
        passwd_invalid_text = "【失败】密码错误!"
        success_text = "【成功】签名成功!"
    else:
        keyfile_text = "[Info] Please input the name of private key: "
        passwd_text = "[Info] Please input the password: "
        infile_text = "[Info] Please input the path of file to be signed: "
        keyfile_invalid_text = "[Fail] Private key file does not exist!"
        infile_invalid_text = "[Fail] File to be signed does not exist!"
        passwd_invalid_text = "[Fail] Password wrong!"
        success_text = "[Done] Signature success!"

    ret = -1

    while ret != SUCCESS:
        if ret == KEYFILE_INVALID:
            print(keyfile_invalid_text)
        elif ret == INFILE_INVALID:
            print(infile_invalid_text)
        elif ret == PASSWD_INVALID:
            print(passwd_invalid_text)

        keyfile_name = input(keyfile_text)
        passwd = getpass.getpass(passwd_text)  # 隐藏输入密码
        infile = input(infile_text)
        ret = sign_file(keyfile, passwd, infile)

    print(success_text)


if __name__ == "__main__":
    # 中英文提示
    language = input("中文请输入 1，English please input 2: ")

    console_main(language)
