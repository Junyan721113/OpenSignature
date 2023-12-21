from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import exceptions
import os

# 定义验证函数的返回值，代表错误类型
SUCCESS = 0
VERIFY_INVALID = 1
INFILE_INVALID = 2


def verify_file(infile: str):
    # 判断待验证文件是否存在
    if not os.path.exists(infile):
        return INFILE_INVALID

    # 待验证的数据
    with open(infile, "rb") as infile_opened:
        in_file_raw = infile_opened.read()

    # 遍历公钥库
    for keyfile in os.listdir("./keys"):
        with open("./keys/" + keyfile, "rb") as keyfile_opened:
            # 加载公钥
            try:
                public_key = serialization.load_pem_public_key(keyfile_opened.read())
            except ValueError:
                continue

            # 验证签名
            try:
                public_key.verify(
                    in_file_raw[-512:],
                    in_file_raw[:-512],
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except exceptions.InvalidSignature:
                continue
            else:
                keyfile_name = keyfile.split("_")[-2]
                return SUCCESS, keyfile_name

    return VERIFY_INVALID


def console_main(language):
    if language == "1":
        infile_text = "【消息】请输入待验证的文件路径: "
        infile_invalid_text = "【失败】待验证的文件不存在!"
        verify_invalid_text = "【失败】验证失败!"
        success_text = "【成功】验证成功! 来自密钥:"
    else:
        infile_text = "[Info] Please input the file path to be verified: "
        infile_invalid_text = "[Fail] The file to be verified does not exist!"
        verify_invalid_text = "[Fail] Verification failed!"
        success_text = "[Done] Verification succeeded! From key:"

    ret = -1

    while ret != SUCCESS and ret != VERIFY_INVALID:
        if ret == INFILE_INVALID:
            print(infile_invalid_text)

        infile = input(infile_text)
        ret, keyfile_name = verify_file(infile)

    if ret == VERIFY_INVALID:
        print(verify_invalid_text)
    else:
        print(success_text, keyfile_name)


if __name__ == "__main__":
    # 中英文提示
    language = input("中文请输入 1，English please input 2: ")

    console_main(language)
