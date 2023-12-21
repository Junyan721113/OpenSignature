from keygen import console_main as keygen_console_main
from sign import console_main as sign_console_main
from verify import console_main as verify_console_main

if __name__ == "__main__":
    # 中英文提示
    language = input("中文请输入 1，English please input 2: ")

    if language == "1":
        main_text = "#### OpenSignature 遵循 AGPL-3.0 许可证 ####\n" \
                    + "【消息】请选择你要进行的操作: \n" \
                    + "【消息】1. 生成密钥对\n" \
                    + "【消息】2. 进行签名\n" \
                    + "【消息】3. 载入公钥库\n" \
                    + "【消息】4. 验证签名\n" \
                    + "【消息】5. 退出程序\n" \
                    + "【消息】请输入你的选择: "
        enter_text = "【消息】按下回车以继续。。。"
    else:
        main_text = "#### OpenSignature is licensed under AGPL-3.0 ####\n" \
                    + "[Info] Please select the operation you want to perform: \n" \
                    + "[Info] 1. Generate key pair\n" \
                    + "[Info] 2. Sign\n" \
                    + "[Info] 3. Load public key\n" \
                    + "[Info] 4. Verify signature\n" \
                    + "[Info] 5. Exit\n" \
                    + "[Info] Please input your choice: "
        enter_text = "[Info] Press Enter to continue..."

    while True:
        choice = input(main_text)
        if choice == "1":
            # 生成密钥对
            keygen_console_main(language)
        elif choice == "2":
            # 进行签名
            sign_console_main(language)
        elif choice == "3":
            # 载入公钥库
            pass
        elif choice == "4":
            # 验证签名
            verify_console_main(language)
        elif choice == "5":
            # 退出程序
            exit(0)
        else:
            # 输入错误
            pass
        # 按任意键继续
        input(enter_text)
