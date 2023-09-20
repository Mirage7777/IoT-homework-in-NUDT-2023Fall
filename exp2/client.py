from os import path
import ssl
import socket
from logging import basicConfig, DEBUG
import sys
basicConfig(level=DEBUG)  # set now for dtls import code
from dtls import do_patch

do_patch()
blocksize = 1024

def main():
    cert_path = path.join(path.abspath(path.dirname(__file__)), "certs")
    s = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), cert_reqs=ssl.CERT_NONE,
                        ca_certs=path.join(cert_path, "ca-cert.pem"))
    s.connect(('127.0.0.1', 28000))
    # 发送文件
    try:
        while True:
            print("input ls <dir> to list files in dir.\n")
            print("input get <filename> to get files from dir.\n")
            send_msg = input(">")
            cmd,filename = send_msg.split(" ")
            try:
                s.send(send_msg.encode())
            except Exception as e:
                print("[-]Can not send Data")
            try:
                if cmd == "ls":
                    data = s.recv(blocksize)
                    print(data.decode())
                else:
                    filename = filename.split("/")[-1]
                    filedir = "./" + filename
                    with open(filedir,"wb") as fd :
                        while True:
                            data = s.recv(blocksize)
                            if data.decode() == "Already Send":
                                print("Already Reveive.")
                                break
                            fd.write(data)
    
            except Exception as e:
                print("[-]Can not receive Data")
    except KeyboardInterrupt:
        s.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
    # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # s.connect(('127.0.0.1', 28000))

