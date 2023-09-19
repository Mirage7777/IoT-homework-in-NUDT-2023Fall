import socket
import subprocess
from os import path

from dtls.err import SSLError, SSL_ERROR_ZERO_RETURN
# basicConfig(level=DEBUG)  # set now for dtls import code
from dtls.sslconnection import SSLConnection

blocksize = 1024


def main():
    current_path = path.abspath(path.dirname(__file__))
    cert_path = path.join(current_path, "certs")
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sck.bind(("127.0.0.1", 28000))
    sck.settimeout(30)

    scn = SSLConnection(
        sck,
        keyfile=path.join(cert_path, "keycert.pem"),
        certfile=path.join(cert_path, "keycert.pem"),
        server_side=True,
        ca_certs=path.join(cert_path, "ca-cert.pem"),
        do_handshake_on_connect=True)

    cnt = 0
    while True:
        cnt += 1
        print("Listen invocation: %d" % cnt)
        peer_address = scn.listen()
        if peer_address:
            print("Completed listening for peer: %s" % str(peer_address))
            break
        else:
            print("continue")
            break

    print("Accepting...")
    conn = scn.accept()[0]
    sck.settimeout(5)
    conn.get_socket(True).settimeout(5)

    cnt = 0
    while True:
        cnt += 1
        # print("Listen invocation: %d" % cnt)
        # peer_address = scn.listen()
        # assert not peer_address
        # print("Handshake invocation: %d" % cnt)
        try:
            conn.do_handshake()
        except SSLError as err:
            if err.errno == 504:
                continue
            raise
        print("Completed handshaking with peer")
        break
    # 接收文件
    cnt = 0
    while True:
        cnt+=1
        try:
            message = conn.read()
        except SSLError as err:
            if err.errno ==502:
                continue
            if err.args[0] ==SSL_ERROR_ZERO_RETURN:
                break
            raise
        data = message.decode()
        print("from client",data)
        cmd_filename = data.split(' ')
        if cmd_filename[0] != "ls" and cmd_filename !="get":
            conn.write("please input True cmd")
            continue
    
        else:
            if cmd_filename[0] == "ls":
                obj = subprocess.Popen(data,shell=True,stdout=subprocess.PIPE)
                cmd_result = obj.stdout.read()
                conn.write(cmd_result)
            else:
                filename = cmd_filename[1]
                if filename[0] == "/":
                    filedir = filename
                else:
                    if filename[2] == "./":
                        filename = filename[2:-1]
                    filedir = path.join(current_path,filename)
                with open(filedir,'r') as fd:
                    while True:
                        byte = fd.read(blocksize)
                        if not byte:
                            conn.write("Already Send".encode)
                            break
                        conn.write(byte.encode())
    


    # shutdown
    cnt = 0
    while True:
        cnt += 1
        # print("Listen invocation: %d" % cnt)
        # peer_address = scn.listen()
        # assert not peer_address
        print("Shutdown invocation: %d" % cnt)
        try:
            s = conn.unwrap()
            s.close()
        except SSLError as err:
            if err.errno == 502:
                continue
            raise
        break

    sck.close()
    pass


if __name__ == "__main__":
    main()
