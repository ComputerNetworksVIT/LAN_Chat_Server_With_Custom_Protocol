import socket, threading

def recv_msgs(sock):
    while True:
        try:
            msg = sock.recv(1024)
            if not msg:
                break
            print(msg.decode(), end="")
        except:
            break

def main():
    print("=== LAN Chat Client ===")
    ip = input("Server IP [127.0.0.1]: ") or "127.0.0.1"
    port = int(input("Port [5555]: ") or "5555")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    print("✅ Connected to server.")
    threading.Thread(target=recv_msgs, args=(sock,), daemon=True).start()

    while True:
        msg = input("> ")
        if msg.lower() == "exit":
            break
        sock.send((msg + "\n").encode())

    sock.close()
    print("Disconnected.")

if __name__ == "__main__":
    main()
