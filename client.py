import socket, threading

def listen(sock):
    """Receive messages from server continuously."""
    while True:
        try:
            data = sock.recv(1024).decode()
            if not data: break
            print(data, end="")
        except:
            break

def main():
    print("=== LAN Chat Client ===")
    host = input("Server IP [127.0.0.1]: ") or "127.0.0.1"
    port = int(input("Port [5555]: ") or "5555")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print("✅ Connected to server.")
    print(sock.recv(1024).decode(), end="")

    # signup or login loop
    while True:
        cmd = input("> ").strip()
        sock.send((cmd + "\n").encode())
        resp = sock.recv(1024).decode()
        print(resp, end="")
        if resp.startswith("✅ Welcome"): break

    # start listener thread
    threading.Thread(target=listen, args=(sock,), daemon=True).start()

    print("Type messages to chat. Type EXIT to quit.\n")
    while True:
        msg = input()
        if msg.strip().upper() == "EXIT":
            sock.send(b"EXIT\n")
            break
        sock.send((msg + "\n").encode())

    sock.close()
    print("Disconnected.")

if __name__ == "__main__":
    main()
