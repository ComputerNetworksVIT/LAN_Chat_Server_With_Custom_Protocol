import socket, threading, time, sys

def recv_msgs(sock):
    """Background thread to receive server messages."""
    while True:
        try:
            msg = sock.recv(1024)
            if not msg:
                print("\n[!] Server closed the connection.")
                break
            print(msg.decode(), end="")
        except ConnectionResetError:
            print("\n[!] Connection reset by server.")
            break
        except Exception as e:
            print(f"\n[!] Error: {e}")
            break
    try:
        sock.close()
    except:
        pass
    sys.exit()

def main():
    print("=== LAN Chat Client ===")
    ip = input("Server IP [127.0.0.1]: ") or "127.0.0.1"
    port = int(input("Port [5555]: ") or "5555")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return

    print("✅ Connected to server.")
    threading.Thread(target=recv_msgs, args=(sock,), daemon=True).start()

    while True:
        try:
            msg = input("> ").strip()
            if not msg:
                continue
            if msg.lower() == "exit":
                break
            sock.send((msg + "\n").encode())
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            print("\n[!] Disconnected from server.")
            break
        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt, exiting.")
            break

    try:
        sock.close()
    except:
        pass
    print("Disconnected.")

if __name__ == "__main__":
    main()
