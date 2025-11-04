import socket, threading, sys

# ---------- LANTP HELPERS ----------
def encode_lantp(data):
    lines = ["LANTP/1.0"]
    for k, v in data.items():
        lines.append(f"{k}: {v}")
    lines.append("<END>")
    return "\n".join(lines) + "\n"

def decode_lantp(packet):
    lines = packet.strip().split("\n")
    if not lines or not lines[0].startswith("LANTP/1.0"):
        return None
    data = {}
    for line in lines[1:]:
        if line.strip() == "<END>":
            break
        if ": " in line:
            k, v = line.split(": ", 1)
            data[k] = v
    return data

# ---------- RECEIVE THREAD ----------
def recv_msgs(sock, username, auth_state):
    buffer = ""
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("\n[!] Server closed the connection.")
                break

            buffer += data.decode("utf-8")
            while "<END>" in buffer:
                packet, buffer = buffer.split("<END>", 1)
                packet += "<END>"
                msg = decode_lantp(packet)
                if not msg:
                    continue

                mtype = msg.get("TYPE")
                content = msg.get("CONTENT", "")

                # --- Handle heartbeat ---
                if mtype == "PING":
                    sock.send(encode_lantp({
                        "TYPE": "PONG",
                        "FROM": username,
                        "CONTENT": ""
                    }).encode("utf-8"))
                    continue

                # --- Handle auth responses ---
                if mtype == "AUTH_OK":
                    print(f"\n✅ {content}")
                    auth_state["ok"] = True
                    print("> ", end="")
                    continue
                elif mtype == "AUTH_FAIL":
                    print(f"\n🚫 {content}")
                    continue

                # --- Display message types cleanly ---
                if mtype == "SYS":
                    print(f"\n💬 [SYSTEM] {content}")
                elif mtype == "CMD_RESP":
                    print(f"\n🧭 {content}")
                elif mtype == "MSG":
                    print(f"\n{content}")
                else:
                    print(f"\n{content}")

                print("> ", end="")

        except Exception as e:
            print(f"\n[!] Error: {e}")
            break
    try:
        sock.close()
    except:
        pass
    sys.exit()

# ---------- MAIN ----------
def main():
    print("=== LANTP Chat Client ===")
    ip = input("Server IP [127.0.0.1]: ") or "127.0.0.1"
    port = int(input("Port [5555]: ") or "5555")
    username = input("Enter your username: ").strip()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return

    print("✅ Connected to server.")
    auth_state = {"ok": False}
    threading.Thread(target=recv_msgs, args=(sock, username, auth_state), daemon=True).start()

    # --- AUTH LOOP (SIGNUP or LOGIN) ---
    while not auth_state["ok"]:
        print("\nAvailable: SIGNUP <user> <pass> | LOGIN <user> <pass>")
        msg = input("> ").strip()
        if not msg:
            continue
        if msg.lower() == "exit":
            sock.close()
            return
        packet = encode_lantp({
            "TYPE": "AUTH",
            "FROM": username,
            "CONTENT": msg
        })
        sock.send(packet.encode("utf-8"))
        # wait for AUTH_OK in background thread
        time_waited = 0
        while not auth_state["ok"] and time_waited < 5:
            time_waited += 0.1

    # --- MAIN CHAT LOOP ---
    try:
        while True:
            msg = input("> ").strip()
            if not msg:
                continue
            if msg.lower() == "exit":
                break
            packet = encode_lantp({
                "TYPE": "MSG",
                "FROM": username,
                "CONTENT": msg
            })
            sock.send(packet.encode("utf-8"))
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
        print("\n[!] Disconnected from server.")
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt, exiting.")
    finally:
        sock.close()
        print("Disconnected.")

if __name__ == "__main__":
    main()
