import socket, threading, time, sys

# ---------- LANTP helpers ----------
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


# ---------- Receiver thread ----------
def recv_msgs(sock, auth_state):
    buffer = ""
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("\n[!] Server closed connection.")
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

                # Handle server PING → respond with PONG
                if mtype == "PING":
                    pong = encode_lantp({
                        "TYPE": "PONG",
                        "FROM": "CLIENT",
                        "CONTENT": ""
                    })
                    sock.send(pong.encode("utf-8"))
                    continue

                # Handle login success/failure
                if mtype == "AUTH_OK":
                    print("\n✅ " + content)
                    auth_state["ok"] = True
                    continue
                elif mtype == "AUTH_FAIL":
                    print("\n❌ " + content)
                    continue

                # Normal display
                print("\n💬 [" + mtype + "] " + content)
                print("> ", end="")
        except Exception as e:
            print(f"\n[!] Error: {e}")
            break
    try:
        sock.close()
    except:
        pass
    sys.exit()


# ---------- Main ----------
def main():
    print("=== LANTP Chat Client ===")
    ip = input("Server IP [127.0.0.1]: ") or "127.0.0.1"
    port = int(input("Port [5555]: ") or "5555")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return

    print("✅ Connected to server.\n")
    print("Available: SIGNUP <user> <pass> | LOGIN <user> <pass>")

    auth_state = {"ok": False}
    threading.Thread(target=recv_msgs, args=(sock, auth_state), daemon=True).start()

    # Authentication loop
    start_time = time.time()
    while not auth_state["ok"]:
        msg = input("> ").strip()
        if not msg:
            continue

        packet = encode_lantp({
            "TYPE": "SYS",          # NOTE: changed from AUTH → SYS
            "FROM": "CLIENT",
            "CONTENT": msg
        })
        sock.send(packet.encode("utf-8"))

        # Wait a bit for AUTH_OK before continuing
        waited = 0
        while not auth_state["ok"] and waited < 5:
            time.sleep(0.1)
            waited += 0.1

    # Chat loop
    print("\n✅ Authenticated. You can now chat! Type /help for commands.\n")
    while True:
        try:
            msg = input("> ").strip()
            if msg.lower() == "exit":
                break
            if not msg:
                continue

            packet = encode_lantp({
                "TYPE": "MSG",
                "FROM": "CLIENT",
                "CONTENT": msg
            })
            sock.send(packet.encode("utf-8"))
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Exiting.")
            break
        except Exception as e:
            print(f"\n[!] Error: {e}")
            break

    sock.close()
    print("Disconnected.")


if __name__ == "__main__":
    main()
