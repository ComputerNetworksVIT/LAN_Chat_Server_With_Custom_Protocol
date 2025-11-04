import socket, threading, json, os, hashlib, time

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

# ---------- PATHS ----------
DATA_DIR = "server_data"
CONFIG_PATH = os.path.join(DATA_DIR, "server_config.json")
USERS_PATH = os.path.join(DATA_DIR, "users.json")
PENDING_PATH = os.path.join(DATA_DIR, "pending.json")

# ---------- HELPERS ----------
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()
def load_json(path, default): return json.load(open(path)) if os.path.exists(path) else default
def save_json(path, data): json.dump(data, open(path, "w"), indent=4)

# ---------- GLOBALS ----------
active_users = {}    # {username: conn}
user_roles = {}      # {username: role}
muted_users = {}     # {username: unmute_time (epoch)}
banned_users = {}    # {username: unban_time}
BAN_DURATION = 10 * 60  # 10 minutes in seconds
connected_since = {}  # {username: timestamp}

# ---------- SETUP ----------
def setup_server():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_PATH):
        print("⚙️  First-time setup detected.")
        admin_user = input("Enter admin username: ").strip()
        admin_pass = input("Enter admin password: ").strip()
        port = input("Enter port number (default 5555): ").strip() or "5555"
        users = {admin_user: {"password": hash_pw(admin_pass), "role": "admin"}}
        save_json(USERS_PATH, users)
        save_json(PENDING_PATH, {})
        save_json(CONFIG_PATH, {"setupDone": True, "port": int(port)})
        print(f"✅ Setup complete. Admin '{admin_user}' created on port {port}.")
    else:
        print("✅ Setup already completed.\n")

# ---------- ADMIN LOGIN ----------
def admin_login():
    users = load_json(USERS_PATH, {})
    while True:
        u = input("Admin username: ").strip()
        p = input("Password: ").strip()
        if u in users and users[u]["password"] == hash_pw(p) and users[u]["role"] == "admin":
            print(f"🔑 Logged in as admin '{u}'.")
            return u
        print("❌ Invalid credentials.\n")

# ---------- BROADCAST ----------
def broadcast(data, sender_conn=None):
    packet = encode_lantp(data)
    for user, conn in list(active_users.items()):
        if conn != sender_conn:
            try:
                conn.send(packet.encode("utf-8"))
            except:
                active_users.pop(user, None)

# ---------- CLIENT HANDLER ----------
def handle_client(conn, addr):
    buffer = ""
    username, role = None, "user"
    users = load_json(USERS_PATH, {})
    pending = load_json(PENDING_PATH, {})

    conn.send(encode_lantp({
        "TYPE": "SYS", "FROM": "SERVER",
        "CONTENT": "Welcome to the LAN Chat Server.\nType SIGNUP or LOGIN\n"
    }).encode())

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer += data.decode("utf-8")
            while "<END>" in buffer:
                packet, buffer = buffer.split("<END>", 1)
                packet += "<END>"
                msg = decode_lantp(packet)
                if not msg: continue

                text = msg.get("CONTENT", "").strip()

                # ---------- SIGNUP ----------
                if text.upper().startswith("SIGNUP "):
                    _, user, pw = text.split(" ", 2)
                    if user in users:
                        conn.send(encode_lantp({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": "Username already exists.\n"
                        }).encode())
                    elif user in pending:
                        conn.send(encode_lantp({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": "Signup already pending.\n"
                        }).encode())
                    else:
                        pending[user] = {"password": hash_pw(pw)}
                        save_json(PENDING_PATH, pending)
                        conn.send(encode_lantp({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": "Signup submitted. Wait for admin approval, then try LOGIN.\n"
                        }).encode())
                    continue

                # ---------- LOGIN ----------
                if user in banned_users:
                    if time.time() < banned_users[user]:
                        remaining = int((banned_users[user] - time.time()) // 60) + 1
                        conn.send(encode_lantp({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": f"🚫 You are temporarily banned. Try again in {remaining} minute(s).\n"
                        }).encode("utf-8"))
                        conn.close()
                        return
                    else:
                        # ban expired -> remove and continue with auth
                        banned_users.pop(user, None)

                    users = load_json(USERS_PATH, {})
                    if user not in users or users[user]["password"] != hash_pw(pw):
                        conn.send(encode_lantp({
                            "TYPE": "AUTH_FAIL", "FROM": "SERVER",
                            "CONTENT": "Invalid credentials or user not approved.\n"
                        }).encode("utf-8"))
                    elif user in active_users:
                        conn.send(encode_lantp({
                            "TYPE": "AUTH_FAIL", "FROM": "SERVER",
                            "CONTENT": "User already logged in elsewhere.\n"
                        }).encode("utf-8"))
                    else:
                        username, role = user, users[user]["role"]
                        active_users[user] = conn
                        user_roles[user] = role
                        connected_since[user] = time.time()
                        tag = "[Admin] " if role == "admin" else ""
                        conn.send(encode_lantp({
                            "TYPE": "AUTH_OK", "FROM": "SERVER",
                            "CONTENT": f"✅ Logged in as {tag}{user}. You can now chat.\n"
                        }).encode("utf-8"))
                        broadcast({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": f"📢 {tag}{user} joined the chat.\n"
                        }, conn)
                        break
                else:
                    conn.send(encode_lantp({
                        "TYPE": "SYS", "FROM": "SERVER",
                        "CONTENT": "Unknown command. Use SIGNUP or LOGIN\n"
                    }).encode("utf-8"))
    except:
        pass

    if not username:
        conn.close()
        return

    # ---------- CHAT LOOP ----------
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer += data.decode("utf-8")
            while "<END>" in buffer:
                packet, buffer = buffer.split("<END>", 1)
                packet += "<END>"
                msg = decode_lantp(packet)
                if not msg: continue
                text = msg.get("CONTENT", "").strip()

                # check mute
                if username in muted_users:
                    if time.time() < muted_users[username]:
                        conn.send(encode_lantp({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": "🚫 You are muted.\n"
                        }).encode("utf-8"))
                        continue
                    else:
                        # mute expired -> remove and notify the user
                        muted_users.pop(username, None)
                        conn.send(encode_lantp({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": "✅ You have been unmuted.\n"
                        }).encode("utf-8"))
                        # continue processing the message (do not do continue here)
                
                # --- Command handling ---
                if text == "/help":
                    help_text = (
                        "\n📘 Available commands:\n"
                        "  /help - show this message\n"
                        "  /users - list online users\n"
                        "  @username <msg> - private message\n"
                        "  exit - disconnect\n"
                    )
                    if role == "admin":
                        help_text += (
                            "  /kick <user> [reason] - disconnect user (10-min ban)\n"
                            "  /mute <user> <minutes> - mute user (default 5m)\n"
                            "  /unmute <user> - unmute a user\n"
                            "  /unban <user> - remove ban early\n"
                        )
                    help_text += "\n"

                    conn.send(encode_lantp({
                        "TYPE": "CMD_RESP",
                        "FROM": "SERVER",
                        "CONTENT": help_text
                    }).encode("utf-8"))
                    continue

                elif text == "/users":
                    users_list = "\n".join([
                        f"  - {u} {'[Admin]' if user_roles.get(u) == 'admin' else ''}"
                        for u in active_users.keys()
                    ]) or "  (none)"
                    conn.send(encode_lantp({
                        "TYPE": "CMD_RESP",
                        "FROM": "SERVER",
                        "CONTENT": f"👥 Online users:\n  {users_list}\n"
                    }).encode("utf-8"))
                    continue

                elif text.startswith("@"):
                    parts = text.split(" ", 1)
                    if len(parts) < 2:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP",
                            "FROM": "SERVER",
                            "CONTENT": "Usage: @username <message>\n"
                        }).encode("utf-8"))
                        continue

                    target, pm = parts
                    target = target[1:]
                    if target not in active_users:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP",
                            "FROM": "SERVER",
                            "CONTENT": f"User '{target}' not found or offline.\n"
                        }).encode("utf-8"))
                        continue

                    tag = "[Admin] " if role == "admin" else ""
                    # message for target user
                    active_users[target].send(encode_lantp({
                        "TYPE": "MSG",
                        "FROM": username,
                        "TO": target,
                        "CONTENT": f"[PM] {tag}{username}: {pm}"
                    }).encode("utf-8"))

                    # confirmation back to sender
                    conn.send(encode_lantp({
                        "TYPE": "CMD_RESP",
                        "FROM": "SERVER",
                        "CONTENT": f"[PM → {target}]: {pm}\n"
                    }).encode("utf-8"))
                    continue


                # --- Admin: Kick (adds temporary ban) ---
                elif text.startswith("/kick "):
                    if role != "admin":
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "🚫 Permission denied.\n"
                        }).encode("utf-8"))
                        continue

                    parts = text.split(" ", 2)
                    if len(parts) < 2:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "Usage: /kick <username> [reason]\n"
                        }).encode("utf-8"))
                        continue

                    target = parts[1]
                    reason = parts[2] if len(parts) > 2 else "No reason given"
                    if target not in active_users:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "User not found or offline.\n"
                        }).encode("utf-8"))
                        continue

                    try:
                        active_users[target].send(encode_lantp({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": f"⚠️ You have been kicked by an admin. Reason: {reason}"
                        }).encode("utf-8"))
                        active_users[target].close()
                    except:
                        pass

                    active_users.pop(target, None)
                    user_roles.pop(target, None)
                    banned_users[target] = time.time() + BAN_DURATION

                    broadcast({
                        "TYPE": "SYS", "FROM": "SERVER",
                        "CONTENT": f"🚨 {target} was kicked and temporarily banned (10 min) by an admin. (Reason: {reason})"
                    })
                    conn.send(encode_lantp({
                        "TYPE": "CMD_RESP", "FROM": "SERVER",
                        "CONTENT": f"✅ {target} has been kicked and banned for 10 minutes.\n"
                    }).encode("utf-8"))
                    print(f"[Admin Action] {username} kicked {target} (Reason: {reason})")
                    continue

                # --- Admin: Mute ---
                elif text.startswith("/mute "):
                    if role != "admin":
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "🚫 Permission denied.\n"
                        }).encode("utf-8"))
                        continue

                    parts = text.split()
                    if len(parts) < 2:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "Usage: /mute <user> <minutes>\n"
                        }).encode("utf-8"))
                        continue

                    target = parts[1]
                    duration = int(parts[2]) if len(parts) > 2 else 2
                    if target not in active_users:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "User not found or offline.\n"
                        }).encode("utf-8"))
                        continue

                    muted_users[target] = time.time() + (duration * 60)
                    active_users[target].send(encode_lantp({
                        "TYPE": "SYS", "FROM": "SERVER",
                        "CONTENT": f"🔇 You have been muted for {duration} minute(s)."
                    }).encode("utf-8"))
                    broadcast({
                        "TYPE": "SYS", "FROM": "SERVER",
                        "CONTENT": f"🔇 {target} was muted by an admin for {duration} minute(s)."
                    })
                    print(f"[Admin Action] {username} muted {target} for {duration}m")
                    continue


                # --- Admin: Unmute ---
                elif text.startswith("/unmute "):
                    if role != "admin":
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "🚫 Permission denied.\n"
                        }).encode("utf-8"))
                        continue

                    parts = text.split()
                    if len(parts) < 2:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "Usage: /unmute <user>\n"
                        }).encode("utf-8"))
                        continue

                    target = parts[1]
                    if target in muted_users:
                        muted_users.pop(target, None)
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": f"✅ {target} has been unmuted.\n"
                        }).encode("utf-8"))

                        if target in active_users:
                            active_users[target].send(encode_lantp({
                                "TYPE": "SYS", "FROM": "SERVER",
                                "CONTENT": "🔊 You have been unmuted by an admin."
                            }).encode("utf-8"))

                        broadcast({
                            "TYPE": "SYS", "FROM": "SERVER",
                            "CONTENT": f"🔊 {target} was unmuted by an admin."
                        })
                        print(f"[Admin Action] {username} unmuted {target}")
                    else:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "User is not muted.\n"
                        }).encode("utf-8"))
                    continue


                # --- Admin: Unban ---
                elif text.startswith("/unban "):
                    if role != "admin":
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "🚫 Permission denied.\n"
                        }).encode("utf-8"))
                        continue

                    parts = text.split()
                    if len(parts) < 2:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "Usage: /unban <user>\n"
                        }).encode("utf-8"))
                        continue

                    target = parts[1]
                    if target in banned_users:
                        banned_users.pop(target, None)
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": f"✅ {target} has been unbanned.\n"
                        }).encode("utf-8"))
                        print(f"[Admin Action] {username} unbanned {target}")
                    else:
                        conn.send(encode_lantp({
                            "TYPE": "CMD_RESP", "FROM": "SERVER",
                            "CONTENT": "User is not banned.\n"
                        }).encode("utf-8"))
                    continue

                # broadcast messages
                tag = "[Admin] " if role == "admin" else ""
                broadcast({
                    "TYPE": "MSG", "FROM": username,
                    "CONTENT": f"{tag}{username}: {text}"
                }, conn)
    except:
        pass
    finally:
        conn.close()
        if username:
            # Clean up user tracking
            active_users.pop(username, None)
            user_roles.pop(username, None)

            # Determine admin tag (for display)
            tag = "[Admin] " if role == "admin" else ""

            # Broadcast LANTP system message to others
            broadcast({
                "TYPE": "SYS",
                "FROM": "SERVER",
                "CONTENT": f"📤 {tag}{username} left the chat."
            })


# ---------- SERVER ----------
def run_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    server.settimeout(1.0)
    print(f"🚀 LANTP/1.0 Server running on port {port}. Ctrl+C to stop.")
    print("💻 Admin commands: list_pending | approve <u> | reject <u> | announce <msg> | exit\n")

        # --- Admin console thread ---
    def admin_console():
        while True:
            raw = input("admin> ").strip()
            if not raw:
                continue

            # Separate command from arguments
            parts = raw.split(" ", 1)
            cmd = parts[0].lower()          # command is case-insensitive
            args = parts[1] if len(parts) > 1 else ""

            # --- List pending signups ---
            if cmd == "list_pending":
                pending = load_json(PENDING_PATH, {})
                if not pending:
                    print("No pending signups.")
                else:
                    print("Pending signups:")
                    for u in pending:
                        print("  -", u)

            # --- Approve a pending user ---
            elif cmd == "approve":
                u = args.strip()
                users = load_json(USERS_PATH, {})
                pending = load_json(PENDING_PATH, {})
                if u in pending:
                    users[u] = {"password": pending[u]["password"], "role": "user"}
                    del pending[u]
                    save_json(USERS_PATH, users)
                    save_json(PENDING_PATH, pending)
                    print(f"✅ Approved {u}.")
                else:
                    print("No such pending user.")

            # --- Reject a pending user ---
            elif cmd == "reject":
                u = args.strip()
                pending = load_json(PENDING_PATH, {})
                if u in pending:
                    del pending[u]
                    save_json(PENDING_PATH, pending)
                    print(f"❌ Rejected {u}.")
                else:
                    print("No such pending user.")

            # --- Admin broadcast announcement ---
            elif cmd == "announce":
                msg = args.strip()
                if not msg:
                    print("Usage: announce <message>")
                    continue
                announcement = encode_lantp({
                    "TYPE": "SYS",
                    "FROM": "SERVER",
                    "CONTENT": f"[Server Announcement] {msg}"
                })
                print(f"📢 {msg}")
                broadcast(announcement)

            # --- Exit server ---
            elif cmd == "exit":
                print("🛑 Server shutting down...")
                os._exit(0)

            else:
                print("Unknown command.")

    threading.Thread(target=admin_console, daemon=True).start()

    # --- Main connection acceptor loop ---
    try:
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n🛑 Server shutting down...")
    finally:
        server.close()
        print("✅ Server closed cleanly.")


# ---------- MAIN ----------
if __name__ == "__main__":
    setup_server()
    cfg = json.load(open(CONFIG_PATH))
    admin_login()
    run_server(cfg["port"])
