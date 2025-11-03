import socket, threading, json, os, hashlib, time

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
def broadcast(msg, sender_conn=None):
    for user, conn in list(active_users.items()):
        if conn != sender_conn:
            try:
                conn.send(msg.encode())
            except:
                active_users.pop(user, None)

# ---------- CLIENT HANDLER ----------
def handle_client(conn, addr):
    users = load_json(USERS_PATH, {})
    pending = load_json(PENDING_PATH, {})
    conn.send(b"Welcome to the LAN Chat Server.\nType SIGNUP or LOGIN\n")

    username = None
    role = "user"

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            msg = data.decode().strip()

            if msg.upper().startswith("SIGNUP "):
                _, user, pw = msg.split(" ", 2)
                if user in users:
                    conn.send(b"Username already exists.\n")
                elif user in pending:
                    conn.send(b"Signup already pending.\n")
                else:
                    pending[user] = {"password": hash_pw(pw)}
                    save_json(PENDING_PATH, pending)
                    conn.send(b"Signup submitted. Wait for admin approval, then try LOGIN.\n")
                continue

            elif msg.upper().startswith("LOGIN "):
                _, user, pw = msg.split(" ", 2)

                # --- 🔒 Temporary ban check ---
                if user in banned_users:
                    if time.time() < banned_users[user]:
                        remaining = int((banned_users[user] - time.time()) // 60) + 1
                        conn.send(f"🚫 You are temporarily banned. Try again in {remaining} minute(s).\n".encode("utf-8"))
                        conn.close()
                        return
                    else:
                        banned_users.pop(user, None)  # ban expired, allow login

                users = load_json(USERS_PATH, {})
                if user not in users or users[user]["password"] != hash_pw(pw):
                    conn.send(b"Invalid credentials or user not approved.\n")
                elif user in active_users:
                    conn.send(b"User already logged in elsewhere.\n")
                else:
                    username = user
                    role = users[user]["role"]
                    active_users[user] = conn
                    user_roles[user] = role
                    tag = "[Admin] " if role == "admin" else ""
                    conn.send(f"✅ Logged in as {tag}{user}. You can now chat.\n".encode())
                    broadcast(f"📢 {tag}{user} joined the chat.\n", conn)
                    break
            else:
                conn.send(b"Unknown command. Use SIGNUP or LOGIN.\n")

    except:
        pass

    if not username:
        conn.close()
        return

    # chat loop
    try:
        while True:
            msg = conn.recv(1024)
            if not msg:
                break
            text = msg.decode().strip()

            # check mute expiration
            if username in muted_users and time.time() < muted_users[username]:
                conn.send("🚫 You are muted.\n".encode("utf-8"))
                continue
            elif username in muted_users and time.time() >= muted_users[username]:
                del muted_users[username]
                conn.send("✅ You have been unmuted.\n".encode("utf-8"))

            # --- Command handling ---
            if text == "/help":
                help_text = (
                    "\nAvailable commands:\n"
                    "  /help - show this message\n"
                    "  /users - list online users\n"
                    "  @username <msg> - private message\n"
                    "  exit - disconnect\n"
                )
                if role == "admin":
                    help_text += (
                        "  /kick <user> - disconnect user\n"
                        "  /mute <user> <minutes> - mute user (default 5m)\n"
                    )
                help_text += "\n"
                conn.send(help_text.encode())
                continue

            elif text == "/users":
                users_list = ", ".join(active_users.keys()) or "(none)"
                conn.send(f"Online users: {users_list}\n".encode())
                continue

            elif text.startswith("@"):
                parts = text.split(" ", 1)
                if len(parts) < 2:
                    conn.send(b"Usage: @username <message>\n")
                    continue
                target, pm = parts
                target = target[1:]
                if target not in active_users:
                    conn.send(b"User not found.\n")
                else:
                    prefix = "[PM] "
                    tag = "[Admin] " if role == "admin" else ""
                    active_users[target].send(f"{prefix}{tag}{username}: {pm}\n".encode())
                    conn.send(f"{prefix}to {target}: {pm}\n".encode())
                continue

            # --- Admin: Kick (adds temporary ban) ---
            elif text.startswith("/kick "):
                if role != "admin":
                    conn.send("🚫 Permission denied.\n".encode("utf-8"))
                    continue
                parts = text.split(" ", 2)
                if len(parts) < 2:
                    conn.send(b"Usage: /kick <username> [reason]\n")
                    continue
                target = parts[1]
                reason = parts[2] if len(parts) > 2 else "No reason given"
                if target not in active_users:
                    conn.send(b"User not found or offline.\n")
                    continue
                try:
                    active_users[target].send(f"⚠️ You have been kicked by an admin. Reason: {reason}\n".encode("utf-8"))
                    active_users[target].close()
                except:
                    pass
                active_users.pop(target, None)
                user_roles.pop(target, None)
                banned_users[target] = time.time() + BAN_DURATION
                broadcast(f"🚨 {target} was kicked and temporarily banned (10 min) by an admin. (Reason: {reason})\n")
                conn.send(f"✅ {target} has been kicked and banned for 10 minutes.\n".encode("utf-8"))
                print(f"[Admin Action] {username} kicked {target} (Reason: {reason})")
                continue

             # --- Admin: Mute ---
            elif text.startswith("/mute "):
                if role != "admin":
                    conn.send("🚫 Permission denied.\n".encode("utf-8"))
                    continue
                parts = text.split()
                if len(parts) < 2:
                    conn.send(b"Usage: /mute <user> <minutes>\n")
                    continue
                target = parts[1]
                duration = int(parts[2]) if len(parts) > 2 else 2
                if target not in active_users:
                    conn.send(b"User not found or offline.\n")
                else:
                    muted_users[target] = time.time() + (duration * 60)
                    active_users[target].send(f"🔇 You have been muted for {duration} minute(s).\n".encode())
                    broadcast(f"🔇 {target} was muted by an admin for {duration} minute(s).\n")
                    print(f"[Admin Action] {username} muted {target} for {duration}m")
                continue

            # --- Admin: Unmute ---
            elif text.startswith("/unmute "):
                if role != "admin":
                    conn.send("🚫 Permission denied.\n".encode("utf-8"))
                    continue
                parts = text.split()
                if len(parts) < 2:
                    conn.send(b"Usage: /unmute <user>\n".encode())
                    continue
                target = parts[1]
                if target in muted_users:
                    muted_users.pop(target, None)
                    conn.send(f"✅ {target} has been unmuted.\n".encode())
                    if target in active_users:
                        active_users[target].send("🔊 You have been unmuted by an admin.\n".encode("utf-8"))
                    broadcast(f"🔊 {target} was unmuted by an admin.\n")
                    print(f"[Admin Action] {username} unmuted {target}")
                else:
                    conn.send("User is not muted.\n".encode())
                continue

             # --- Admin: Unban ---
            elif text.startswith("/unban "):
                if role != "admin":
                    conn.send("🚫 Permission denied.\n".encode("utf-8"))
                    continue
                parts = text.split()
                if len(parts) < 2:
                    conn.send("Usage: /unban <user>\n".encode())
                    continue
                target = parts[1]
                if target in banned_users:
                    banned_users.pop(target, None)
                    conn.send(f"✅ {target} has been unbanned.\n".encode())
                    print(f"[Admin Action] {username} unbanned {target}")
                else:
                    conn.send("User is not banned.\n".encode())
                continue

            else:
                tag = "[Admin] " if role == "admin" else ""
                broadcast(f"{tag}{username}: {text}\n", conn)

    except:
        pass
    finally:
        conn.close()
        if username:
            active_users.pop(username, None)
            user_roles.pop(username, None)
            tag = "[Admin] " if role == "admin" else ""
            broadcast(f"📤 {tag}{username} left the chat.\n", conn)

# ---------- SERVER ----------
def run_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    server.settimeout(1.0)
    print(f"🚀 Server running on port {port}. Ctrl+C to stop.")
    print("💻 Admin commands: list_pending | approve <u> | reject <u> | announce <msg> | exit\n")

    def admin_console():
        while True:
            cmd = input("admin> ").strip()
            if cmd == "list_pending":
                pending = load_json(PENDING_PATH, {})
                if not pending:
                    print("No pending signups.")
                else:
                    print("Pending signups:")
                    for u in pending:
                        print("  -", u)
            elif cmd.startswith("approve "):
                u = cmd.split(" ", 1)[1]
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
            elif cmd.startswith("reject "):
                u = cmd.split(" ", 1)[1]
                pending = load_json(PENDING_PATH, {})
                if u in pending:
                    del pending[u]
                    save_json(PENDING_PATH, pending)
                    print(f"❌ Rejected {u}.")
                else:
                    print("No such pending user.")
            elif cmd.startswith("announce "):
                msg = cmd.split(" ", 1)[1]
                announcement = f"[Server Announcement] {msg}\n"
                print(announcement.strip())
                broadcast(announcement)
            elif cmd == "exit":
                os._exit(0)
            else:
                print("Unknown command.")

    threading.Thread(target=admin_console, daemon=True).start()

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
