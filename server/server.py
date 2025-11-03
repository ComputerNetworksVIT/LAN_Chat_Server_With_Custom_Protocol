import socket, threading, json, os, hashlib

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
active_users = {}   # {username: conn}
user_roles = {}     # {username: role}

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

            # --- Command handling ---
            if text == "/help":
                help_text = (
                    "\nAvailable commands:\n"
                    "  /help - show this message\n"
                    "  /users - list online users\n"
                    "  @username <msg> - private message\n"
                    "  exit - disconnect\n\n"
                )
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
