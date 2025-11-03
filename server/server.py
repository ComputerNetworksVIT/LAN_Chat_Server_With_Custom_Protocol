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

# store all active clients {username: conn}
clients = {}

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

# ---------- LOGIN ----------
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
def broadcast(msg, sender=None):
    for user, conn in list(clients.items()):
        if user != sender:
            try: conn.send(msg.encode())
            except: clients.pop(user, None)

# ---------- CLIENT HANDLER ----------
def handle_client(conn, addr):
    users = load_json(USERS_PATH, {})
    pending = load_json(PENDING_PATH, {})

    conn.send(b"Welcome to the LAN Chat Server.\nType SIGNUP or LOGIN\n")
    username = None

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            msg = data.decode().strip()
            if msg.startswith("SIGNUP "):
                _, user, pw = msg.split(" ", 2)
                if user in users:
                    conn.send(b"Username already exists.\n")
                elif user in pending:
                    conn.send(b"Signup already pending.\n")
                else:
                    pending[user] = {"password": hash_pw(pw)}
                    save_json(PENDING_PATH, pending)
                    conn.send(b"Signup submitted. Wait for admin approval, then try LOGIN.\n")
                continue  # keep connection open for later login

            elif msg.startswith("LOGIN "):
                _, user, pw = msg.split(" ", 2)
                if user not in users or users[user]["password"] != hash_pw(pw):
                    conn.send(b"Invalid credentials.\n")
                elif user in active_users:
                    conn.send(b"User already logged in elsewhere.\n")
                else:
                    username = user
                    active_users[user] = conn
                    conn.send(f"✅ Logged in as {user}. You can now chat.\n".encode())
                    broadcast(f"📢 {user} joined the chat.\n", conn)
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
            broadcast(f"{username}: {text}\n", conn)
    except:
        pass
    finally:
        conn.close()
        if username:
            active_users.pop(username, None)
            broadcast(f"📤 {username} left the chat.\n", conn)

clients = []

def broadcast(message, sender=None):
    for c in clients[:]:
        try:
            if c != sender:
                c.send(message.encode())
        except:
            clients.remove(c)

# ---------- SERVER ----------
def run_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    server.settimeout(1.0)
    print(f"🚀 Server running on port {port}. Ctrl+C to stop.")
    print("💻 Admin commands: list_pending | approve <u> | reject <u> | exit\n")

    # --- admin console thread ---
    def admin_console():
        while True:
            cmd = input("admin> ").strip()
            if cmd == "list_pending":
                pending = load_json(PENDING_PATH, {})
                if not pending: print("No pending signups.")
                else:
                    print("Pending signups:")
                    for u in pending: print("  -", u)
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
                else: print("No such pending user.")
            elif cmd.startswith("reject "):
                u = cmd.split(" ", 1)[1]
                pending = load_json(PENDING_PATH, {})
                if u in pending:
                    del pending[u]; save_json(PENDING_PATH, pending)
                    print(f"❌ Rejected {u}.")
                else: print("No such pending user.")
            elif cmd == "exit": os._exit(0)
            else: print("Unknown command.")

    threading.Thread(target=admin_console, daemon=True).start()

    try:
        while True:
            try:
                conn, addr = server.accept()
                clients.append(conn)
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout: continue
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
