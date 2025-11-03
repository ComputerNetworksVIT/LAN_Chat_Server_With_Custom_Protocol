import socket, threading, json, os, hashlib, time

DATA_DIR = "server_data"
CONFIG_PATH = os.path.join(DATA_DIR, "server_config.json")
USERS_PATH = os.path.join(DATA_DIR, "users.json")
PENDING_PATH = os.path.join(DATA_DIR, "pending.json")

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def load_json(path, default):
    if os.path.exists(path):
        return json.load(open(path))
    else:
        return default

def save_json(path, data):
    json.dump(data, open(path, "w"), indent=4)

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
        username = input("Admin username: ").strip()
        password = input("Password: ").strip()
        if username in users and users[username]["password"] == hash_pw(password) and users[username]["role"] == "admin":
            print(f"🔑 Logged in as admin '{username}'.")
            return username
        else:
            print("❌ Invalid credentials. Try again.\n")

# ---------- CLIENT HANDLER ----------
def handle_client(conn, addr):
    users = load_json(USERS_PATH, {})
    pending = load_json(PENDING_PATH, {})

    conn.send(b"Welcome to the LAN Chat Server.\nType: SIGNUP <user> <pass> to register.\n")
    try:
        data = conn.recv(1024).decode().strip()
        if data.startswith("SIGNUP "):
            _, user, pw = data.split(" ", 2)
            if user in users:
                conn.send(b"Username already exists.\n")
            elif user in pending:
                conn.send(b"Signup already pending approval.\n")
            else:
                pending[user] = {"password": hash_pw(pw)}
                save_json(PENDING_PATH, pending)
                conn.send(b"Signup request submitted. Wait for admin approval.\n")
        else:
            conn.send(b"Unknown command.\n")
    except Exception as e:
        conn.send(b"Error occurred.\n")
    conn.close()

# ---------- SERVER ----------
def run_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    server.settimeout(1.0)
    print(f"🚀 Server running on port {port}. Press Ctrl+C to stop.")
    print("💻 Admin commands: list_pending | approve <user> | reject <user> | exit\n")

    # admin command thread
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
                user = cmd.split(" ", 1)[1]
                users = load_json(USERS_PATH, {})
                pending = load_json(PENDING_PATH, {})
                if user in pending:
                    users[user] = {"password": pending[user]["password"], "role": "user"}
                    del pending[user]
                    save_json(USERS_PATH, users)
                    save_json(PENDING_PATH, pending)
                    print(f"✅ Approved {user}.")
                else:
                    print("No such pending user.")
            elif cmd.startswith("reject "):
                user = cmd.split(" ", 1)[1]
                pending = load_json(PENDING_PATH, {})
                if user in pending:
                    del pending[user]
                    save_json(PENDING_PATH, pending)
                    print(f"❌ Rejected {user}.")
                else:
                    print("No such pending user.")
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
        print("\n🛑 Shutting down server...")
    finally:
        server.close()
        print("✅ Server closed cleanly.")

if __name__ == "__main__":
    setup_server()
    config = json.load(open(CONFIG_PATH))
    admin_login()
    run_server(config["port"])
