
# 🌐 **“LANComms-LANTP”**

*A LAN-based chat system with authentication, admin moderation, and a custom transport protocol.*

---

## 📖 Overview

**LANTP Chat Server** is a multi-user chat system built over a **custom application protocol (LANTP/1.0)** using raw **TCP sockets in Python**.
It supports **authenticated logins, real-time messaging, and admin moderation tools**, all running on a local network — no external dependencies.

This project was developed as part of a **Computer Networks (CN)** course to demonstrate low-level socket programming, protocol design, and session management.

---

## 🚀 Key Features

* 🔐 **User Authentication**

  * Signup and admin approval flow
  * Passwords hashed with SHA-256
* 🧩 **Custom Protocol – LANTP/1.0**

  * Structured text-based packets
  * Types: `SYS`, `MSG`, `AUTH_OK`, `AUTH_FAIL`, `CMD_RESP`, `PING`, `PONG`
* 💬 **Global & Private Messaging**

  * Global chat visible to all users
  * Private DMs via `@username`
* ⚙️ **Admin Controls**

  * `/kick`, `/mute`, `/unmute`, `/unban`, `/whois`, `/announce`
* 🧱 **Threaded Server Architecture**

  * Concurrent client handling
  * Real-time broadcast updates
* 📡 **Heartbeat (PING/PONG)**

  * Detects disconnected or frozen clients
* 🗃️ **Persistent Storage**

  * JSON-based user database, pending signups, and chat logs
* 🪶 **Lightweight & Pure Python**

  * No frameworks, no dependencies

---

## ⚙️ Folder Structure

```
LANTP_Chat_Server/
│
├── server/
│   ├── server.py         # main server logic (LANTP + commands)
│   ├── server_data/      # config, user data, pending signups
│   └── logs/             # daily log files
│
├── client/
│   └── client.py         # terminal-based LANTP client
│
└── README.md
```

---

## 🧩 LANTP/1.0 – LAN Transmission Protocol

A minimal, human-readable text protocol that structures all communication between the client and server.

### 📦 Packet Format

```
LANTP/1.0
TYPE: MSG
FROM: test_user
TO: (optional)
CONTENT: Hello, this is a test message!
<END>
```
🔗 See [`LANTP_SPEC.md`](LANTP_SPEC.md) for full protocol documentation.

### 🔍 Supported Message Types

| Type        | Direction       | Description                                |
| ----------- | --------------- | ------------------------------------------ |
| `SYS`       | Server → Client | System messages, joins, leaves, or notices |
| `MSG`       | Both            | Normal chat messages                       |
| `AUTH_OK`   | Server → Client | Login success confirmation                 |
| `AUTH_FAIL` | Server → Client | Authentication failure                     |
| `CMD_RESP`  | Server → Client | Response to a user command (/help, /users) |
| `PING/PONG` | Both            | Heartbeat keepalive messages               |
| `ERR`       | Server → Client | Protocol or logic errors                   |

---

## 💻 Command Reference

| Command                  | Description                             | Role  |
| ------------------------ | --------------------------------------- | ----- |
| `/help`                  | Show list of available commands         | All   |
| `/users`                 | List all currently online users         | All   |
| `@username <msg>`        | Send a private message                  | All   |
| `/kick <user> [reason]`  | Disconnect user and apply temporary ban | Admin |
| `/mute <user> [minutes]` | Mute user temporarily                   | Admin |
| `/unmute <user>`         | Unmute user                             | Admin |
| `/unban <user>`          | Remove ban early                        | Admin |
| `/whois <user>`          | Get info: IP, role, uptime              | Admin |
| `/announce <msg>`        | Broadcast a server-wide announcement    | Admin |
| `exit`                   | Disconnect from the chat                | All   |

---

## 🧠 Example Interaction

### Client

```
> LOGIN alex password123
✅ Authenticated. You can now chat! Type /help for commands.

> /users
👥 Online users:
  - alex
  - root [Admin]

> @root Hello admin!
[PM → root]: Hello admin!
```

### Server

```
🚀 LANTP/1.0 Server running on port 5555
[Admin Action] root muted alex for 5m
[Admin Action] root kicked user1 (Reason: spam)
[TIMEOUT] user2 disconnected (no PONG in 90s)
```

---

## 🧰 Setup Instructions

### Requirements

* Python 3.10 or later
* Local network or localhost setup

### Server Setup

```bash
cd server
python server.py
```

* On first launch, you’ll be asked to create an **admin account** and set a **port**.
* All data will be stored inside `server_data/`.

### Client Setup

```bash
cd client
python client.py
```

* Enter the server’s IP and port.
* Use `SIGNUP <user> <pass>` to request registration.
* The admin must approve your signup before `LOGIN` works.

---

## 🧾 Logging

* All system events (logins, commands, disconnects, timeouts) are saved in:

  ```
  server/logs/YYYY-MM-DD.log
  ```
* Example entry:

  ```
  [12:45:22] root (admin) logged in from 127.0.0.1:52341
  [12:47:10] [ADMIN] root muted alex for 2m
  [12:48:33] alex: test message
  [12:52:14] alex (user) disconnected
  ```

---

## 🧱 Technical Summary

| Layer        | Technology                     |
| ------------ | ------------------------------ |
| Language     | Python 3                       |
| Transport    | TCP (socket module)            |
| Architecture | Multi-threaded server / client |
| Protocol     | LANTP/1.0 (custom text-based)  |
| Data Storage | JSON                           |
| Logs         | Per-day text logs              |

---

## 🧩 Future Work

* 🔄 Persistent session recovery after disconnect
* 🔒 TLS or local encryption for passwords
* 💾 Optional SQLite backend for user data
* 🪟 GUI client (Tkinter/PyQt)
* 📡 LANTP/2.0 draft — structured key–value framing with checksums

---

## 👥 Author

Developed independantly by **Bashar Mohammad Wakil (24BCE1964)**
as part of a **Computer Networks B.Tech project (VIT)**

