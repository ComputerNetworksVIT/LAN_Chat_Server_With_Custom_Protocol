Perfect 😎
Here’s your **`LANTP_SPEC.md`** — a clean, standalone document describing your protocol in detail.
You can put it in the project root (same level as `README.md`), and optionally link to it in the README with:

> 🔗 See [`LANTP_SPEC.md`](./LANTP_SPEC.md) for full protocol documentation.

---

# 📜 LANTP/1.0 Specification

**LAN Transmission Protocol**
Version 1.0 — November 2025
Author: *Bashar Mohammad Wakil (24BCE1964)*

---

## 1. Introduction

**LANTP (LAN Transmission Protocol)** is a simple, text-based application-layer protocol designed for LAN-based chat and command transmission over TCP sockets.
It defines a **human-readable packet structure** to standardize how clients and servers exchange messages, commands, and control information.

This protocol powers the *LANTP Chat Server* system — enabling secure authentication, structured commands, and reliable communication between multiple users.

---

## 2. Design Goals

* 💬 **Readable** — easily debuggable in plaintext form
* ⚙️ **Structured** — consistent message format across systems
* 🔄 **Synchronous** — works over persistent TCP connections
* 🧩 **Extensible** — new `TYPE`s can be added in future versions

---

## 3. Protocol Format

Every message (client or server) follows this format:

```
LANTP/1.0
TYPE: <MessageType>
FROM: <Sender>
[TO: <Receiver>]
CONTENT: <Payload>
<END>
```

Each field is separated by a newline (`\n`), and the literal `<END>` line marks the end of the packet.

---

## 4. Core Fields

| Field       | Required | Description                                                       |
| ----------- | -------- | ----------------------------------------------------------------- |
| **TYPE**    | ✅        | Defines the purpose of the packet (e.g., `MSG`, `SYS`, `AUTH_OK`) |
| **FROM**    | ✅        | Sender identifier (`SERVER`, `CLIENT`, or username)               |
| **TO**      | ❌        | Optional recipient (for private messages)                         |
| **CONTENT** | ✅        | Main message body (text content or command)                       |

All packets must begin with `LANTP/1.0` and end with `<END>`.

---

## 5. Example Packets

### 5.1 Authentication

**Client → Server**

```
LANTP/1.0
TYPE: SYS
FROM: CLIENT
CONTENT: LOGIN test1 password
<END>
```

**Server → Client**

```
LANTP/1.0
TYPE: AUTH_OK
FROM: SERVER
CONTENT: ✅ Logged in as test1. You can now chat.
<END>
```

---

### 5.2 Chat Message

**Client → Server**

```
LANTP/1.0
TYPE: MSG
FROM: test1
CONTENT: Hello everyone!
<END>
```

**Server → All Clients**

```
LANTP/1.0
TYPE: MSG
FROM: test1
CONTENT: test1: Hello everyone!
<END>
```

---

### 5.3 Private Message

```
LANTP/1.0
TYPE: MSG
FROM: test1
TO: user2
CONTENT: [PM] test1: Hey, you there?
<END>
```

---

### 5.4 Heartbeat

**Server → Client**

```
LANTP/1.0
TYPE: PING
FROM: SERVER
CONTENT:
<END>
```

**Client → Server**

```
LANTP/1.0
TYPE: PONG
FROM: CLIENT
CONTENT:
<END>
```

---

### 5.5 System Message

```
LANTP/1.0
TYPE: SYS
FROM: SERVER
CONTENT: 📢 test1 joined the chat.
<END>
```

---

### 5.6 Admin Announcement

```
LANTP/1.0
TYPE: SYS
FROM: SERVER
CONTENT: [Server Announcement] Maintenance at 6 PM.
<END>
```

---

## 6. Message Types

| TYPE        | Direction       | Description                                    |
| ----------- | --------------- | ---------------------------------------------- |
| `SYS`       | Server → Client | System messages, announcements, status updates |
| `MSG`       | Both            | Chat messages (global or private)              |
| `AUTH_OK`   | Server → Client | Successful authentication                      |
| `AUTH_FAIL` | Server → Client | Failed authentication                          |
| `CMD_RESP`  | Server → Client | Response to a command (/help, /users, etc.)    |
| `PING`      | Server → Client | Heartbeat check                                |
| `PONG`      | Client → Server | Heartbeat reply                                |
| `ERR`       | Server → Client | Malformed or unauthorized packet               |

---

## 7. Command Semantics (Server-Side)

### 7.1 Global Commands (All Users)

| Command           | Description                |
| ----------------- | -------------------------- |
| `/help`           | Display available commands |
| `/users`          | List online users          |
| `@username <msg>` | Send private message       |
| `exit`            | Disconnect gracefully      |

### 7.2 Admin Commands

| Command                  | Description                     |
| ------------------------ | ------------------------------- |
| `/kick <user> [reason]`  | Kick and temporarily ban a user |
| `/mute <user> [minutes]` | Mute user temporarily           |
| `/unmute <user>`         | Unmute a muted user             |
| `/unban <user>`          | Remove a ban                    |
| `/whois <user>`          | Show IP, role, connection time  |
| `/announce <msg>`        | Send broadcast announcement     |

---

## 8. Connection Lifecycle

### 8.1 Establishment

1. Client connects to server via TCP socket.
2. Server greets client with a `SYS` message.
3. Client sends `SIGNUP` or `LOGIN` command.

### 8.2 Authentication

* If successful → `AUTH_OK` sent.
* If failed → `AUTH_FAIL` sent.

### 8.3 Message Exchange

* Authenticated clients may send `/commands`, `MSG`, or `@username`.
* Server relays or responds with appropriate `TYPE`.

### 8.4 Heartbeat

* Server sends `PING` every 30 seconds.
* Client must reply `PONG`.
* No `PONG` within 180 seconds ⇒ disconnection and log entry.

### 8.5 Termination

* Client sends `exit` or disconnects manually.
* Server logs disconnect, removes from active list.

---

## 9. Error Handling

Malformed or incomplete packets are ignored or responded to with:

```
LANTP/1.0
TYPE: ERR
FROM: SERVER
CONTENT: Malformed or incomplete packet.
<END>
```

Servers **should not** crash or hang on bad packets.

---

## 10. Logging and Audit Trail

The server logs:

* User logins/logouts
* Admin actions (kick/mute/unmute/unban)
* Timeouts and errors
* Private message traces (sender/receiver only)

Logs are stored in:

```
server/logs/YYYY-MM-DD.log
```

---

## 11. Implementation Guidelines

### Server

* Use per-client threads for simultaneous connections.
* Wrap file writes in a global lock for thread safety.
* Track:

  * `active_users`
  * `muted_users`
  * `banned_users`
  * `connected_since`
  * `last_pong`

### Client

* Maintain a receive thread to parse `<END>` delimited messages.
* Always respond to `PING` with `PONG`.
* Respect `/exit` and socket closures gracefully.

---

## 12. Versioning

| Version           | Date     | Summary                                                |
| ----------------- | -------- | ------------------------------------------------------ |
| **1.0**           | Nov 2025 | Initial release — stable LAN chat protocol             |
| **1.1 (planned)** | 2026     | Add binary framing, optional checksums, session resume |

---

## 13. Example Timeline

```
Client                      Server
 |                             |
 | ------ CONNECT ------------>|
 |                             |
 | LOGIN alex pass ----------->|
 |                             |
 | <--- AUTH_OK ---------------|
 |                             |
 | MSG "hello" --------------->|
 | <--- MSG "hi" --------------|
 |                             |
 | <--- PING ------------------|
 | PONG ---------------------->|
 |                             |
 | exit ---------------------->|
 | <--- SYS "bye" -------------|
```

---

## 14. Licensing and Attribution

This protocol was developed by **Bashar Mohammad Wakil (24BCE1964)**
as part of a **Computer Networks (CN)** project at VIT.

Use, modification, and redistribution are permitted with attribution.

---

## 15. Notes

* LANTP is intentionally simple and easy to implement in any language (Python, C, Java, etc.).
* The design borrows from early text-based protocols like **SMTP**, **POP3**, and **IRC**.
* It serves both as an educational tool and a functional chat system foundation.

---

✅ **End of LANTP/1.0 Specification**

---