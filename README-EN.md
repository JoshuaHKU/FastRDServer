[中文](README.md) | **English**

# FastRDServer

**Self-hosted ID / relay server**, an **unofficial fork** of
[rustdesk-server](https://github.com/rustdesk/rustdesk-server) open-source
edition 1.1.17.

Companion client: **FastRustDesk** (same author, separate repository).

---

> ### ⚠️ Unofficial fork
>
> This is an **unofficial personal fork** of rustdesk-server. It is **not
> affiliated with, endorsed by, or supported by** RustDesk or Purslane Ltd.
> "RustDesk" is a trademark of Purslane Ltd.
>
> A **personal build**: **no commercial support**, **no warranty**.
> Please do **not** report problems with this fork to RustDesk upstream.

---

## Three binaries

| Program | Role | Upstream name |
|---|---|---|
| **`FastRDServer`** | ID registration, hole-punch signalling, account API | `hbbs` |
| **`FastRDRelay`** | Relay when hole punching fails | `hbbr` |
| **`FastRDServer-utils`** | Admin CLI: accounts, passwords, device binding | `rustdesk-utils` |

## What this adds over the open-source edition

The open-source rustdesk-server does two things: register IDs and relay traffic.
**Accounts, groups and the address book are RustDesk Server Pro features** — the
open-source edition has none of them, which is why the client's "Address book"
and "Accessible devices" tabs are effectively dead on a self-hosted setup.

This fork fills that in, **without adding a single new crate** — everything is
built from dependencies the open-source edition already carries:

### 1. Accounts

Two tables, `user` and `user_token`, in the existing SQLite database. Passwords
are salted and hashed with **argon2id13** (sodiumoxide is already a dependency).

```bash
FastRDServer-utils user add <name> <password>
FastRDServer-utils user passwd <name> <new-password>   # also signs out that user everywhere
FastRDServer-utils user disable <name>
FastRDServer-utils user list
```

The server creates **admin/admin** on first start. Change it immediately.

The HTTP API listens on `<signalling port> - 2`:
`/api/login`, `/api/currentUser`, `/api/logout`, `/api/ab` (address book),
`/api/password` (self-service change while signed in).

> **Login payloads are sealed with a libsodium sealed box** — anonymous
> public-key encryption, no handshake and no certificates. The server's ed25519
> signing key is converted to a curve25519 public key that the client uses to
> seal the credentials, so **the password never crosses the wire in the clear**
> even though the port speaks plain HTTP.
>
> This is a deliberate compromise for deployments with no TLS available. It
> protects the credential; it does not protect metadata, and it is not a
> substitute for TLS. If you expose this port, put a TLS reverse proxy in front.

### 2. Devices grouped by account

After a client signs in, its token rides along on `RegisterPk` and the server
binds the device to the account (`peer.user`). The device roster is filtered by
group — **a signed-in user sees only their own devices**.

Devices can also be assigned from the server, so you need not sign in on every
machine:

```bash
FastRDServer-utils user bind <account> <device-id>
FastRDServer-utils user devices <account>
FastRDServer-utils user unbind <device-id>
```

> A registration **without** a token does **not** clear an assignment. A device
> that is merely signed out is not evidence that it does not belong to the
> account. Only an invalid token — a device claiming an identity it cannot prove
> — clears the binding.

### 3. Passwordless access within an account

The most useful thing about pairing this with FastRustDesk: **devices in the
same account connect to each other without a password**.

The decision is made entirely on the server:

```
client   PunchHoleRequest.account_token ──▶ server
                                            ├ token → user
                                            ├ target device's peer.user
                                            └ same?
server   PunchHole.same_account ──▶ controlled side ──▶ password check skipped
```

Three cases all answer "no": no token, an invalid or expired token, or a target
device not bound to any account.

> This exemption sits **after** the controlled side's "ask me first" gate — a
> machine configured to require manual approval still asks.
> **Grouping relaxes the password, not consent.**
>
> The cost: the account token is a **bearer credential**. Whoever holds it
> reaches every device in the group without a password. Acceptable for a private
> deployment; not for an exposed one.

### 4. Device enumeration

The client's "Accessible devices" tab needs the commercial API to have any data.
This fork adds `ListPeersRequest` / `ListPeersResponse` to the rendezvous
protocol so the client can ask this server directly for the roster (ID, online
state, hostname, platform, last registration).

> **The server key is mandatory on this request.** The adjacent online-state
> query upstream does not check it — fine, because it only confirms the state of
> an ID the caller already knows. Enumeration is different: without the check,
> anyone who can reach the signalling port could harvest every device ID and IP
> on the server.

### 5. `RegisterPk` carries hostname and platform

The server stored **only the IP**, so device lists were columns of nine-digit
numbers with nothing to recognise. Devices now report hostname and platform when
they register — on `RegisterPk` rather than in the heartbeat, because it is
static information and the heartbeat runs every few seconds.

## Ports: one is configurable, the rest are derived

Only `-p` can be set. Every other port is computed, by the same formula on both
the server and the client:

| Port (with `-p 21116`) | Protocol | Purpose | Derived as |
|---|---|---|---|
| 21114 | TCP | Account API (login / address book) | `port - 2` |
| 21115 | TCP | NAT type probe | `port - 1` |
| 21116 | **TCP + UDP** | ID registration, signalling (**do not omit UDP**) | `-p` |
| 21117 | TCP | Relay | relay `-p` |
| 21118 | TCP | WebSocket ID service | `port + 2` |
| 21119 | TCP | WebSocket relay | relay `port + 2` |

**All six need to be open, and the account API port is the one people forget** —
with misleading consequences: remote control works perfectly, only address-book
login times out.

The client only needs `<host>:<signalling port>`; the rest follow.

## Quick deployment

```bash
# Dependencies (the WebSocket ports pull in openssl; it is not optional)
sudo apt-get install -y libssl3 sqlite3

sudo useradd --system --no-create-home --shell /usr/sbin/nologin fastrd
sudo mkdir -p /home/FastRDSvr/{bin,data,logs}
sudo install -m 755 FastRDServer FastRDRelay FastRDServer-utils /home/FastRDSvr/bin/
sudo chown -R fastrd:fastrd /home/FastRDSvr/data /home/FastRDSvr/logs

sudo cp systemd/*.service /etc/systemd/system/    # edit the domain in them first
sudo systemctl daemon-reload
sudo systemctl enable --now FastRDServer FastRDRelay

# The public key clients need
sudo cat /home/FastRDSvr/data/id_ed25519.pub
```

`-k _` means "use the `id_ed25519` pair in the working directory, and **require
clients to hold the matching public key**" — knowing the domain alone is not
enough to use the server. The pair is generated on first start.

Full instructions — verification, migrating from upstream hbbs/hbbr, what to back
up — are in `INSTALL-FastRDServer-ubuntu.md` in the client repository (Chinese).

## Building from source

```bash
sudo apt-get install -y libssl-dev pkg-config build-essential sqlite3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
cargo build --release --all-features --locked
```

`build.rs` generates `db_v2.sqlite3` from the checked-in `schema.sql` before
compiling (schema only, zero rows), so a fresh clone builds as-is. **The
`sqlite3` command must be installed.** To rebuild it by hand:

```bash
rm -f db_v2.sqlite3 && sqlite3 db_v2.sqlite3 < schema.sql
```

> Why the file has to exist: sqlx validates SQL at **compile** time
> (`sqlx::query!`), by opening the database named in `.env`'s `DATABASE_URL` and
> reading its schema. Without it the build fails across `src/database.rs` with
> `unable to open database file` — which reads like a runtime problem and is not.
> This database is only for compile-time checking; the runtime one lives in the
> service's working directory and is unrelated.

## What to back up

**`<working dir>/id_ed25519` is the server's private key and its identity.**
Lose it and you have a different server: every client must change its key. Back
it up separately, and do not leak it. `db_v2.sqlite3` holds the device table,
the user table and the address book — back that up too.

## License

**AGPL-3.0**, unchanged from upstream — see [LICENSE](LICENSE).

As a derivative of an AGPL work, this project **must** be, and can only be,
released under AGPL-3.0. The statements above about personal use, no commercial
support and no warranty are the author's **statements**, **not** additional
licence terms — AGPL-3.0 does not permit imposing further restrictions.

⚠️ **The AGPL network clause matters especially for a server**: running it for
yourself carries no obligation; **the moment you offer it as a service to
others, you owe those users the corresponding source.**
