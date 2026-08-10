**中文** | [English](README-EN.md)

# FastRDServer

**自建 ID / 中继服务器**，基于 [rustdesk-server](https://github.com/rustdesk/rustdesk-server)
开源版 1.1.17 的**非官方分支**。

配套客户端：**FastRustDesk**（同一作者，另一个仓库）。

---

> ### ⚠️ 非官方分支声明
>
> 本项目是 rustdesk-server 的**非官方个人分支**，与 RustDesk 官方、
> Purslane Ltd **没有任何关联**，未获其认可或背书。
> `RustDesk` 是 Purslane Ltd 的商标。
>
> 这是**个人自用**的改造版：**不提供商业支持**，**不承担任何担保**。
> 遇到问题请**不要**向 RustDesk 官方反馈。

---

## 三个二进制

| 程序 | 作用 | 对应上游 |
|---|---|---|
| **`FastRDServer`** | ID 注册、打洞信令、账号 API | `hbbs` |
| **`FastRDRelay`** | 打洞失败时的中继转发 | `hbbr` |
| **`FastRDServer-utils`** | 管理命令行：建号、改密、设备绑定 | `rustdesk-utils` |

## 相比上游开源版，多了什么

开源版 rustdesk-server 只做两件事：ID 注册和中继转发。**账号、分组、地址簿这些
都是 RustDesk Server Pro（商业版）的功能**，开源版没有，所以自建环境下客户端的
「地址簿」「可访问的设备」两个页签基本是摆设。

本分支把这一块补上了 —— 用开源版已有的依赖，**没有引入任何新 crate**：

### 1. 账号体系

SQLite 里增加 `user` / `user_token` 两张表。密码用 **argon2id13** 加盐哈希存储
（sodiumoxide 本来就在依赖里）。

```bash
FastRDServer-utils user add <名字> <密码>
FastRDServer-utils user passwd <名字> <新密码>   # 会同时踢掉该用户所有登录态
FastRDServer-utils user disable <名字>
FastRDServer-utils user list
```

服务端首次启动会自动创建 **admin/admin**，请立刻改密。

HTTP 接口在 `<信令端口> - 2`（默认布局下是 41114）：
`/api/login`、`/api/currentUser`、`/api/logout`、`/api/ab`（地址簿读写）、
`/api/password`（登录状态下自助改密）。

> **登录载荷用 libsodium sealed box 加密**（匿名公钥加密，不需要握手和证书）。
> 服务器的 ed25519 签名密钥转成 curve25519 公钥后由客户端用来封装口令，所以
> 即使这个端口是明文 HTTP，**密码也不会明文过线**。这是在没有 TLS 条件时的
> 折中——它保护口令，不保护元数据，也不防重放之外的主动攻击。真要暴露到公网，
> 请自行在前面加 TLS 反向代理。

### 2. 设备按账号分组

客户端登录后，其令牌随 `RegisterPk` 上报，服务端据此把设备绑到账号
（`peer.user`）。「可访问的设备」列表按组过滤——**登录用户只看得到自己的设备**。

也可以在服务端直接指派，免得每台设备都手工登录一次：

```bash
FastRDServer-utils user bind <账号> <设备ID>
FastRDServer-utils user devices <账号>
FastRDServer-utils user unbind <设备ID>
```

> 未登录设备注册时**不会**清掉管理员指派的绑定——设备只是没登录，不构成
> 「它不属于那个账号」的证据。只有令牌无效（声称一个证明不了的身份）才清除。

### 3. 同一账号内的设备互连免密

这是搭配 FastRustDesk 后最实用的一项：**同组设备之间连接不需要输密码**。

判定全部在服务端完成：

```
客户端  PunchHoleRequest.account_token ──▶ 服务端
                                           ├ 令牌 → 用户
                                           ├ 目标设备的 peer.user
                                           └ 相同？
服务端  PunchHole.same_account ──▶ 被控端 ──▶ 跳过密码校验
```

三种情况一律判否：没带令牌、令牌无效或过期、目标设备未绑定账号。

> 这道放行**位于被控端「必须手动确认」那道闸之后**——设了要点同意的机器，
> 同组仍然要点。**分组放宽的是密码，不是同意权。**
>
> 代价：账号令牌是**持有即可用**的凭证，拿到它就能免密进入该组所有设备。
> 自建自用可以接受，公网暴露则不行。

### 4. 设备枚举接口

客户端的「可访问的设备」页原本要连商业版 API 才有数据。本分支在信令协议上加了
`ListPeersRequest` / `ListPeersResponse`，客户端直接向本服务器要设备清单
（ID、在线状态、主机名、平台、最后注册时间）。

> **强制校验服务器密钥**。相邻的在线状态查询上游不校验，那没问题——它只能确认
> 调用方**已知 ID** 的设备状态；枚举不同，不校验的话任何能连到信令端口的人都能
> 把服务器上全部设备的 ID 和 IP 扒下来。

### 5. `RegisterPk` 增加主机名与平台

服务器原本**只存 IP**，设备列表里全是九位数字，无法辨认。现在注册时一并上报
主机名和平台。放在 `RegisterPk` 而不是心跳里——它是静态信息，而心跳每几秒一次。

## 端口：只有一个能指定，其余是派生的

`-p` 之外的端口**不能分别指定**，服务端和客户端两侧按同一套公式算：

| 端口（`-p 21116` 时） | 协议 | 用途 | 来源 |
|---|---|---|---|
| 21114 | TCP | 账号 API（登录 / 地址簿） | `port - 2` |
| 21115 | TCP | NAT 类型探测 | `port - 1` |
| 21116 | **TCP + UDP** | ID 注册、打洞信令（**UDP 别漏**） | `-p` |
| 21117 | TCP | 中继 | relay `-p` |
| 21118 | TCP | WebSocket 版 ID 服务 | `port + 2` |
| 21119 | TCP | WebSocket 版中继 | relay `port + 2` |

**六个都要在防火墙/安全组放行，账号 API 那个最容易漏** —— 漏了的表现很有
迷惑性：远程控制完全正常，只有地址簿登录连不上。

客户端只需把 ID 服务器写成 `<主机>:<信令端口>`，其余自动跟着走。

## 快速部署

```bash
# 依赖（WebSocket 端口用到 openssl，不是可选的）
sudo apt-get install -y libssl3 sqlite3

sudo useradd --system --no-create-home --shell /usr/sbin/nologin fastrd
sudo mkdir -p /home/FastRDSvr/{bin,data,logs}
sudo install -m 755 FastRDServer FastRDRelay FastRDServer-utils /home/FastRDSvr/bin/
sudo chown -R fastrd:fastrd /home/FastRDSvr/data /home/FastRDSvr/logs

sudo cp systemd/*.service /etc/systemd/system/    # 先改里面的域名
sudo systemctl daemon-reload
sudo systemctl enable --now FastRDServer FastRDRelay

# 取公钥，客户端要用
sudo cat /home/FastRDSvr/data/id_ed25519.pub
```

`-k _` 表示使用工作目录下的 `id_ed25519`，并**强制客户端持有匹配公钥** ——
没有公钥的人即使知道域名也用不了这台服务器。首次启动会自动生成密钥对。

完整说明（含验证方法、从上游 hbbs/hbbr 迁移、备份要点）见客户端仓库的
`INSTALL-FastRDServer-ubuntu.md`。

## 从源码编译

```bash
sudo apt-get install -y libssl-dev pkg-config build-essential sqlite3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
cargo build --release --all-features --locked
```

`build.rs` 会在编译前**自动**从仓库里的 `schema.sql` 生成 `db_v2.sqlite3`
（只有表结构、零数据），所以 clone 下来直接 `cargo build` 就行。
**需要系统装有 `sqlite3` 命令**。手工重建：

```bash
rm -f db_v2.sqlite3 && sqlite3 db_v2.sqlite3 < schema.sql
```

> 为什么要有这个文件：sqlx 是**编译期**校验 SQL 的
> （`sqlx::query!` 宏），编译时会按 `.env` 里的 `DATABASE_URL` 打开它读表结构。
> 少了它，编译会在 `src/database.rs` 上报一片 `unable to open database file` ——
> 看着像运行时问题，其实发生在编译期。这个库只用于编译校验，运行时用的是工作
> 目录下那个，两者互不相干。

## 备份要点

**`<工作目录>/id_ed25519` 是服务器私钥，也是它的身份。** 丢了等于换服务器，
所有客户端都要改 Key。单独备份，且不要外泄。
`db_v2.sqlite3` 存设备表、用户表和地址簿，一并备份。

## 许可

**AGPL-3.0**，与上游一致 —— 见 [LICENSE](LICENSE)。

作为 AGPL 派生作品，本项目**必须**且**只能**以 AGPL-3.0 发布。
上文「个人自用、不提供商业支持、不承担担保」是作者的**声明**，
**不是**附加的许可条款——AGPL-3.0 不允许附加任何额外限制。

⚠️ **AGPL 的网络条款对服务端尤其要紧**：自建自用没有义务；
**一旦对外提供服务，就有向使用者提供对应源码的义务**。
