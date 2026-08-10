use dns_lookup::{lookup_addr, lookup_host};
// The tokio::main macro expands to `tokio::...` paths, so the name has to be in
// scope here even though hbb_common owns the dependency.
use hbb_common::tokio;
use hbb_common::{bail, ResultType};
use sodiumoxide::crypto::sign;
use std::{
    env,
    net::{IpAddr, TcpStream},
    process, str,
};

fn print_help() {
    println!(
        "Usage:
    FastRDServer-utils [command]\n
Available Commands:
    genkeypair                                   Generate a new keypair
    validatekeypair [public key] [secret key]    Validate an existing keypair
    doctor [rustdesk-server]                     Check for server connection problems

  Accounts (LOCAL FORK):
    user list                                    List accounts
    user add [name] [password]                   Create an account
    user passwd [name] [password]                Reset an account's password
    user disable [name]                          Disable an account
    user enable [name]                           Enable an account
    user devices [name]                          List the devices bound to an account
    user bind [name] [device-id]                 Bind a device to an account
    user unbind [device-id]                      Remove a device's account binding

  Devices in the same account reach each other without a password.
  A device normally binds itself after signing in from the client; `user bind`
  lets you do it here instead of signing in on every machine.

  The database is db_v2.sqlite3 in the working directory, or $DB_URL.
  Run these from the server's working directory (/home/FastRDSvr/data)."
    );
    process::exit(0x0001);
}

fn error_then_help(msg: &str) {
    println!("ERROR: {msg}\n");
    print_help();
}

fn gen_keypair() {
    let (pk, sk) = sign::gen_keypair();
    let public_key = base64::encode(pk);
    let secret_key = base64::encode(sk);
    println!("Public Key:  {public_key}");
    println!("Secret Key:  {secret_key}");
}

fn validate_keypair(pk: &str, sk: &str) -> ResultType<()> {
    let sk1 = base64::decode(sk);
    if sk1.is_err() {
        bail!("Invalid secret key");
    }
    let sk1 = sk1.unwrap();

    let secret_key = sign::SecretKey::from_slice(sk1.as_slice());
    if secret_key.is_none() {
        bail!("Invalid Secret key");
    }
    let secret_key = secret_key.unwrap();

    let pk1 = base64::decode(pk);
    if pk1.is_err() {
        bail!("Invalid public key");
    }
    let pk1 = pk1.unwrap();

    let public_key = sign::PublicKey::from_slice(pk1.as_slice());
    if public_key.is_none() {
        bail!("Invalid Public key");
    }
    let public_key = public_key.unwrap();

    let random_data_to_test = b"This is meh.";
    let signed_data = sign::sign(random_data_to_test, &secret_key);
    let verified_data = sign::verify(&signed_data, &public_key);
    if verified_data.is_err() {
        bail!("Key pair is INVALID");
    }
    let verified_data = verified_data.unwrap();

    if random_data_to_test != &verified_data[..] {
        bail!("Key pair is INVALID");
    }

    Ok(())
}

fn doctor_tcp(address: std::net::IpAddr, port: &str, desc: &str) {
    let start = std::time::Instant::now();
    let conn = format!("{address}:{port}");
    if let Ok(_stream) = TcpStream::connect(conn.as_str()) {
        let elapsed = std::time::Instant::now().duration_since(start);
        println!(
            "TCP Port {} ({}): OK in {} ms",
            port,
            desc,
            elapsed.as_millis()
        );
    } else {
        println!("TCP Port {port} ({desc}): ERROR");
    }
}

fn doctor_ip(server_ip_address: std::net::IpAddr, server_address: Option<&str>) {
    println!("\nChecking IP address: {server_ip_address}");
    println!("Is IPV4: {}", server_ip_address.is_ipv4());
    println!("Is IPV6: {}", server_ip_address.is_ipv6());

    // reverse dns lookup
    // TODO: (check) doesn't seem to do reverse lookup on OSX...
    let reverse = lookup_addr(&server_ip_address).unwrap();
    if let Some(server_address) = server_address {
        if reverse == server_address {
            println!("Reverse DNS lookup: '{reverse}' MATCHES server address");
        } else {
            println!(
                "Reverse DNS lookup: '{reverse}' DOESN'T MATCH server address '{server_address}'"
            );
        }
    }

    // TODO: ICMP ping?

    // port check TCP (UDP is hard to check)
    doctor_tcp(server_ip_address, "21114", "API");
    doctor_tcp(server_ip_address, "21115", "hbbs extra port for nat test");
    doctor_tcp(server_ip_address, "21116", "FastRDServer");
    doctor_tcp(server_ip_address, "21117", "hbbr tcp");
    doctor_tcp(server_ip_address, "21118", "hbbs websocket");
    doctor_tcp(server_ip_address, "21119", "hbbr websocket");

    // TODO: key check
}

fn doctor(server_address_unclean: &str) {
    let server_address3 = server_address_unclean.trim();
    let server_address2 = server_address3.to_lowercase();
    let server_address = server_address2.as_str();
    println!("Checking server:  {server_address}\n");
    if let Ok(server_ipaddr) = server_address.parse::<IpAddr>() {
        // user requested an ip address
        doctor_ip(server_ipaddr, None);
    } else {
        // the passed string is not an ip address
        let ips: Vec<std::net::IpAddr> = lookup_host(server_address).unwrap();
        println!("Found {} IP addresses: ", ips.len());

        ips.iter().for_each(|ip| println!(" - {ip}"));

        ips.iter()
            .for_each(|ip| doctor_ip(*ip, Some(server_address)));
    }
}

// ---------------------------------------------------------------- accounts

fn db_url() -> String {
    // Same resolution the server uses, so the CLI always edits the database the
    // running service actually reads.
    std::env::var("DB_URL").unwrap_or_else(|_| "db_v2.sqlite3".to_owned())
}

#[tokio::main(flavor = "current_thread")]
async fn user_command(args: &[String]) {
    use hbbs::account;
    use hbbs::database::Database;

    sodiumoxide::init().ok();
    let url = db_url();
    if !std::path::Path::new(&url).exists() {
        println!("ERROR: database not found: {url}");
        println!("Run this from the server's working directory, or set DB_URL.");
        process::exit(1);
    }
    let db = match Database::new(&url).await {
        Ok(db) => db,
        Err(e) => {
            println!("ERROR: cannot open {url}: {e}");
            process::exit(1);
        }
    };

    let sub = args.get(2).map(|s| s.to_lowercase()).unwrap_or_default();
    match sub.as_str() {
        "list" => match db.list_users().await {
            Ok(users) if users.is_empty() => println!("(no accounts)"),
            Ok(users) => {
                println!("{:<24} {:<8} {:<7}", "NAME", "STATUS", "ADMIN");
                for u in users {
                    println!(
                        "{:<24} {:<8} {:<7}",
                        u.name,
                        if u.status == 1 { "enabled" } else { "disabled" },
                        if u.is_admin { "yes" } else { "no" }
                    );
                }
            }
            Err(e) => {
                println!("ERROR: {e}");
                process::exit(1);
            }
        },
        "add" => {
            let (Some(name), Some(pw)) = (args.get(3), args.get(4)) else {
                error_then_help("Usage: user add [name] [password]");
                return;
            };
            if let Ok(Some(_)) = db.get_user_by_name(name).await {
                println!("ERROR: account '{name}' already exists");
                process::exit(1);
            }
            match account::hash_password(pw) {
                Ok(hash) => match db.insert_user(name, &hash, false).await {
                    Ok(_) => println!("created account '{name}'"),
                    Err(e) => {
                        println!("ERROR: {e}");
                        process::exit(1);
                    }
                },
                Err(e) => {
                    println!("ERROR: {e}");
                    process::exit(1);
                }
            }
        }
        "passwd" => {
            let (Some(name), Some(pw)) = (args.get(3), args.get(4)) else {
                error_then_help("Usage: user passwd [name] [password]");
                return;
            };
            match db.get_user_by_name(name).await {
                Ok(Some(u)) => match account::hash_password(pw) {
                    Ok(hash) => match db.set_user_password(&u.guid, &hash).await {
                        // set_user_password also drops that user's tokens, so every
                        // other signed-in device is logged out -- which is the point
                        // of resetting a password you think has leaked.
                        Ok(_) => {
                            println!("password changed for '{name}'; other sessions signed out")
                        }
                        Err(e) => {
                            println!("ERROR: {e}");
                            process::exit(1);
                        }
                    },
                    Err(e) => {
                        println!("ERROR: {e}");
                        process::exit(1);
                    }
                },
                Ok(None) => {
                    println!("ERROR: no such account '{name}'");
                    process::exit(1);
                }
                Err(e) => {
                    println!("ERROR: {e}");
                    process::exit(1);
                }
            }
        }
        "disable" | "enable" => {
            let Some(name) = args.get(3) else {
                error_then_help("Usage: user disable|enable [name]");
                return;
            };
            let want = if sub == "enable" { 1 } else { 0 };
            match db.set_user_status(name, want).await {
                Ok(true) => println!(
                    "'{name}' is now {}",
                    if want == 1 { "enabled" } else { "disabled" }
                ),
                Ok(false) => {
                    println!("ERROR: no such account '{name}'");
                    process::exit(1);
                }
                Err(e) => {
                    println!("ERROR: {e}");
                    process::exit(1);
                }
            }
        }
        // LOCAL FORK: 设备与账号的绑定平时由客户端登录后随 RegisterPk 上报，
        // 但那要求每台设备都手工登录一次。这几个命令让管理员在服务端直接指派，
        // 同组免密(PunchHole.same_account)依赖的就是这个绑定关系。
        "devices" => {
            let Some(name) = args.get(3) else {
                error_then_help("usage: user devices [name]");
                return;
            };
            match db.get_user_by_name(name).await {
                Ok(Some(u)) => match db.list_peers_of_user(&u.guid, 1000).await {
                    Ok(peers) if peers.is_empty() => println!("(no devices bound to {name})"),
                    Ok(peers) => {
                        println!("{:<14} {:<8}", "DEVICE", "STATUS");
                        for p in peers {
                            println!(
                                "{:<14} {:<8}",
                                p.id,
                                if p.status.unwrap_or(1) == 0 {
                                    "disabled"
                                } else {
                                    "enabled"
                                }
                            );
                        }
                    }
                    Err(e) => {
                        println!("ERROR: {e}");
                        process::exit(1);
                    }
                },
                Ok(None) => {
                    println!("ERROR: no such account: {name}");
                    process::exit(1);
                }
                Err(e) => {
                    println!("ERROR: {e}");
                    process::exit(1);
                }
            }
        }
        "bind" => {
            let (Some(name), Some(id)) = (args.get(3), args.get(4)) else {
                error_then_help("usage: user bind [name] [device-id]");
                return;
            };
            let Ok(Some(u)) = db.get_user_by_name(name).await else {
                println!("ERROR: no such account: {name}");
                process::exit(1);
            };
            // 设备必须先在服务器注册过(连过一次)，否则 peer 表里没有这一行。
            let Ok(Some(_)) = db.get_peer(id).await else {
                println!("ERROR: device {id} has never registered with this server");
                process::exit(1);
            };
            match db.set_peer_user(id, Some(&u.guid)).await {
                Ok(()) => println!("bound {id} to {name}"),
                Err(e) => {
                    println!("ERROR: {e}");
                    process::exit(1);
                }
            }
        }
        "unbind" => {
            let Some(id) = args.get(3) else {
                error_then_help("usage: user unbind [device-id]");
                return;
            };
            match db.set_peer_user(id, None).await {
                Ok(()) => println!("unbound {id}"),
                Err(e) => {
                    println!("ERROR: {e}");
                    process::exit(1);
                }
            }
        }
        _ => error_then_help("Unknown user subcommand"),
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() <= 1 {
        print_help();
    }

    let command = args[1].to_lowercase();
    match command.as_str() {
        "genkeypair" => gen_keypair(),
        "validatekeypair" => {
            if args.len() <= 3 {
                error_then_help("You must supply both the public and the secret key");
            }
            let res = validate_keypair(args[2].as_str(), args[3].as_str());
            if let Err(e) = res {
                println!("{e}");
                process::exit(0x0001);
            }
            println!("Key pair is VALID");
        }
        "user" => {
            user_command(&args);
        }
        "doctor" => {
            if args.len() <= 2 {
                error_then_help("You must supply the rustdesk-server address");
            }
            doctor(args[2].as_str());
        }
        _ => print_help(),
    }
}
