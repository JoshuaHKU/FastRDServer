//! LOCAL FORK: accounts for the address book and device grouping.
//!
//! Upstream has no user table -- accounts are a RustDesk Server Pro feature
//! served by a separate web API. This is the minimum that makes the client's
//! existing login dialog and address book work against the open-source server.
//!
//! Password hashing is **Argon2id**, via libsodium's `pwhash`, not
//! sha256-with-salt. This server is reachable from the internet; a leaked table
//! of fast hashes is effectively a leaked table of passwords, and Argon2's
//! memory cost is what makes offline cracking expensive.
//!
//! libsodium comes from `sodiumoxide`, which hbbs already depends on for its
//! signing keys -- so this adds **no new dependency**. That matters: the build
//! host cannot reach the internet and compiles from a vendored tree, so a new
//! crate would mean re-vendoring and re-shipping ~900 MB.

use crate::database::{Database, User};
use hbb_common::{bail, log, ResultType};
use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::randombytes;

/// How long a login stays valid. Long enough not to nag, short enough that an
/// abandoned device eventually stops being able to reach the address book.
pub const TOKEN_TTL_DAYS: i64 = 30;

/// The account created on an empty database, so a fresh server is usable without
/// first SSH-ing in.
pub const DEFAULT_ADMIN_NAME: &str = "admin";
pub const DEFAULT_ADMIN_PASSWORD: &str = "admin";

/// Interactive limits: ~64 MB and a few tenths of a second per hash. Enough to
/// make bulk offline cracking painful without stalling a login. The stored
/// string records the parameters, so raising these later does not invalidate
/// existing hashes.
fn hash_limits() -> (argon2id13::OpsLimit, argon2id13::MemLimit) {
    (
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
}

pub fn hash_password(password: &str) -> ResultType<String> {
    let (ops, mem) = hash_limits();
    let Ok(hashed) = argon2id13::pwhash(password.as_bytes(), ops, mem) else {
        bail!("failed to hash password");
    };
    // The result is a NUL-padded fixed-size buffer; store it as the printable
    // prefix so the column holds a normal `$argon2id$...` string.
    let end = hashed
        .0
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(hashed.0.len());
    Ok(String::from_utf8_lossy(&hashed.0[..end]).to_string())
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    // Rebuild the fixed-size buffer libsodium expects, NUL-padded.
    let mut buf = [0u8; argon2id13::HASHEDPASSWORDBYTES];
    let bytes = encoded.as_bytes();
    if bytes.len() >= buf.len() {
        return false;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    match argon2id13::HashedPassword::from_slice(&buf) {
        // A malformed stored hash must fail closed, never open.
        None => false,
        Some(h) => argon2id13::pwhash_verify(&h, password.as_bytes()),
    }
}

pub fn generate_token() -> String {
    randombytes::randombytes(32)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn token_expiry() -> String {
    let t = chrono::Utc::now() + chrono::Duration::days(TOKEN_TTL_DAYS);
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Create `admin/admin` if the user table is empty.
///
/// Only on an *empty* table: once anyone has made an account, silently adding a
/// well-known one would be a backdoor. It is also why this logs loudly.
pub async fn ensure_default_admin(db: &Database) -> ResultType<()> {
    if !db.list_users().await?.is_empty() {
        return Ok(());
    }
    let hash = hash_password(DEFAULT_ADMIN_PASSWORD)?;
    db.insert_user(DEFAULT_ADMIN_NAME, &hash, true).await?;
    log::warn!(
        "created default account '{}' with password '{}' -- change it with: \
         FastRDServer-utils user passwd {}",
        DEFAULT_ADMIN_NAME,
        DEFAULT_ADMIN_PASSWORD,
        DEFAULT_ADMIN_NAME
    );
    Ok(())
}

/// Look up a user by password.
///
/// Returns `None` for unknown name, wrong password, or disabled account --
/// deliberately indistinguishable to the caller, so the error cannot be used to
/// enumerate valid usernames.
pub async fn authenticate(db: &Database, name: &str, password: &str) -> ResultType<Option<User>> {
    let Some(user) = db.get_user_by_name(name).await? else {
        // Hash anyway, so a missing user does not answer measurably faster than
        // a wrong password.
        let _ = hash_password(password);
        return Ok(None);
    };
    if user.status != 1 {
        return Ok(None);
    }
    if !verify_password(password, &user.password) {
        return Ok(None);
    }
    Ok(Some(user))
}

/// Issue a bearer token for a successful login.
pub async fn issue_token(db: &Database, user: &User, device_id: &str) -> ResultType<String> {
    let token = generate_token();
    db.insert_token(&token, &user.guid, device_id, &token_expiry())
        .await?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        sodiumoxide::init().ok();
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(h.starts_with("$argon2id$"), "unexpected format: {h}");
        assert!(verify_password("correct horse battery staple", &h));
        assert!(!verify_password("wrong", &h));
    }

    /// Two hashes of the same password must differ: identical output would mean
    /// the salt is not random, and a precomputed table would work.
    #[test]
    fn salted_per_call() {
        sodiumoxide::init().ok();
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("same", &a));
        assert!(verify_password("same", &b));
    }

    /// A corrupt or truncated stored hash must fail closed. Failing open here
    /// would turn a damaged row into an account anyone can log into.
    #[test]
    fn malformed_hash_fails_closed() {
        sodiumoxide::init().ok();
        assert!(!verify_password("anything", ""));
        assert!(!verify_password("anything", "not-a-hash"));
        assert!(!verify_password("anything", "$argon2id$truncated"));
    }

    #[test]
    fn tokens_are_unique_and_sized() {
        sodiumoxide::init().ok();
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}
