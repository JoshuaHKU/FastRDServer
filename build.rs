fn main() {
    hbb_common::gen_version();
    ensure_sqlx_schema_db();
}

/// LOCAL FORK: create the schema database sqlx needs at **compile** time.
///
/// `sqlx::query!` / `query_as!` validate every SQL statement while compiling, by
/// opening the database named in `.env`'s `DATABASE_URL` and reading its schema.
/// Without it the build dies with a wall of
///
/// ```text
/// error: error returned from database: no such table: peer
///    --> src/database.rs:83:9
/// ```
///
/// which reads like a runtime problem but is not.
///
/// Upstream never hit this: their `.gitignore` excludes the file and
/// contributors happen to have one lying around from running the server. A
/// fresh clone has nothing, so the very first build fails for a reason that has
/// nothing to do with what is being built.
///
/// Rather than commit a binary SQLite file, generate it from the checked-in
/// `schema.sql` -- reviewable, diffable, and obviously free of anyone's data.
/// The runtime database lives in the service's working directory and has
/// nothing to do with this one.
fn ensure_sqlx_schema_db() {
    use std::path::Path;
    println!("cargo:rerun-if-changed=schema.sql");

    let db = Path::new("db_v2.sqlite3");
    // Treat a zero-length file as absent: that is what a checkout leaves behind
    // if the name was ever committed empty, and sqlx would reject it anyway.
    if db.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return;
    }
    let Ok(schema) = std::fs::read_to_string("schema.sql") else {
        println!("cargo:warning=schema.sql is missing; sqlx compile-time checks will fail");
        return;
    };
    let _ = std::fs::remove_file(db);
    if let Err(e) = apply_schema(db, &schema) {
        println!("cargo:warning=cannot build {}: {e}", db.display());
    }
}

/// Run `schema.sql` through the `sqlite3` binary.
///
/// Adding a crate just to issue `CREATE TABLE` at build time would be a poor
/// trade; the `sqlite3` command is already needed to inspect the database during
/// operation, so requiring it here costs nothing new.
fn apply_schema(db: &std::path::Path, sql: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("sqlite3")
        .arg(db)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!("sqlite3 not found ({e}); install it, or create db_v2.sqlite3 by hand with: sqlite3 db_v2.sqlite3 < schema.sql")
        })?;
    child
        .stdin
        .as_mut()
        .ok_or("cannot write to sqlite3")?
        .write_all(sql.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}
