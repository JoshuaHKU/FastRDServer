use async_trait::async_trait;
use hbb_common::{log, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

/// LOCAL FORK: a registered account.
#[derive(Default, Clone)]
pub struct User {
    pub guid: Vec<u8>,
    pub name: String,
    pub password: String,
    pub email: Option<String>,
    pub status: i64,
    pub is_admin: bool,
    pub ab: Option<String>,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = crate::common::get_arg_or("MAX_DATABASE_CONNECTIONS", "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);

            -- LOCAL FORK: accounts, so the address book can be per-user and devices
            -- can be grouped. `peer.user` above is upstream's -- it exists and is
            -- indexed but was never written to; we now point it at user.guid.
            create table if not exists user (
                guid blob primary key not null,
                name varchar(100) not null,
                -- Argon2id encoded string; carries its own salt and parameters.
                -- Not sha256+salt: this server is reachable from the internet, and
                -- a leaked table of fast hashes is a leaked table of passwords.
                password varchar(200) not null,
                email varchar(200),
                status tinyint not null default 1,
                is_admin boolean not null default 0,
                created_at datetime not null default(current_timestamp),
                -- Legacy-mode address book: the whole book as one JSON document.
                -- The client falls back to this shape when /api/ab/personal 404s.
                ab text
            ) without rowid;
            create unique index if not exists index_user_name on user (name);

            -- Opaque bearer tokens rather than JWT: changing a password has to be
            -- able to invalidate sessions on other machines immediately, which a
            -- self-contained token cannot do.
            create table if not exists user_token (
                token varchar(64) primary key not null,
                user_guid blob not null,
                device_id varchar(100),
                created_at datetime not null default(current_timestamp),
                expires_at datetime not null
            ) without rowid;
            create index if not exists index_token_user on user_token (user_guid);
        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    /// LOCAL FORK: every registered peer, for the device list.
    ///
    /// The in-memory map only holds peers seen since this process started, so it
    /// cannot answer "what devices exist" on its own -- an offline machine would
    /// simply vanish from the list after a server restart. The table is the
    /// authoritative roster; online state is overlaid from memory by the caller.
    ///
    /// `limit` is a hard cap so this can never become an unbounded scan.
    pub async fn list_peers(&self, limit: i64) -> ResultType<Vec<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer order by id limit ?",
            limit
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query!(
            "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    // ---------------------------------------------------------------- accounts

    pub async fn get_user_by_name(&self, name: &str) -> ResultType<Option<User>> {
        Ok(sqlx::query_as!(
            User,
            "select guid, name, password, email, status, is_admin, ab from user where name = ?",
            name
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn get_user_by_guid(&self, guid: &[u8]) -> ResultType<Option<User>> {
        Ok(sqlx::query_as!(
            User,
            "select guid, name, password, email, status, is_admin, ab from user where guid = ?",
            guid
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn list_users(&self) -> ResultType<Vec<User>> {
        Ok(sqlx::query_as!(
            User,
            "select guid, name, password, email, status, is_admin, ab from user order by name"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_user(
        &self,
        name: &str,
        password_hash: &str,
        is_admin: bool,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query!(
            "insert into user(guid, name, password, is_admin) values(?, ?, ?, ?)",
            guid,
            name,
            password_hash,
            is_admin
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    /// Changing a password drops every token for that user: a password change is
    /// how you evict a device you no longer trust, so leaving old sessions alive
    /// would defeat the point.
    pub async fn set_user_password(&self, guid: &[u8], password_hash: &str) -> ResultType<()> {
        sqlx::query!(
            "update user set password=? where guid=?",
            password_hash,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        sqlx::query!("delete from user_token where user_guid=?", guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// Returns false when there is no such account, so the CLI can say so rather
    /// than reporting a silent success.
    pub async fn set_user_status(&self, name: &str, status: i64) -> ResultType<bool> {
        let r = sqlx::query!("update user set status=? where name=?", status, name)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn get_user_ab(&self, guid: &[u8]) -> ResultType<Option<String>> {
        let row = sqlx::query!("select ab from user where guid = ?", guid)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?;
        Ok(row.and_then(|r| r.ab))
    }

    pub async fn set_user_ab(&self, guid: &[u8], ab: &str) -> ResultType<()> {
        sqlx::query!("update user set ab=? where guid=?", ab, guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------------ tokens

    pub async fn insert_token(
        &self,
        token: &str,
        user_guid: &[u8],
        device_id: &str,
        expires_at: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "insert into user_token(token, user_guid, device_id, expires_at) values(?, ?, ?, ?)",
            token,
            user_guid,
            device_id,
            expires_at
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    /// Resolve a bearer token to its user, rejecting expired ones in the query so
    /// a stale token can never authenticate even if cleanup has not run.
    pub async fn user_by_token(&self, token: &str) -> ResultType<Option<User>> {
        Ok(sqlx::query_as!(
            User,
            "select u.guid, u.name, u.password, u.email, u.status, u.is_admin, u.ab
             from user u join user_token t on t.user_guid = u.guid
             where t.token = ? and t.expires_at > current_timestamp",
            token
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn delete_token(&self, token: &str) -> ResultType<()> {
        sqlx::query!("delete from user_token where token=?", token)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn purge_expired_tokens(&self) -> ResultType<()> {
        sqlx::query!("delete from user_token where expires_at <= current_timestamp")
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------------ peers

    /// Bind a device to an account. This is what "grouping" is: peers sharing a
    /// `user` are one group, so no separate group table is needed.
    pub async fn set_peer_user(&self, id: &str, user_guid: Option<&[u8]>) -> ResultType<()> {
        sqlx::query!("update peer set user=? where id=?", user_guid, id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn list_peers_of_user(&self, user_guid: &[u8], limit: i64) -> ResultType<Vec<Peer>> {
        // Bind as an owned Vec: sqlx cannot settle on a type for a bare `&[u8]`
        // against a BLOB column here.
        let g = user_guid.to_vec();
        // `guid!` / `id!` etc. are sqlx's not-null overrides. Filtering on a
        // nullable column makes sqlx widen every projected column to Option,
        // which no longer matches `Peer`; the bangs assert what the schema
        // already guarantees.
        Ok(sqlx::query_as!(
            Peer,
            r#"select guid as "guid!", id as "id!", uuid as "uuid!", pk as "pk!",
                      user, status, info as "info!"
               from peer where user = ? order by id limit ?"#,
            g,
            limit
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use hbb_common::tokio;
    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db = super::Database::new("test.sqlite3").await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
    }
}
