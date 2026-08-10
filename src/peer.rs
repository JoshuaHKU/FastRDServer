use crate::common::*;
use crate::database;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
    // LOCAL FORK: reported by the client on RegisterPk so the device list can show
    // something recognisable instead of a nine-digit id. `serde(default)` keeps rows
    // written before this field existed readable -- they simply come back empty.
    #[serde(default)]
    pub(crate) hostname: String,
    #[serde(default)]
    pub(crate) platform: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = get_arg_opt("DB_URL").unwrap_or_else(|| {
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
        hostname: String,
        platform: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?} {:?} {:?}", id, addr, uuid, pk);
        let (info_str, guid) = {
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.uuid = uuid.clone();
            w.pk = pk.clone();
            w.last_reg_time = Instant::now();
            w.info.ip = ip;
            // Only overwrite when the client actually sent something, so a client
            // that predates these fields does not blank out what we already know.
            if !hostname.is_empty() {
                w.info.hostname = hostname;
            }
            if !platform.is_empty() {
                w.info.platform = platform;
            }
            (
                serde_json::to_string(&w.info).unwrap_or_default(),
                w.guid.clone(),
            )
        };
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(guid) => {
                    peer.write().await.guid = guid;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("pk updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            self.map.write().await.insert(id.to_owned(), peer.clone());
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    /// LOCAL FORK: roster for the device list.
    ///
    /// Persisted rows are the source of truth for *which* devices exist; the
    /// in-memory map supplies liveness (`last_reg_time`) and the current address,
    /// which the table does not track. `exclude` drops the caller's own machine.
    ///
    /// `reg_timeout_ms` is the same freshness window the online check uses, passed
    /// in so the policy stays defined in one place (rendezvous_server.rs).
    /// Same as `list_briefs`, restricted to one account's devices.
    pub(crate) async fn list_briefs_of_user(
        &self,
        user_guid: &[u8],
        exclude: &str,
        limit: i64,
        reg_timeout_ms: i64,
    ) -> Vec<PeerBrief> {
        let rows = match self.db.list_peers_of_user(user_guid, limit).await {
            Ok(v) => v,
            Err(err) => {
                log::error!("db.list_peers_of_user failed: {}", err);
                return Vec::new();
            }
        };
        self.briefs_from_rows(rows, exclude, reg_timeout_ms).await
    }

    pub(crate) async fn list_briefs(
        &self,
        exclude: &str,
        limit: i64,
        reg_timeout_ms: i64,
    ) -> Vec<PeerBrief> {
        let rows = match self.db.list_peers(limit).await {
            Ok(v) => v,
            Err(err) => {
                log::error!("db.list_peers failed: {}", err);
                return Vec::new();
            }
        };
        self.briefs_from_rows(rows, exclude, reg_timeout_ms).await
    }

    /// Shared by both list paths: the table says which devices exist, the
    /// in-memory map supplies liveness and the current address.
    async fn briefs_from_rows(
        &self,
        rows: Vec<database::Peer>,
        exclude: &str,
        reg_timeout_ms: i64,
    ) -> Vec<PeerBrief> {
        let mem = self.map.read().await.clone();
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            if row.id == exclude {
                continue;
            }
            let stored: PeerInfo = serde_json::from_str(&row.info).unwrap_or_default();
            let (online, last_reg_ms, ip) = match mem.get(&row.id) {
                Some(p) => {
                    let p = p.read().await;
                    let elapsed = p.last_reg_time.elapsed().as_millis() as i64;
                    let ip = if p.info.ip.is_empty() {
                        stored.ip.clone()
                    } else {
                        p.info.ip.clone()
                    };
                    (elapsed < reg_timeout_ms, elapsed, ip)
                }
                // Never seen since startup: known to exist, but not online.
                None => (false, -1, stored.ip.clone()),
            };
            out.push(PeerBrief {
                id: row.id,
                online,
                ip,
                last_reg_ms,
                hostname: stored.hostname,
                platform: stored.platform,
                ..Default::default()
            });
        }
        out
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }
}
