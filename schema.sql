CREATE TABLE peer (
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
CREATE UNIQUE INDEX index_peer_id on peer (id);
CREATE INDEX index_peer_user on peer (user);
CREATE INDEX index_peer_created_at on peer (created_at);
CREATE INDEX index_peer_status on peer (status);
CREATE TABLE user (guid blob primary key not null, name varchar(100) not null, password varchar(200) not null, email varchar(200), status tinyint not null default 1, is_admin boolean not null default 0, created_at datetime not null default(current_timestamp), ab text) without rowid;
CREATE UNIQUE INDEX index_user_name on user (name);
CREATE TABLE user_token (token varchar(64) primary key not null, user_guid blob not null, device_id varchar(100), created_at datetime not null default(current_timestamp), expires_at datetime not null) without rowid;
CREATE INDEX index_token_user on user_token (user_guid);
