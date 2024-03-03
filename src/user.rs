use mysql::prelude::Queryable;
use rand::Rng;

#[derive(Debug, PartialEq, Eq)]
pub struct User {
    id: i32,
    pub username: String,
    pub hash: String,
    p: u32,
    r: u32,
    n: u8,
}

pub fn get_user_info(conn: &mut mysql::PooledConn, user: String) -> Option<User> {
    let quer = "SELECT id, username, passhash, n, r, p FROM users WHERE username=? LIMIT 1";

    let usertest = conn.exec_map(quer, (user,), |(id, username, passhash, n, r, p)| User {
        id: id,
        username: username,
        hash: passhash,
        p: p,
        r: r,
        n: n,
    });
    usertest.unwrap().pop()
}

fn make_user_table(conn: &mut mysql::PooledConn) {
    println!("Making the user table");
    let result = conn.query_drop("CREATE TABLE users (id INT AUTO_INCREMENT, username VARCHAR(255) UNIQUE, passhash VARCHAR(128), n INT, r INT, p INT, PRIMARY KEY(id))");
    if let Err(e) = result {
        println!("Failed to create user table {}", e);
    }
}

fn make_login_table(conn: &mut mysql::PooledConn) {
    println!("Making the user login table");
    let result =
        conn.query_drop("CREATE TABLE login (id BIGINT, username VARCHAR(255), PRIMARY KEY(id))");
    if let Err(e) = result {
        println!("Failed to create user login table {}", e);
    }
}

pub fn check_user_table(conn: &mut mysql::PooledConn) {
    let r: Result<std::option::Option<mysql::Row>, mysql::Error> = conn.query_first("SELECT * FROM information_schema.tables WHERE table_schema = 'iot' AND table_name = 'users' LIMIT 1");
    if let None = r.unwrap() {
        make_user_table(conn);
    }
}

pub fn check_login_table(conn: &mut mysql::PooledConn) {
    let r: Result<std::option::Option<mysql::Row>, mysql::Error> = conn.query_first("SELECT * FROM information_schema.tables WHERE table_schema = 'iot' AND table_name = 'login' LIMIT 1");
    if let None = r.unwrap() {
        make_login_table(conn);
    }
}

pub fn check_login_entry(conn: &mut mysql::PooledConn, val: u64) -> Option<String> {
    let query = "SELECT username FROM login WHERE id=? LIMIT 1";
    let logintest = conn.exec_map(query, (val,), |username| username);
    logintest.unwrap().pop()
}

pub fn new_user_login(conn: &mut mysql::PooledConn, user: User) -> u64 {
    let mut random: u64;
    loop {
        random = rand::thread_rng().gen::<u64>();
        let random_fail = check_login_entry(conn, random);
        let random_fail = if let Some(_asdf) = random_fail {
            true
        } else {
            false
        };
        if !random_fail {
            break;
        }
    }
    conn.exec_drop(
        "INSERT INTO login (id, username) VALUES(?, ?)",
        (random, user.username),
    );
    random
}

pub fn try_user_login2(userinfo: &Option<User>, pass: String) -> bool {
    match userinfo {
        Some(ref u) => todo!("scrypt check pass and u.hash"),
        None => false,
    }
}

pub fn try_user_hash(conn: &mut mysql::PooledConn, user: String, hash: String) -> bool {
    if user == "".to_string() {
        return false;
    }
    let user_check = get_user_info(conn, user);
    let result = match user_check {
        Some(ref u) => hash == u.hash,
        None => false,
    };
    result
}

pub fn try_user_login(conn: &mut mysql::PooledConn, user: String, pass: String) -> bool {
    let userinfo = get_user_info(conn, user);
    try_user_login2(&userinfo, pass)
}

pub fn set_admin_login(conn: &mut mysql::PooledConn, settings: &configparser::ini::Ini) {
    let scrypt_password = settings.get("admin", "pass").unwrap();
    let scrypt_r: u32 = settings.get("admin", "r").unwrap().parse().unwrap();
    let scrypt_n: u8 = settings.get("admin", "n").unwrap().parse().unwrap();
    let scrypt_p: u32 = settings.get("admin", "p").unwrap().parse().unwrap();
    let scrypt_params: scrypt::Params =
        scrypt::Params::new(scrypt_n, scrypt_r, scrypt_p, 64).unwrap();
    let scrypt_out: String;

    let admin = get_user_info(conn, "admin".to_string());

    let result = match admin {
        Some(ref admin) => {
            todo!("scrypt scrypt_password and admin.hash")
        }
        None => false,
    };

    if !result {
        scrypt_out = todo!("scrypt scrypt_password and scrypt_params");
        let result = match admin {
            Some(_x) => {
                println!("Updating the admin account");
                conn.exec_drop(
                    "UPDATE users SET passhash=?, n=?, r=?, p=? WHERE username='admin'",
                    (scrypt_out, scrypt_n, scrypt_r, scrypt_p),
                )
            }
            None => {
                println!("Creating the admin account");
                conn.exec_drop(
                    "INSERT INTO users (username, passhash, n, r, p) VALUES(?, ?, ?, ?, ?)",
                    ("admin", scrypt_out, scrypt_n, scrypt_r, scrypt_p),
                )
            }
        };
        if let Err(e) = result {
            println!("Failed to update/create admin account {}", e);
        }
        ()
    } else {
        println!("Not updating admin account");
    }
}
