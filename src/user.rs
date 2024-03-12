//! This module manages users in the system

use mysql::prelude::Queryable;
use rand::Rng;

/// Represents a single user of the system
#[derive(Debug, PartialEq, Eq)]
pub struct User {
    /// The user id
    id: i32,
    /// The username
    pub username: String,
    /// The hash of the user's password
    pub hash: String,
    /// The p value for password hashing
    p: u32,
    /// The r value for password hashing
    r: u32,
    /// The n value for password hashing
    n: u8,
}

/// Get the specified user from the database
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

/// Create the user table
fn make_user_table(conn: &mut mysql::PooledConn) {
    println!("Making the user table");
    let result = conn.query_drop("CREATE TABLE users (id INT AUTO_INCREMENT, username VARCHAR(255) UNIQUE, passhash VARCHAR(128), n INT, r INT, p INT, PRIMARY KEY(id))");
    if let Err(e) = result {
        println!("Failed to create user table {}", e);
    }
}

/// Create the login table
fn make_login_table(conn: &mut mysql::PooledConn) {
    println!("Making the user login table");
    let result =
        conn.query_drop("CREATE TABLE login (id BIGINT, username VARCHAR(255), PRIMARY KEY(id))");
    if let Err(e) = result {
        println!("Failed to create user login table {}", e);
    }
}

/// Create the user table if it does not exist
pub fn check_user_table(conn: &mut mysql::PooledConn) {
    let r: Result<std::option::Option<mysql::Row>, mysql::Error> = conn.query_first("SELECT * FROM information_schema.tables WHERE table_schema = 'iot' AND table_name = 'users' LIMIT 1");
    if r.unwrap().is_none() {
        make_user_table(conn);
    }
}

/// Create the login table if it does not exist
pub fn check_login_table(conn: &mut mysql::PooledConn) {
    let r: Result<std::option::Option<mysql::Row>, mysql::Error> = conn.query_first("SELECT * FROM information_schema.tables WHERE table_schema = 'iot' AND table_name = 'login' LIMIT 1");
    if r.unwrap().is_none() {
        make_login_table(conn);
    }
}

/// Get the username with the user login
pub fn check_login_entry(conn: &mut mysql::PooledConn, val: u64) -> Option<String> {
    let query = "SELECT username FROM login WHERE id=? LIMIT 1";
    let logintest = conn.exec_map(query, (val,), |username| username);
    logintest.unwrap().pop()
}

/// Create a new user login with a random user id, verifying the user id does not already exist.
pub fn new_user_login(conn: &mut mysql::PooledConn, user: User) -> Result<u64, mysql::Error> {
    let mut random: u64;
    loop {
        random = rand::thread_rng().gen::<u64>();
        let random_fail = check_login_entry(conn, random);
        let random_fail = matches!(random_fail, Some(_asdf));
        if !random_fail {
            break;
        }
    }
    conn.exec_drop(
        "INSERT INTO login (id, username) VALUES(?, ?)",
        (random, user.username),
    )?;
    Ok(random)
}

/// Try to login a user with a password. TODO: move to implementation of User
/// # Arguments
/// * userinfo - The user
/// * pass - The password for the user
pub fn try_user_login2(userinfo: &Option<User>, pass: String) -> bool {
    match userinfo {
        Some(ref u) => todo!("scrypt check pass and u.hash"),
        None => false,
    }
}

/// Try to login with a hash
/// # Arguments
/// * conn - The mysql database connection
/// * user - The username
/// * hash - The hash of the users password
pub fn try_user_hash(conn: &mut mysql::PooledConn, user: String, hash: String) -> bool {
    if user.is_empty() {
        return false;
    }
    let user_check = get_user_info(conn, user);
    match user_check {
        Some(ref u) => hash == u.hash,
        None => false,
    }
}

/// Try to login a user with the given username and password.
/// # Arguments
/// * conn - The mysql database connection
/// * user - The username
/// * pass - The password for the username
pub fn try_user_login(conn: &mut mysql::PooledConn, user: String, pass: String) -> bool {
    let userinfo = get_user_info(conn, user);
    try_user_login2(&userinfo, pass)
}

/// Used to initalize the administrator login for the system using the credentials specified in the config file.
pub fn set_admin_login(conn: &mut mysql::PooledConn, settings: &crate::MainConfiguration) {
    let scrypt_password = settings.admin.get("pass").unwrap().as_str().unwrap();
    let scrypt_r: u32 = settings.admin.get("r").unwrap().as_integer().unwrap() as u32;
    let scrypt_n: u8 = settings.admin.get("n").unwrap().as_integer().unwrap() as u8;
    let scrypt_p: u32 = settings.admin.get("p").unwrap().as_integer().unwrap() as u32;
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
