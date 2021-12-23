use mysql::prelude::Queryable;

#[derive(Debug, PartialEq, Eq)]
pub struct User {
    id: i32,
    username: String,
    hash: String,
    p: u32,
    r: u32,
    n: u8,
}

fn get_user_info(conn: &mut mysql::PooledConn, user: String) -> Option<User> {
    let quer = "SELECT id, username, passhash, n, r, p FROM users WHERE username=? LIMIT 1";

    let usertest = conn.exec_map(quer, (user,),
        |(id, username, passhash, n, r, p)| {
            User{ id: id, username: username, hash: passhash, p: p, r: r, n: n}
        },
        );
    usertest.unwrap().pop()
}

fn make_user_table(conn: &mut mysql::PooledConn) {
    println!("Making the user table");
    conn.query_drop("CREATE TABLE users (id INT AUTO_INCREMENT, username VARCHAR(255) UNIQUE, passhash VARCHAR(128), n INT, r INT, p INT, PRIMARY KEY(id))");
}

pub fn check_user_table(conn: &mut mysql::PooledConn) {
    let r: Result<std::option::Option<mysql::Row>, mysql::Error> = conn.query_first("SELECT * FROM information_schema.tables WHERE table_schema = 'iot' AND table_name = 'users' LIMIT 1");
    match r.unwrap() {
        Some(thing) => (),
        None => {
            make_user_table(conn);
        },
    };
}

pub fn try_user_login(conn: &mut mysql::PooledConn,
                      user: String,
                      pass: String) -> bool{
    let userinfo = get_user_info(conn, user);
    match userinfo {
        Some (ref u) => crypto::scrypt::scrypt_check(&pass, u.hash.as_str()).unwrap(),
        None => false,
    }
}

pub fn set_admin_login(conn : &mut mysql::PooledConn,
                   settings: &configparser::ini::Ini) {
    let mut scrypt_password = settings.get("admin", "pass").unwrap();
    let scrypt_r : u32 = settings.get("admin", "r").unwrap().parse().unwrap();
    let scrypt_n : u8 = settings.get("admin", "n").unwrap().parse().unwrap();
    let scrypt_p : u32 = settings.get("admin", "p").unwrap().parse().unwrap();
    let scrypt_params: crypto::scrypt::ScryptParams = crypto::scrypt::ScryptParams::new(scrypt_n, scrypt_r, scrypt_p);
    let mut scrypt_out : String = "".to_string();

    let admin = get_user_info(conn, "admin".to_string());
 
    let result = match admin {
        Some(ref admin) => crypto::scrypt::scrypt_check(scrypt_password.as_str(), admin.hash.as_str()).unwrap(),
        None => false,
    };

    if !result {
        scrypt_out = crypto::scrypt::scrypt_simple(
            scrypt_password .as_str(),
            &scrypt_params).unwrap();
        match admin {
            Some(x) => {
                println!("Updating the admin account");
                conn.exec_drop("UPDATE users SET passhash=?, n=?, r=?, p=? WHERE username='admin'", (scrypt_out, scrypt_n, scrypt_r, scrypt_p));
            },
            None => {
                println!("Creating the admin account");
                conn.exec_drop("INSERT INTO users (username, passhash, n, r, p) VALUES(?, ?, ?, ?, ?)", ("admin", scrypt_out, scrypt_n, scrypt_r, scrypt_p));
            }
            ,
        }
    } else {
        println!("Not updating admin account");
    }
}

