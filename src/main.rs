use std::convert::Infallible;
use std::net::SocketAddr;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::server::conn::AddrStream;
use std::collections::HashMap;

use std::sync::{Arc, Mutex};
use std::fs;
use regex::Regex;
use cookie::Cookie;
use ttl_cache::TtlCache;
use rand::{distributions::Alphanumeric, Rng};
use futures::FutureExt;

mod user;

type Callback = fn(&mut WebPageContext, &mut hyper::http::response::Parts) -> Body;

#[derive(Clone)]
struct SessionContents {
    id: u32,
    user: String,
    passhash: String,
}

#[derive(Clone)]
struct HttpContext {
    dirmap : HashMap<String, Callback>,
    root: String,
    cookiename: String,
    proxy: Option<String>,
    sess: Arc<Mutex<TtlCache<String,SessionContents>>>, //to be something else actually useful
    pool: mysql::Pool,
}

struct WebPageContext {
    proxy: String,
    post: HashMap<String, String>,
    get: HashMap<String, String>,
    ourcookie: Option<String>,
    pool: mysql::PooledConn,
    session: SessionContents,
}

fn test_func(s: &mut WebPageContext, _bld: &mut hyper::http::response::Parts) -> Body {
    s.ourcookie = None;
    Body::from("this is a test".to_string())
}

fn main_page(s: &mut WebPageContext, _bld: &mut hyper::http::response::Parts) -> Body {
    let mut c : String = "<HTML>".to_string();
    s.session.id = s.session.id+1;
    if s.post.contains_key("username") && s.post.contains_key("password") {
        let uname = &s.post["username"];
        let pass = &s.post["password"];
	let useri = user::get_user_info(&mut s.pool, uname.to_string());
        let login_pass = user::try_user_login2(
            &useri, pass.to_string());
        if login_pass {
            let useru = useri.unwrap();
            s.session.user = useru.username;
            s.session.passhash = useru.hash;
        }
        else {
            //login failed because account does not exist
            c.push_str("Login fail");
        }
    }
    let logged_in = user::try_user_hash(&mut s.pool, 
        s.session.user.to_owned(), 
        s.session.passhash.to_owned());
    if !logged_in {
    c.push_str("
Welcome to the login page!
<form>
    Username: 
    <input type=\"text\" id=\"username\" name=\"username\"><br>
    Password: 
    <input type=\"password\" id=\"password\" name=\"password\"><br>
    <input type=\"submit\" value=\"Login\" formmethod=\"post\"><br>
    </form>
</HTML>");
    }
    else
    {
        c.push_str("You are logged in</HTML>")
    }
    Body::from(c)
}

fn main_redirect(s: &mut WebPageContext, bld: &mut hyper::http::response::Parts) -> Body {
    bld.status = hyper::http::StatusCode::from_u16(302).unwrap();
    let url = format!("{}/main.rs", s.proxy.to_string());
    bld.headers.insert("Location",hyper::http::header::HeaderValue::from_str(&url).unwrap());
    Body::from("redirect goes here")
}

async fn handle(
    context: HttpContext,
    addr: SocketAddr,
    req: Request<Body>
    ) -> Result<Response<Body>, Infallible> {

    let (rparts,body) = req.into_parts();

    let mut post_data = HashMap::new();
    let body_data = hyper::body::to_bytes(body).await;
    let body_data = body_data.unwrap();
    let body_data = std::str::from_utf8(&body_data);
    let body_parts = body_data.unwrap().split("&");
    for bel in body_parts {
        let mut ele_split = bel.split("=").take(2);
            let i1 = ele_split.next().unwrap_or_default();
            let i2 = ele_split.next().unwrap_or_default();
            post_data.insert(i1.to_owned(), i2.to_owned());
    }

    let get_data = rparts.uri.query().unwrap_or("");
    let get_split = get_data.split("&");
    let mut get_map = HashMap::new();
    for get_elem in get_split {
        let mut ele_split = get_elem.split("=").take(2);
            let i1 = ele_split.next().unwrap_or_default();
            let i2 = ele_split.next().unwrap_or_default();
            get_map.insert(i1.to_owned(), i2.to_owned());
    }

//    for (k,v) in get_map.iter() {
//        println!("GET: {} {}", k, v);
//    }

    let path = rparts.uri.path();
    let proxy = context.proxy.unwrap_or("".to_string());
    let reg1 = format!("(^{})",proxy);
    let reg1 = Regex::new(&reg1[..]).unwrap();
    let fixed_path = reg1.replace_all(&path, "");

	println!("{} access {}", addr, fixed_path);
    let sys_path = context.root + &fixed_path;

    let hdrs = rparts.headers;

    let cks_ga = hdrs.get_all("cookie");
    let mut cookiemap = HashMap::new();
    for c in cks_ga.into_iter() {
        let cookies = c.to_str().unwrap().split(";");
        for ck in cookies {
            let cookie = Cookie::parse(ck).unwrap();
            let (c1, c2) = cookie.name_value();
            //println!("The cookie is {:?} {:?}", c1, c2);
            cookiemap.insert(c1.to_owned(), c2.to_owned());
        }
    }

//    for (k, v) in cookiemap.iter() {
//        println!("COOKIE {:?} {:?}", k, v);
//    }

//    for (key, value) in hdrs.iter() {
//        println!(" {:?}: {:?}", key, value);
//    }

    let mysql = context.pool.get_conn().unwrap();

    let response = Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let ourcookie = if cookiemap.contains_key(&context.cookiename)
    {
	let value  = &cookiemap[&context.cookiename];
        Some(value.to_owned())
    }
    else
    {
        let newcookie: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(64)
                .map(char::from)
                .collect();
        Some(newcookie.to_owned())
    };
    let session_cache_mut = context.sess;
    let session_cache = session_cache_mut.lock().unwrap();
    //determine if the session data exists
    let session_data_maybe = session_cache.get(&ourcookie.as_ref().unwrap().to_owned());
    let session_data = match session_data_maybe {
        Some(x) => {
            println!("There is something here in session data");
            x.clone()
        },
        None => {
            println!("There is nothing here at session data");
            SessionContents { id: 0,
		user: "".to_string(),
		passhash: "".to_string()}
        },
    };

    drop(session_cache);

    let mut p = WebPageContext {
            post: post_data,
            get: get_map,
            proxy: proxy,
            ourcookie: ourcookie.clone(),
            pool: mysql,
            session: session_data,
        };

    let body = if context.dirmap.contains_key(&fixed_path.to_string())
    {
//        println!("script {} exists", &fixed_path.to_string());
        let (_key,fun) = context.dirmap.get_key_value(&fixed_path.to_string()).unwrap();
        fun(&mut p, &mut response)
    }
    else
    {
        let file = fs::read_to_string(sys_path.clone());
        match file {
            Ok(c) => Body::from(c),
            Err(_) => Body::from("Not found".to_string()),
        }
    };

    let mut session_lock2 = session_cache_mut.lock().unwrap();
    let index = &ourcookie.clone().unwrap();
    session_lock2.insert(index.to_owned(), p.session, std::time::Duration::from_secs(1440));
    drop(session_lock2);

    //this section expires the cookie if it needs to be deleted
    //and makes the contents empty
    let sent_cookie = match p.ourcookie {
        Some(ref x) => {
            let testcookie: cookie::Cookie = cookie::Cookie::build(&context.cookiename, x)
                .http_only(true)
                .same_site(cookie::SameSite::Strict)
                .finish();
            testcookie
        },
        None => {
            let testcookie: cookie::Cookie = cookie::Cookie::build(&context.cookiename, "")
                .http_only(true)
                .expires(time::OffsetDateTime::unix_epoch())
                .same_site(cookie::SameSite::Strict)
                .finish();
            testcookie
        },
    };
    
    response.headers.append("Set-Cookie", hyper::http::header::HeaderValue::from_str(
            &sent_cookie.to_string()).unwrap());
    
    Ok(hyper::http::Response::from_parts(response,body))
}

async fn webserver(hc: HttpContext,
	http_port: u16) {
    // Construct our SocketAddr to listen on...
    let addr = SocketAddr::from(([127, 0, 0, 1], http_port));

    // And a MakeService to handle each connection...
    let make_service = make_service_fn(move |conn: &AddrStream| {
        let context = hc.clone();
        let addr = conn.remote_addr();
        async move {
        Ok::<_, Infallible>(service_fn(move|req| {
            let context = context.clone();
            async move { 
                    handle(context.clone(),addr,req).await}} ))
        }
    });

    // Then bind and serve...
   let server = Server::bind(&addr).serve(make_service);

    println!("Rust-iot server is running");
    // And run forever...
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

#[tokio::main]
async fn main() {
    let mut map : HashMap<String, Callback> = HashMap::new();
    map.insert("/asdf".to_string(), test_func);
    map.insert("".to_string(), main_redirect);
    map.insert("/".to_string(), main_redirect);
    map.insert("/main.rs".to_string(), main_page);

    let settings_file = fs::read_to_string("./settings.ini");
    let settings_con = match settings_file {
        Ok(con) => con,
        Err(_) => "".to_string(),
    };
    let mut settings = configparser::ini::Ini::new();
    let settings_result = settings.read(settings_con);
    if let Err(e) = settings_result {
	println!("Failed to read settings {}", e);
    }

    let mysql_pw = settings.get("database","password").unwrap_or("iinvalid".to_string());
    let mysql_user = settings.get("database", "username").unwrap_or("invalid".to_string());
    let mysql_dbname = settings.get("database", "name").unwrap_or("none".to_string());
    let mysql_url = settings.get("database", "url").unwrap_or("invalid".to_string());
    let mysql_conn_s = format!("mysql://{}:{}@{}/{}", mysql_user, mysql_pw, mysql_url, mysql_dbname);
    let mysql_opt = mysql::Opts::from_url(mysql_conn_s.as_str()).unwrap();
    let mysql_temp = mysql::Pool::new(mysql_opt);
    match mysql_temp {
        Ok(ref _bla) => println!("I have a bla"),
        Err(ref e) => println!("Error connecting to mysql: {}", e),
    }
    let mysql_pool = mysql_temp.unwrap();
    let mut mysql_conn_s = mysql_pool.get_conn().unwrap();

    let mut hc = HttpContext {
        dirmap: map.clone(),
        root: ".".to_string(),
        proxy: Some("/testing".to_string()),
        cookiename: "rustcookie".to_string(),
        sess: Arc::new(Mutex::new(TtlCache::new(50))),
        pool: mysql_pool,
    };

    user::check_user_table(&mut mysql_conn_s);
    user::set_admin_login(&mut mysql_conn_s, &settings);

    hc.cookiename = settings.get("general","cookie").unwrap_or("rustcookie".to_string());
    
    match &hc.proxy {
        Some(s) => println!("Using {} as the proxy path", s),
        None => println!("Not using a proxy path"),
    }

//    println!("{} is {}", "bob", settings.getint("general","bob").unwrap_or(None).unwrap_or(32));

    let http_port = settings.getint("http", "port").unwrap_or(None).unwrap_or(3001) as u16;
    println!("Listening on port {}", http_port);

    tokio::spawn(async move {
	webserver(hc, http_port).await;
	});

	loop {
		futures::select! {
			_ = tokio::signal::ctrl_c().fuse() => {
				break;
			}
		}
	}
	println!("Ending the server");
}
