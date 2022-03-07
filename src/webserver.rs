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

pub trait Buildable {
    fn new() -> Self;
    fn duplicate(&self) -> Self;
}

pub type Callback<T> = fn(&mut WebPageContext<T>, &mut hyper::http::response::Parts) -> Body;

#[derive(Clone)]
pub struct HttpContext<T> where T: Clone {
    pub dirmap : HashMap<String, Callback<T>>,
    pub root: String,
    pub cookiename: String,
    pub proxy: Option<String>,
    pub sess: Arc<Mutex<TtlCache<String,T>>>, //to be something else actually useful
    pub pool: mysql::Pool,
}

pub struct WebPageContext<T> {
    pub proxy: String,
    pub post: HashMap<String, String>,
    get: HashMap<String, String>,
    pub ourcookie: Option<String>,
    pub pool: mysql::PooledConn,
    pub session: T,
}

async fn handle<T: Buildable + std::clone::Clone>(
    context: HttpContext<T>,
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
            x.duplicate()
        },
        None => {
            println!("There is nothing here at session data");
            T::new()
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

pub async fn http_webserver<T:'static + Clone + Buildable + Send>(hc: HttpContext<T>,
	http_port: u16) {
    // Construct our SocketAddr to listen on...
    let addr = SocketAddr::from(([0, 0, 0, 0], http_port));

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

pub mod tls;
use crate::webserver::tls::*;
use hyper::server::conn::AddrIncoming;
use std::future::ready;
use tokio::net::TcpListener;
use tls_listener::TlsListener;
use std::io::{self, Read};

pub async fn https_webserver<T:'static + Clone + Buildable + Send>
    (
    hc:HttpContext<T>, 
    http_port: u16,
    tls_config: TlsConfig) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0,0,0,0], http_port));

    let cert = load_private_key(&tls_config.key_file, &tls_config.key_password).unwrap(); 

//    let incoming = TlsObject::new(cert,addr).await;
      let incoming = TlsListener::new(tls_acceptor(cert), AddrIncoming::bind(&addr)?);
/*          .filter(|conn| {
        if let Err(err) = conn {
            eprintln!("Error: {:?}", err);
            ready(false)
        } else {
            ready(true)
        }
    });
*/
    // And a MakeService to handle each connection...
    let make_service = make_service_fn(move |conn: &tokio_native_tls::TlsStream<AddrStream>| {
        let context = hc.clone();
        let addr = conn.get_ref().get_ref().get_ref().remote_addr();
        async move {
        Ok::<_, Infallible>(service_fn(move|req| {
            let context = context.clone();
            async move { 
                    handle(context.clone(),addr,req).await}} ))
        }
    });

    let server = Server::builder(incoming).serve(make_service);
    println!("Listening on https://{}", addr);
    Ok(())
}
