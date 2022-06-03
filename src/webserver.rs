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
use rand::{distributions::Alphanumeric, Rng};

pub type Callback = fn(&mut WebPageContext, &mut hyper::http::response::Parts) -> Body;

#[derive(Clone)]
pub struct HttpContext {
    pub dirmap : HashMap<String, Callback>,
    pub root: String,
    pub cookiename: String,
    pub proxy: String,
    pub pool: mysql::Pool,
}

pub struct WebPageContext {
    pub proxy: String,
    pub post: HashMap<String, String>,
    get: HashMap<String, String>,
    pub logincookie: Option<String>,
    pub pool: mysql::PooledConn,
    pub pc: Option<X509>
}

use openssl::x509::X509;

async fn handle(
    context: HttpContext,
    addr: SocketAddr,
    req: Request<Body>,
    pc: Option<X509>
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
    let proxy = context.proxy;
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
        None
    };

    let mut p = WebPageContext {
            post: post_data,
            get: get_map,
            proxy: proxy.clone(),
            logincookie: ourcookie.clone(),
            pool: mysql,
            pc: pc,
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

    //this section expires the cookie if it needs to be deleted
    //and makes the contents empty
    let sent_cookie = match p.logincookie {
        Some(ref x) => {
            let testcookie: cookie::Cookie = cookie::Cookie::build(&context.cookiename, x)
                .http_only(true)
                .path(proxy)
                .same_site(cookie::SameSite::Strict)
                .finish();
            testcookie
        },
        None => {
            let testcookie: cookie::Cookie = cookie::Cookie::build(&context.cookiename, "")
                .http_only(true)
                .path(proxy)
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

pub async fn http_webserver(hc: HttpContext,
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
                    handle(context.clone(),addr,req,None).await}} ))
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
use tls_listener::TlsListener;
use futures::StreamExt;
use futures::future::ready;

pub async fn https_webserver
    (
    hc:HttpContext, 
    http_port: u16,
    tls_config: TlsConfig) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0,0,0,0], http_port));

    let cert = load_private_key(&tls_config.key_file, &tls_config.key_password).unwrap(); 

//    let incoming = TlsObject::new(cert,addr).await;
      let incoming = TlsListener::new(tls_acceptor(cert), AddrIncoming::bind(&addr)?)      .filter(|conn| {
        if let Err(err) = conn {
            eprintln!("Error: {:?}", err);
            ready(false)
        } else {
            ready(true)
        }
    });

    // And a MakeService to handle each connection...
    let make_service = make_service_fn(move |conn: &tokio_native_tls::TlsStream<AddrStream>| {
        let context = hc.clone();
        let con = conn.get_ref();
        let peercert = con.peer_certificate();
        let pc = if let Ok(s) = peercert {
            if let Some(cert) = s {
                let der = cert.to_der().unwrap();
                let x509 : openssl::x509::X509 =
                    openssl::x509::X509::from_der(&der).unwrap();
                Some(x509)
            }
            else
            {
                None
            }
        }
        else
        {
            None
        };
        let addr = con.get_ref().get_ref().remote_addr();
        async move {
        Ok::<_, Infallible>(service_fn(move|req| {
            let context = context.clone();
            let pc2 = pc.clone();
            async move { 
                    handle(context.clone(),addr,req,pc2).await}} ))
        }
    });

    let server = Server::builder(hyper::server::accept::from_stream(incoming)).serve(make_service);
    println!("Listening on https://{}", addr);
    if let Err(e) = server.await {
        eprintln!("https server error: {}", e);
    }
    Ok(())
}
