use std::convert::Infallible;
use std::net::SocketAddr;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::server::conn::AddrStream;
use std::collections::HashMap;

use std::fs;
use std::panic;
use regex::Regex;

type Callback = fn(String) -> Option<String>;

#[derive(Clone)]
struct HttpContext {
    dirmap : HashMap<String, Callback>,
    root: String,
    proxy: Option<String>,
}

fn test_func(s: String) -> Option<String> {
    Some("this is a test".to_string())
}

async fn handle(
    context: HttpContext,
    addr: SocketAddr,
    req: Request<Body>
    ) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();
    let proxy = context.proxy.unwrap_or("".to_string());
    let reg1 = format!("(^{})",proxy);
    let reg1 = Regex::new(&reg1[..]).unwrap();
    let fixed_path = reg1.replace_all(&path, "");
    println!("Fixed path is {}", fixed_path);
    let sys_path = context.root + &fixed_path;
    let s = "Hello world";
    println!("syspath is {}", sys_path);
    let mut contents : Result<String, String> = if context.dirmap.contains_key(&fixed_path.to_string())
    {
        println!("script {} exists", &fixed_path.to_string());
        let (key,fun) = context.dirmap.get_key_value(&fixed_path.to_string()).unwrap();
        let f = fun("asdf".to_string());
        match f {
            Some(c) => Ok(c),
            None => Err("Script failed".to_string())
        }
    }
    else
    {
        let file = fs::read_to_string(sys_path.clone());
        match file {
            Ok(_) => println!("{} exists", sys_path),
            Err(_) => println!("Could not open {}", sys_path),
        }
        match file {
            Ok(c) => Ok(c),
            Err(_) => Err("not found".to_string()),
        }
    };
    let t = match (contents)
    {
        Ok(c) => format!("{}{}{}",s, path, c),
        Err(e) => format!("error {} {} {}", s, path, e),
    };
    Ok(Response::new(Body::from(t)))
}

fn get_string_setting(dat: configparser::ini::Ini, 
                      s: String, v: String, def: String) -> String {
    return dat.get(&s, &v).unwrap_or(def);
}

#[tokio::main]
async fn main() {
    let mut map : HashMap<String, Callback> = HashMap::new();
    map.insert("/asdf".to_string(), test_func);
    let hc = HttpContext {
        dirmap: map.clone(),
        root: ".".to_string(),
        proxy: Some("/testing".to_string()),
    };

    let settings_file = fs::read_to_string("./settings.ini");
    let settings_con = match settings_file {
        Ok(con) => con,
        Err(_) => "".to_string(),
    };
    let mut settings = configparser::ini::Ini::new();
    settings.read(settings_con);
    
    match &hc.proxy {
        Some(s) => println!("Using {} as the proxy path", s),
        None => println!("Not using a proxy path"),
    }

    println!("{} is {}", "bob", settings.getint("general","bob").unwrap_or(None).unwrap_or(32));

    // Construct our SocketAddr to listen on...
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

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
