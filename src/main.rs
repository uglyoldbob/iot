use std::convert::Infallible;
use std::net::SocketAddr;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::server::conn::AddrStream;
use std::collections::HashMap;

use std::fs;
use std::panic;

#[derive(Clone)]
struct HttpContext {
    dirmap : HashMap<String, fn() -> String>,
    root: String,
}

async fn handle(
    context: HttpContext,
    addr: SocketAddr,
    req: Request<Body>
    ) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();
    let sys_path = context.root + path;
    let s = "Hello world";
    println!("syspath is {}", sys_path);
    let mut contents : Result<String, String> = if context.dirmap.contains_key(path)
    {
        println!("{} exists", path);
        let fun = context.dirmap.get_key_value(path);
        Err("Unable to run code".to_string())        
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
    let mut map : HashMap<String, fn() -> String> = HashMap::new();
    let hc = HttpContext {
        dirmap: map.clone(),
        root: ".".to_string(),
    };

    let settings_file = fs::read_to_string("./settings.ini");
    let settings_con = match settings_file {
        Ok(con) => con,
        Err(_) => "".to_string(),
    };

    let mut settings = configparser::ini::Ini::new();
    settings.read(settings_con);
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
