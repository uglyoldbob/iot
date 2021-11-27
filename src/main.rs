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
    let s = "Hello world";
    if context.dirmap.contains_key(path)
    {
        println!("{} exists", path);
        let fun = context.dirmap.get_key_value(path);
        fun;
    }
    else
    {

    }
    let t = format!("{}{}",s, path);
    Ok(Response::new(Body::from(t)))
}

#[tokio::main]
async fn main() {
    let mut map : HashMap<String, fn() -> String> = HashMap::new();
    let hc = HttpContext {
        dirmap: map.clone(),
        root: "/etc".to_string(),
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
