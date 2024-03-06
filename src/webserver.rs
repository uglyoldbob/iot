use hyper::{Request, Response, StatusCode};
use regex::Regex;
use std::collections::HashMap;
use std::convert::Infallible;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use cookie::Cookie;

pub type Callback =
    fn(&mut WebPageContext) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>>;

pub struct HttpContext {
    pub dirmap: HashMap<String, Callback>,
    pub root: String,
    pub cookiename: String,
    pub proxy: String,
    pub pool: Option<mysql::Pool>,
}

pub struct WebPageContext {
    pub proxy: String,
    pub post: HashMap<String, String>,
    pub get: HashMap<String, String>,
    pub logincookie: Option<String>,
    pub pool: Option<mysql::PooledConn>,
}

struct WebService<F, R, C> {
    context: Arc<C>,
    addr: SocketAddr,
    f: F,
    _req: PhantomData<fn(Arc<C>, SocketAddr, R)>,
}

impl<F, R, S, C> WebService<F, R, C>
where
    F: Fn(Arc<C>, SocketAddr, Request<R>) -> S,
    S: futures::Future,
{
    fn new(context: Arc<C>, addr: SocketAddr, f: F) -> Self {
        Self {
            context,
            addr,
            f,
            _req: PhantomData,
        }
    }
}

impl<F, R, C> Clone for WebService<F, R, C>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            context: self.context.clone(),
            addr: self.addr.clone(),
            _req: PhantomData,
        }
    }
}

impl<C, F, ReqBody, Ret, ResBody, E> hyper::service::Service<Request<ReqBody>>
    for WebService<F, ReqBody, C>
where
    F: Fn(Arc<C>, SocketAddr, Request<ReqBody>) -> Ret,
    Ret: futures::Future<Output = Result<Response<ResBody>, E>>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResBody: hyper::body::Body,
{
    type Response = Response<ResBody>;
    type Error = E;
    type Future = Ret;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        (self.f)(self.context.clone(), self.addr, req)
    }
}

/// TODO Figure out how to pass a reference of an HttpContext instead of a clone of one
async fn handle<'a>(
    context: Arc<HttpContext>,
    addr: SocketAddr,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    let (rparts, body) = req.into_parts();

    let mut post_data = HashMap::new();
    // TODO collect post data from body

    let mut get_map = HashMap::new();
    let get_data = rparts.uri.query().unwrap_or("");
    let get_split = get_data.split("&");
    for get_elem in get_split {
        let mut ele_split = get_elem.split("=").take(2);
        let i1 = ele_split.next().unwrap_or_default();
        let i2 = ele_split.next().unwrap_or_default();
        get_map.insert(i1.to_owned(), i2.to_owned());
    }

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

    let response = Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let ourcookie = if cookiemap.contains_key(&context.cookiename) {
        let value = &cookiemap[&context.cookiename];
        Some(value.to_owned())
    } else {
        None
    };

    let mysql = context.pool.as_ref().map(|f| f.get_conn().unwrap());

    let mut p = WebPageContext {
        post: post_data,
        get: get_map,
        proxy: context.proxy.to_owned(),
        logincookie: ourcookie.clone(),
        pool: mysql,
    };

    let path = rparts.uri.path();
    let proxy = &context.proxy;
    let reg1 = format!("(^{})", proxy);
    let reg1 = Regex::new(&reg1[..]).unwrap();
    let fixed_path = reg1.replace_all(&path, "");
    let sys_path = context.root.to_owned() + &fixed_path;

    let body = if context.dirmap.contains_key(&fixed_path.to_string()) {
        let (_key, fun) = context
            .dirmap
            .get_key_value(&fixed_path.to_string())
            .unwrap();
        fun(&mut p)
    } else {
        let response = hyper::Response::new("dummy");
        let (mut response, _) = response.into_parts();
        let file = std::fs::read_to_string(sys_path.clone());
        let body = match file {
            Ok(c) => http_body_util::Full::new(hyper::body::Bytes::from(c)),
            Err(_e) => {
                response.status = StatusCode::NOT_FOUND;
                http_body_util::Full::new(hyper::body::Bytes::from("missing"))
            }
        };
        hyper::http::Response::from_parts(response, body)
    };

    //this section expires the cookie if it needs to be deleted
    //and makes the contents empty
    let sent_cookie = match p.logincookie {
        Some(ref x) => {
            let testcookie: cookie::CookieBuilder = cookie::Cookie::build((&context.cookiename, x))
                .http_only(true)
                .path(proxy)
                .same_site(cookie::SameSite::Strict);
            testcookie
        }
        None => {
            let testcookie: cookie::CookieBuilder =
                cookie::Cookie::build((&context.cookiename, ""))
                    .http_only(true)
                    .path(proxy)
                    .expires(time::OffsetDateTime::UNIX_EPOCH)
                    .same_site(cookie::SameSite::Strict);
            testcookie
        }
    };

    response.headers.append(
        "Set-Cookie",
        hyper::http::header::HeaderValue::from_str(&sent_cookie.to_string()).unwrap(),
    );

    Ok(body)
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    struct TokioIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> TokioIo<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn inner(self) -> T {
        self.inner
    }
}

impl<T> hyper::rt::Read for TokioIo<T>
where
    T: tokio::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match tokio::io::AsyncRead::poll_read(self.project().inner, cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> hyper::rt::Write for TokioIo<T>
where
    T: tokio::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(self.project().inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_flush(self.project().inner, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(self.project().inner, cx)
    }

    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(&self.inner)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write_vectored(self.project().inner, cx, bufs)
    }
}

impl<T> tokio::io::AsyncRead for TokioIo<T>
where
    T: hyper::rt::Read,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tbuf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        //let init = tbuf.initialized().len();
        let filled = tbuf.filled().len();
        let sub_filled = unsafe {
            let mut buf = hyper::rt::ReadBuf::uninit(tbuf.unfilled_mut());

            match hyper::rt::Read::poll_read(self.project().inner, cx, buf.unfilled()) {
                Poll::Ready(Ok(())) => buf.filled().len(),
                other => return other,
            }
        };

        let n_filled = filled + sub_filled;
        // At least sub_filled bytes had to have been initialized.
        let n_init = sub_filled;
        unsafe {
            tbuf.assume_init(n_init);
            tbuf.set_filled(n_filled);
        }

        Poll::Ready(Ok(()))
    }
}

impl<T> tokio::io::AsyncWrite for TokioIo<T>
where
    T: hyper::rt::Write,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        hyper::rt::Write::poll_write(self.project().inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        hyper::rt::Write::poll_flush(self.project().inner, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        hyper::rt::Write::poll_shutdown(self.project().inner, cx)
    }

    fn is_write_vectored(&self) -> bool {
        hyper::rt::Write::is_write_vectored(&self.inner)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        hyper::rt::Write::poll_write_vectored(self.project().inner, cx, bufs)
    }
}

pub async fn http_webserver(
    hc: Arc<HttpContext>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    // Construct our SocketAddr to listen on...
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let webservice = WebService::new(hc, addr, handle);

    tokio::task::spawn(async move {
        println!("Rust-iot server is running");
        loop {
            let (stream, _addr) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let svc = webservice.clone();
            tokio::task::spawn(async move {
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
        Ok::<(), std::io::Error>(())
    });
    Ok(())
}

pub mod tls;

pub async fn https_webserver(
    hc: Arc<HttpContext>,
    port: u16,
    tls_config: tls::TlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let cert = tls::load_certificate(&tls_config.cert_file, &tls_config.key_password)?;

    let acc: tokio_rustls::TlsAcceptor = cert.into();
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let webservice = WebService::new(hc, addr, handle);

    tokio::task::spawn(async move {
        println!("Rust-iot https server is running?");
        loop {
            let (stream, _addr) = listener.accept().await?;
            let stream = acc.accept(stream).await;
            if let Err(e) = stream {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
            }
            let mut stream = stream.unwrap();
            let (a, b) = stream.get_mut();
            let cert = b.peer_certificates();
            match cert {
                Some(c) => {
                    for cert in c {
                        println!("Certificate: ");
                        for b in cert.iter() {
                            print!("{:X} ", b);
                        }
                        println!("");
                    }
                }
                None => {
                    println!("No peer certificate");
                }
            }
            let io = TokioIo::new(stream);
            let svc = webservice.clone();
            tokio::task::spawn(async move {
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
        Ok::<(), std::io::Error>(())
    });

    Ok(())
}
