use futures::future::BoxFuture;
use futures::Future;
use hyper::{Request, Response, StatusCode};
use regex::Regex;
use std::collections::HashMap;
use std::convert::Infallible;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_rustls::rustls::server::danger::ClientCertVerifier;

use cookie::Cookie;

pub struct WebResponse {
    pub response: hyper::Response<http_body_util::Full<hyper::body::Bytes>>,
    pub cookie: Option<String>,
}

pub struct WebRouter {
    r: HashMap<String, HashMapCallback>,
}

impl WebRouter {
    pub fn new() -> Self {
        WebRouter { r: HashMap::new() }
    }

    pub fn register<F, R>(&mut self, path: &str, f: F)
    where
        F: Fn(WebPageContext) -> R + Send + Sync + 'static,
        R: Future<Output = WebResponse> + Send + Sync + 'static,
    {
        let h = move |a: WebPageContext| Box::pin(f(a));
        self.r.insert(path.to_string(), Box::new(h));
    }
}

pub type Callback =
    fn(&mut WebPageContext) -> (dyn Future<Output = WebResponse> + Send + Sync + 'static);

type HashMapCallback = Box<dyn WebHandlerTrait>;

trait WebHandlerTrait: Send + Sync + 'static {
    fn call(&self, req: WebPageContext)
        -> Pin<Box<dyn Future<Output = WebResponse> + Send + Sync>>;
}

impl<F: Send + Sync + 'static, R> WebHandlerTrait for F
where
    F: Fn(WebPageContext) -> R + Send + Sync,
    R: Future<Output = WebResponse> + Send + Sync + 'static,
{
    fn call(
        &self,
        req: WebPageContext,
    ) -> Pin<Box<dyn Future<Output = WebResponse> + Send + Sync>> {
        Box::pin(self(req))
    }
}

pub struct HttpContext {
    pub dirmap: WebRouter,
    pub root: String,
    pub cookiename: String,
    pub proxy: String,
    pub pool: Option<mysql::Pool>,
}

pub struct ExtraContext {
    pub user_certs: Arc<Option<Vec<x509_cert::Certificate>>>,
}

pub enum UserCerts {
    HttpsCerts(Vec<x509_cert::Certificate>),
    ProxyCerts(Vec<x509_cert::Certificate>),
    None,
}

impl UserCerts {
    pub fn all_certs(&self) -> Option<&Vec<x509_cert::Certificate>> {
        match self {
            UserCerts::HttpsCerts(hc) => Some(&hc),
            UserCerts::ProxyCerts(pc) => Some(&pc),
            UserCerts::None => None,
        }
    }
}

pub struct WebPageContext {
    pub proxy: String,
    pub post: HashMap<String, String>,
    pub get: HashMap<String, String>,
    pub logincookie: Option<String>,
    pub pool: Option<mysql::PooledConn>,
    pub user_certs: UserCerts,
}

struct WebService<F, R, C> {
    context: Arc<C>,
    addr: SocketAddr,
    user_certs: Arc<Option<Vec<x509_cert::Certificate>>>,
    f: F,
    _req: PhantomData<fn(Arc<C>, SocketAddr, R)>,
}

impl<F, R, S, C> WebService<F, R, C>
where
    F: Fn(Arc<C>, ExtraContext, SocketAddr, Request<R>) -> S,
    S: futures::Future,
{
    fn new(context: Arc<C>, addr: SocketAddr, f: F) -> Self {
        Self {
            context,
            addr,
            user_certs: Arc::new(None),
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
            user_certs: self.user_certs.clone(),
            addr: self.addr.clone(),
            _req: PhantomData,
        }
    }
}

impl<C, F, ReqBody, Ret, ResBody, E> hyper::service::Service<Request<ReqBody>>
    for WebService<F, ReqBody, C>
where
    F: Fn(Arc<C>, ExtraContext, SocketAddr, Request<ReqBody>) -> Ret,
    Ret: futures::Future<Output = Result<Response<ResBody>, E>>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResBody: hyper::body::Body,
{
    type Response = Response<ResBody>;
    type Error = E;
    type Future = Ret;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        let ec = ExtraContext {
            user_certs: self.user_certs.clone(),
        };
        (self.f)(self.context.clone(), ec, self.addr, req)
    }
}

/// TODO Figure out how to pass a reference of an HttpContext instead of a clone of one
async fn handle<'a>(
    context: Arc<HttpContext>,
    ec: ExtraContext,
    _addr: SocketAddr,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    let (rparts, _body) = req.into_parts();

    let post_data = HashMap::new();
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

    let user_certs = if let Some(uc) = ec.user_certs.as_ref() {
        UserCerts::HttpsCerts(uc.to_owned())
    } else {
        UserCerts::None
    };

    let mysql = context.pool.as_ref().map(|f| f.get_conn().unwrap());

    let mut p = WebPageContext {
        post: post_data,
        get: get_map,
        proxy: context.proxy.to_owned(),
        logincookie: ourcookie.clone(),
        pool: mysql,
        user_certs,
    };

    let path = rparts.uri.path();
    let proxy = &context.proxy;
    let reg1 = format!("(^{})", proxy);
    let reg1 = Regex::new(&reg1[..]).unwrap();
    let fixed_path = reg1.replace_all(&path, "");
    let sys_path = context.root.to_owned() + &fixed_path;

    println!("Lookup {}", fixed_path);

    let body = if context.dirmap.r.contains_key(&fixed_path.to_string()) {
        let (_key, fun) = context
            .dirmap
            .r
            .get_key_value(&fixed_path.to_string())
            .unwrap();
        fun.call(p).await
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
        WebResponse {
            response: hyper::http::Response::from_parts(response, body),
            cookie: p.logincookie,
        }
    };

    //this section expires the cookie if it needs to be deleted
    //and makes the contents empty
    let sent_cookie = match body.cookie {
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
    Ok(body.response)
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
    tasks: &mut tokio::task::JoinSet<Result<(), ServiceError>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Construct our SocketAddr to listen on...
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let webservice = WebService::new(hc, addr, handle);

    tasks.spawn(async move {
        println!("Rust-iot server is running");
        loop {
            let (stream, _addr) = listener
                .accept()
                .await
                .map_err(|e| ServiceError::Other(e.to_string()))?;
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
    });
    Ok(())
}

pub mod tls;

#[derive(Debug)]
pub enum ServiceError {
    Other(String),
}

pub async fn https_webserver(
    hc: Arc<HttpContext>,
    port: u16,
    tls_config: tls::TlsConfig,
    tasks: &mut tokio::task::JoinSet<Result<(), ServiceError>>,
    client_certs: Option<Arc<dyn ClientCertVerifier>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let cert = tls::load_certificate(
        &tls_config.cert_file,
        &tls_config.key_password,
        client_certs,
    )?;

    let acc: tokio_rustls::TlsAcceptor = cert.into();
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let webservice = WebService::new(hc, addr, handle);

    tasks.spawn(async move {
        println!("Rust-iot https server is running?");
        loop {
            let la = listener
                .accept()
                .await
                .map_err(|e| ServiceError::Other(e.to_string()));
            let (stream, addr) = match la {
                Err(e) => {
                    println!("Error accepting connection {:?}", e);
                    continue;
                }
                Ok(s) => s,
            };
            let stream = acc.accept(stream).await;
            let mut stream = match stream {
                Err(e) => {
                    println!("Error accepting tls stream: {:?}", e);
                    continue;
                }
                Ok(s) => s,
            };
            let (_a, b) = stream.get_mut();
            let mut svc = webservice.clone();
            svc.addr = addr;
            let cert = b.peer_certificates();
            let certs = cert.map(|cder| {
                let certs: Vec<x509_cert::certificate::Certificate> = cder
                    .iter()
                    .map(|c| {
                        use der::Decode;
                        x509_cert::Certificate::from_der(c).unwrap()
                    })
                    .collect();
                certs
            });
            svc.user_certs = Arc::new(certs);
            let io = TokioIo::new(stream);
            tokio::task::spawn(async move {
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
    });

    Ok(())
}
