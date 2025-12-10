//! This module is used to run a webserver.

use futures::stream::FuturesUnordered;
use futures::{Future, FutureExt};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::convert::Infallible;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_rustls::rustls::RootCertStore;

use cookie::Cookie;

/// Represents the response of an async function web handler. Contains web page data and cookie information.
pub struct WebResponse {
    /// The response to deliver to the web client.
    pub response: hyper::Response<http_body_util::Full<hyper::body::Bytes>>,
    /// The loginn cookie after processing has been done
    pub cookie: Option<String>,
}

/// Routes web requests to an async function
pub struct WebRouter {
    /// The map used by the router
    r: HashMap<String, HashMapCallback>,
}

impl WebRouter {
    /// Create a blank web router.
    pub fn new() -> Self {
        WebRouter { r: HashMap::new() }
    }
    /// Register an async function to handle the given path
    /// # Arguments
    /// * path - The exact path to handle
    /// * f - The async function that handles the specified path
    pub fn register<F, R>(&mut self, path: &str, f: F)
    where
        F: Fn(WebPageContext) -> R + Send + Sync + 'static,
        R: Future<Output = WebResponse> + Send + Sync + 'static,
    {
        let h = move |a: WebPageContext| Box::pin(f(a));
        self.r.insert(path.to_string(), Box::new(h));
    }
}

/// The type to store in a hasmap when asyn fn are needed in a hashmap
type HashMapCallback = Box<dyn WebHandlerTrait>;

/// Used to stored async functions in a hashmap.
trait WebHandlerTrait: Send + Sync + 'static {
    /// Call the contained async function
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

/// The context necessary to respond to a web request.
pub struct HttpContext {
    /// The map for static content, mapping urls to static content files
    pub static_map: HashMap<String, String>,
    /// The map that is used to route requests to the proper async function.
    pub dirmap: WebRouter,
    /// The root path for static files
    pub root: String,
    /// The name of the login cookie
    pub cookiename: String,
    /// This maps domain names to proxy names
    pub proxy: HashMap<String, String>,
    /// The optional mysql connection
    pub pool: Option<mysql::Pool>,
    /// The application settings
    pub settings: Arc<crate::MainConfiguration>,
    /// The pki object
    pub pki: Arc<futures::lock::Mutex<crate::ca::PkiInstance>>,
}

/// Represents extra context for a web service
pub struct ExtraContext {
    /// True when the context is https
    pub https: bool,
    /// The optional list of user certificates
    pub user_certs: Arc<Option<Vec<x509_cert::Certificate>>>,
}

/// Represents the ways user certs can make it to us
pub enum UserCert {
    /// The user certs came directly from tls, could be a user certificate or a load balancer (reverse proxy) certificate.
    HttpsCert(x509_cert::Certificate),
    /// The user certs came from http headers
    ProxyCert(x509_cert::Certificate),
}

/// A list of all the `UserCert` that the current page knows about.
pub struct UserCerts(Vec<UserCert>);

impl UserCerts {
    /// Return a list of all certs, regardless of how the made it here
    pub fn all_certs(&self) -> Vec<&x509_cert::Certificate> {
        self.0
            .iter()
            .map(|c| match c {
                UserCert::HttpsCert(a) => a,
                UserCert::ProxyCert(a) => a,
            })
            .collect()
    }
}

/// Represents the context necessary to render a webpage
pub struct WebPageContext {
    /// Was https used to access the page?
    https: bool,
    /// The domain that was used to access the request
    pub domain: String,
    /// The actual page requested
    pub page: std::path::PathBuf,
    /// The proxy sub-directory
    pub proxy: String,
    /// The map of all post arguments
    pub post: PostContent,
    /// The map of all get arguments
    pub get: HashMap<String, String>,
    /// The login cookie
    pub logincookie: Option<String>,
    /// The optional mysql server connection
    pub pool: Option<mysql::PooledConn>,
    /// The list of user certificates presented by the user
    pub user_certs: UserCerts,
    /// The application settings
    pub settings: Arc<crate::MainConfiguration>,
    /// The pki object
    pub pki: Arc<futures::lock::Mutex<crate::ca::PkiInstance>>,
}

impl WebPageContext {
    /// Build an absolute url
    pub fn get_absolute_url(&self, sd: &str, url: &str) -> String {
        match &self.settings.pki {
            crate::ca::PkiConfigurationEnum::AddedCa(ca) => {
                if self.https {
                    format!("https://{}/{}{}", self.domain, self.proxy, url)
                } else {
                    format!("http://{}/{}{}", self.domain, self.proxy, url)
                }
            }
            crate::ca::PkiConfigurationEnum::Pki(pki_configuration) => {
                if self.https {
                    format!("https://{}/{}{}{}", self.domain, self.proxy, sd, url)
                } else {
                    format!("http://{}/{}{}{}", self.domain, self.proxy, sd, url)
                }
            }
            crate::ca::PkiConfigurationEnum::Ca(standalone_ca_configuration) => {
                if self.https {
                    format!("https://{}/{}{}", self.domain, self.proxy, url)
                } else {
                    format!("http://{}/{}{}", self.domain, self.proxy, url)
                }
            }
        }
    }
}

/// Represents the contents of a post request
#[derive(Clone)]
pub struct PostContent {
    /// The body of a request, containing some content
    body: Option<hyper::body::Bytes>,
    /// The headers, for extracting the multipart
    headers: hyper::header::HeaderMap,
}

impl PostContent {
    /// Construct a Self with the given body and headers.
    fn new(body: Option<hyper::body::Bytes>, headers: hyper::header::HeaderMap) -> Self {
        Self { body, headers }
    }

    /// Just get the post content
    #[allow(dead_code)]
    pub fn content(&self) -> Option<Vec<u8>> {
        self.body.as_ref().map(|d| d.to_vec())
    }

    /// Convert the post content to an ocsp request if possible.
    pub fn ocsp(&self) -> Option<ocsp::request::OcspRequest> {
        let b = self.body.as_ref()?;
        ocsp::request::OcspRequest::parse(b.as_ref()).ok()
    }

    /// Convert the post content to form data if possible
    pub fn form(&self) -> Option<url_encoded_data::UrlEncodedData<'_>> {
        if let Some(body) = self.body.as_ref() {
            let s = std::str::from_utf8(body).ok()?;
            Some(url_encoded_data::UrlEncodedData::parse_str(s))
        } else {
            None
        }
    }

    /// Convert the post content to a multipart request if possible.
    #[allow(dead_code)]
    pub fn multipart(&self) -> Option<multer::Multipart<'_>> {
        if let Some(body) = &self.body {
            if let Some(boundary) = self.headers.get("Content-Type") {
                let data = futures_util::stream::once(async move {
                    Result::<multer::bytes::Bytes, Infallible>::Ok(body.clone())
                });
                let bs = boundary.to_str().unwrap();
                Some(multer::Multipart::new(data, bs))
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl std::io::Read for PostContent {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let b = match self.body.as_ref() {
            None => {
                return Ok(0);
            }
            Some(a) => a,
        };
        buf.copy_from_slice(b);
        Ok(b.len())
    }
}

/// Represents the information required to handle web requests
struct WebService<F, R, C> {
    /// The context of the web service
    context: Arc<C>,
    /// The address that is being listened on
    addr: SocketAddr,
    /// True when https is involved
    https: bool,
    /// The user certificates for the request
    user_certs: Arc<Option<Vec<x509_cert::Certificate>>>,
    /// The async function called to service web requests
    f: F,
    /// Required to make it work
    _req: PhantomData<fn(Arc<C>, SocketAddr, R)>,
}

impl<F, R, S, C> WebService<F, R, C>
where
    F: Fn(Arc<C>, ExtraContext, SocketAddr, Request<R>) -> S,
    S: futures::Future,
{
    /// Create a new Self
    /// # Arguments
    /// * context - The context for the web service
    /// * addr - The address the service is listening on
    /// * f - The async function used to handle web requests
    fn new(context: Arc<C>, https: bool, addr: SocketAddr, f: F) -> Self {
        Self {
            context,
            addr,
            https,
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
            addr: self.addr,
            https: self.https,
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
            https: self.https,
            user_certs: self.user_certs.clone(),
        };
        (self.f)(self.context.clone(), ec, self.addr, req)
    }
}

/// Used to receive the full contents of a body and convert it into a `hyper::body::Frame<hyper::body::Bytes>`
struct BodyHandler {
    /// The body being handled
    b: hyper::body::Incoming,
}

impl Future for BodyHandler {
    type Output = Option<Result<hyper::body::Frame<hyper::body::Bytes>, hyper::Error>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let a = Pin::new(&mut self.b);
        hyper::body::Body::poll_frame(a, cx)
    }
}

/// Handle a web request
async fn handle<'a>(
    context: Arc<HttpContext>,
    ec: ExtraContext,
    _addr: SocketAddr,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    let (rparts, body) = req.into_parts();

    let mut post_data: Option<hyper::body::Bytes> = None;

    let reader = BodyHandler { b: body };
    let body = reader.await;
    if let Some(Ok(b)) = body {
        let b = b.into_data().unwrap();
        post_data = Some(b);
    }

    let post_data = PostContent::new(post_data, rparts.headers.to_owned());

    let mut get_map = HashMap::new();
    let get_data = rparts.uri.query().unwrap_or("");
    let get_split = get_data.split('&');
    for get_elem in get_split {
        let mut ele_split = get_elem.split('=').take(2);
        let i1 = ele_split.next().unwrap_or_default();
        let i2 = ele_split.next().unwrap_or_default();
        get_map.insert(i1.to_owned(), i2.to_owned());
    }

    let hdrs = rparts.headers;

    let cks_ga = hdrs.get_all("cookie");
    let mut cookiemap = HashMap::new();
    for c in cks_ga.into_iter() {
        let cookies = c.to_str().unwrap().split(';');
        for ck in cookies {
            let cookie = Cookie::parse(ck).unwrap();
            let (c1, c2) = cookie.name_value();
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

    let mut user_certs = UserCerts(Vec::new());
    if let Some(uc) = ec.user_certs.as_ref() {
        for c in uc {
            user_certs.0.push(UserCert::HttpsCert(c.to_owned()));
        }
    }

    let ssls = hdrs.get_all("ssl_client_cert");
    for ssl in ssls {
        use der::DecodePem;
        let ssl = url_escape::decode(std::str::from_utf8(ssl.as_bytes()).unwrap());
        let x509 = x509_cert::Certificate::from_pem(ssl.as_bytes()).unwrap();
        user_certs.0.push(UserCert::ProxyCert(x509));
    }

    let mysql = context.pool.as_ref().map(|f| f.get_conn().unwrap());
    service::log::debug!("URI IS \"{}\" \"{}\"", rparts.method, rparts.uri);
    let domain = hdrs.get("host").unwrap().to_str().unwrap().to_string();
    service::log::debug!("Domain host is \"{}\"", domain);
    let domain2 = if let Some((a, _b)) = domain.as_str().split_once(':') {
        a.to_string()
    } else {
        domain.clone()
    };
    let path = rparts.uri.path();
    let proxy = if let Some(p) = context.proxy.get(&domain2) {
        p.to_owned()
    } else {
        String::new()
    };
    let fixed_path = path;

    let cookiename = format!("{}{}", proxy, context.cookiename);

    service::log::info!("Lookup {} on {}{}", fixed_path, domain2, proxy);

    let p = WebPageContext {
        https: ec.https,
        domain,
        page: <std::path::PathBuf as std::str::FromStr>::from_str(fixed_path).unwrap(),
        post: post_data,
        get: get_map,
        proxy: proxy.clone(),
        logincookie: ourcookie.clone(),
        pool: mysql,
        user_certs,
        settings: context.settings.clone(),
        pki: context.pki.clone(),
    };

    let body = if let Some(fun) = context.dirmap.r.get(fixed_path) {
        fun.call(p).await
    } else {
        let response = hyper::Response::new("dummy");
        let (mut response, _) = response.into_parts();
        // lookup the fixed path, if it exists use it, otherwise use the path from the static map
        // This means that the static map is a fallback
        let fixed_path = if let Some(a) = context.static_map.get(fixed_path) {
            if std::path::PathBuf::from(context.root.to_owned() + fixed_path).exists() {
                fixed_path.to_string()
            } else {
                a.to_owned()
            }
        } else {
            fixed_path.to_string()
        };
        let sys_path = std::path::PathBuf::from(context.root.to_owned() + &fixed_path);
        let file = tokio::fs::read(sys_path.clone()).await;
        let body = match file {
            Ok(c) => {
                service::log::debug!("File {} loaded", sys_path.display());
                if let Some(ext) = sys_path.extension() {
                    match ext.to_str().unwrap() {
                        "css" => {
                            response.headers.append(
                                "Content-Type",
                                hyper::header::HeaderValue::from_static("text/css"),
                            );
                        }
                        "js" => {
                            response.headers.append(
                                "Content-Type",
                                hyper::header::HeaderValue::from_static("text/javascript"),
                            );
                        }
                        "wasm" => {
                            response.headers.append(
                                "Content-Type",
                                hyper::header::HeaderValue::from_static("application/wasm"),
                            );
                        }
                        _ => {}
                    }
                }
                let body = hyper::body::Bytes::copy_from_slice(&c);
                http_body_util::Full::new(body)
            }
            Err(_e) => {
                service::log::debug!("File {} missing", sys_path.display());
                response.status = StatusCode::NOT_FOUND;
                http_body_util::Full::new(hyper::body::Bytes::from("missing"))
            }
        };

        let response = hyper::http::Response::from_parts(response, body);

        WebResponse {
            response,
            cookie: p.logincookie,
        }
    };

    //this section expires the cookie if it needs to be deleted
    //and makes the contents empty
    let sent_cookie = match body.cookie {
        Some(ref x) => {
            let testcookie: cookie::CookieBuilder = cookie::Cookie::build((&cookiename, x))
                .http_only(true)
                .path(proxy)
                .same_site(cookie::SameSite::Strict);
            testcookie
        }
        None => {
            let testcookie: cookie::CookieBuilder = cookie::Cookie::build((&cookiename, ""))
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
    /// Create a new Self
    pub fn new(inner: T) -> Self {
        Self { inner }
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

/// Start an http webserver.
/// # Arguments
/// * hc - The httpcontext that the webserver will run under
/// * port - The port to listen on
/// * tasks: A joinset used to determine if any critical threads have terminated early.
pub async fn http_webserver(
    hc: Arc<HttpContext>,
    port: u16,
    tasks: &mut tokio::task::JoinSet<Result<(), ServiceError>>,
) -> Result<(), ServiceError> {
    // Construct our SocketAddr to listen on...
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ServiceError::Other(e.to_string()))?;

    let webservice = WebService::new(hc, false, addr, handle);

    tasks.spawn(async move {
        service::log::info!("Rust-iot server is running");

        let mut f: FuturesUnordered<Pin<Box<dyn futures::Future<Output = ()> + Send>>> =
            FuturesUnordered::new();

        let (t, mut r) = tokio::sync::mpsc::channel(50);

        let acceptor = async {
            loop {
                let la = listener
                    .accept()
                    .await
                    .map_err(|e| ServiceError::Other(e.to_string()));
                let (stream, _addr) = match la {
                    Err(e) => {
                        service::log::error!("Error accepting connection {:?}", e);
                        continue;
                    }
                    Ok(s) => s,
                };
                let io = TokioIo::new(stream);
                let svc = webservice.clone();
                let _ = t.send((svc, io)).await;
            }
        };

        tokio::pin!(acceptor);

        loop {
            use futures::StreamExt;
            tokio::select! {
                _ = &mut acceptor => { break; }
                Some((svc, io)) = r.recv() => {
                    f.push(Box::pin(async move {
                        if let Err(err) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await
                        {
                            service::log::error!("Error serving connection: {:?}", err);
                        }
                    }));
                }
                Ok(Some(_)) = AssertUnwindSafe(f.next()).catch_unwind() => { }
                _ = tokio::signal::ctrl_c() => break,
            }
        }
        Ok(())
    });
    Ok(())
}

pub mod tls;

/// The types of errors that can occur when starting a service within the application
#[derive(Debug)]
pub enum ServiceError {
    /// A general catch-all error type.
    Other(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Start an https webserver.
/// # Arguments
/// * hc - The httpcontext that the webserver will run under
/// * port - The port to listen on
/// * tls_config - A struct describing how to load the pkcs12 document.
/// * tasks: A joinset used to determine if any critical threads have terminated early.
/// * client_certs - Used to request and verify tls client certificates
/// * require_cert - True when the https should require a client certificate.
pub async fn https_webserver(
    hc: Arc<HttpContext>,
    port: u16,
    https: crate::ca::HttpsCertificate,
    tasks: &mut tokio::task::JoinSet<Result<(), ServiceError>>,
    client_certs: Option<RootCertStore>,
    require_cert: bool,
) -> Result<(), ServiceError> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let cert = tls::load_certificate(&https, client_certs, &hc.pki, require_cert).map_err(|e| {
        service::log::error!("Error loading https certificate {}", e);
        ServiceError::Other(e.to_string())
    })?;

    let acc: tokio_rustls::TlsAcceptor = cert.into();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ServiceError::Other(e.to_string()))?;

    let webservice = WebService::new(hc, true, addr, handle);

    tasks.spawn(async move {
        service::log::info!("Rust-iot https server is running");

        let mut f: FuturesUnordered<Pin<Box<dyn futures::Future<Output = ()> + Send>>> =
            FuturesUnordered::new();

        let (t, mut r) = tokio::sync::mpsc::channel(50);

        let acceptor = async {
            loop {
                let la = listener
                    .accept()
                    .await
                    .map_err(|e| ServiceError::Other(e.to_string()));
                let (stream, addr) = match la {
                    Err(e) => {
                        service::log::error!("Error accepting connection {:?}", e);
                        continue;
                    }
                    Ok(s) => s,
                };

                let stream = acc.accept(stream).await;
                let mut stream = match stream {
                    Err(e) => {
                        service::log::error!("Error accepting tls stream: {:?}", e);
                        continue;
                    }
                    Ok(s) => s,
                };
                let (_a, b) = stream.get_mut();
                let mut svc = webservice.clone();
                svc.addr = addr;
                let cert = b.peer_certificates();
                let sn = b.server_name();
                service::log::info!("Server name is {:?}", sn);
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
                let _ = t.send((svc, io)).await;
            }
        };

        tokio::pin!(acceptor);

        loop {
            use futures::StreamExt;
            tokio::select! {
                _ = &mut acceptor => { break; }
                Some((svc, io)) = r.recv() => {
                    f.push(Box::pin(async move {
                        if let Err(err) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await
                        {
                            service::log::error!("Error serving connection: {:?}", err);
                        }
                    }));
                }
                Ok(Some(_)) = AssertUnwindSafe(f.next()).catch_unwind() => { }
                _ = tokio::signal::ctrl_c() => break,
                else => break,
            }
        }
        Ok(())
    });

    Ok(())
}
