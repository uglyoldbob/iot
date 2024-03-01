use hyper::service::service_fn;
use hyper::{Request, Response};
use std::collections::HashMap;
use std::convert::Infallible;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use cookie::Cookie;

pub type Callback = fn(
    &mut WebPageContext,
    &mut hyper::http::response::Parts,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>>;

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
    get: HashMap<String, String>,
    pub logincookie: Option<String>,
    pub pool: Option<mysql::PooledConn>,
    pub pc: Option<X509>,
}

use openssl::x509::X509;

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
    // TODO collect post data

    let mut get_map = HashMap::new();
    // TODO collect get data

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

    let response = Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    let ourcookie = None;

    let mut p = WebPageContext {
        post: post_data,
        get: get_map,
        proxy: "todo".to_string(),
        logincookie: ourcookie.clone(),
        pool: None,
        pc: None,
    };

    let body = http_body_util::Full::new(hyper::body::Bytes::from("I am groot!"));
    Ok(hyper::http::Response::from_parts(response, body))
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
use crate::webserver::tls::*;

pub async fn https_webserver(
    hc: Arc<HttpContext>,
    port: u16,
    tls_config: TlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let cert = load_private_key(&tls_config.key_file, &tls_config.key_password)?;

    let acc = tokio_native_tls::native_tls::TlsAcceptor::new(cert).unwrap();
    let acc: tokio_native_tls::TlsAcceptor = acc.into();
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
            let stream = stream.unwrap();
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
