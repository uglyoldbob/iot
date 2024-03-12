#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

//! This program is for managing iot devices.

//For the html crate
#![recursion_limit = "512"]

mod ca;

use std::fs;
use std::sync::Arc;

use futures::FutureExt;
use hyper::header::HeaderValue;

mod user;
mod webserver;

pub mod oid;

use crate::webserver::tls::*;
use crate::webserver::*;

/// The main configuration of the application
#[derive(serde::Deserialize)]
pub struct MainConfiguration {
    /// General settings
    pub general: toml::Table,
    /// Admin user settings
    pub admin: toml::Table,
    /// Settings for the http server
    pub http: toml::Table,
    /// Settings for the https server
    pub https: toml::Table,
    /// Settings for the database
    pub database: toml::Table,
    /// Settings for client certificates
    pub client_certs: Option<Vec<String>>,
    /// The table for ca settings
    pub ca: Option<toml::Table>,
}

/// A test function that produces demo content
async fn test_func2(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| h).body(|b| {
        b.ordered_list(|ol| {
            for name in ["I", "am", "groot"] {
                ol.list_item(|li| li.text(name));
            }
            ol
        })
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// Another test function that produces demo content
async fn test_func(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| h).body(|b| {
        if !s.get.is_empty() {
            b.ordered_list(|ol| {
                for (a, b) in s.get.iter() {
                    ol.list_item(|li| li.text(format!("{}: {}", a, b)));
                }
                ol
            });
        }
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// The page for /main.rs
async fn main_page<'a>(mut s: WebPageContext) -> webserver::WebResponse {
    let mut c: String = "".to_string();
    let mut logincookie = s.logincookie;

    let mut logged_in = false;
    let mut username: String = "".to_string();
    if let Some(cookie) = &logincookie {
        //lookup login cookie
        let value = cookie.parse::<u64>();
        if let Ok(value) = value {
            let user = s
                .pool
                .as_mut()
                .and_then(|f| user::check_login_entry(f, value));
            if let Some(user) = user {
                logged_in = true;
                username = user;
            }
        }
    }
    if s.post.contains_key("username") && s.post.contains_key("password") {
        let uname = &s.post["username"];
        let pass = &s.post["password"];
        let useri = s
            .pool
            .as_mut()
            .and_then(|f| user::get_user_info(f, uname.to_string()));
        let login_pass = user::try_user_login2(&useri, pass.to_string());
        if login_pass {
            let useru = useri.unwrap();
            let value = s.pool.as_mut().map(|f| user::new_user_login(f, useru));
            let print = format!("Login pass {:?}", value);
            c.push_str(&print);
            let cookieval = format!("{:?}", value);
            logincookie = Some(cookieval);
        } else {
            //login failed because account does not exist
            c.push_str("Login fail");
        }
    }
    /*user::try_user_hash(&mut s.pool,
    s.session.user.to_owned(),
    s.session.passhash.to_owned());*/
    if !logged_in {
        c.push_str(
            "
Welcome to the login page!
<form>
    Username: 
    <input type=\"text\" id=\"username\" name=\"username\"><br>
    Password: 
    <input type=\"password\" id=\"password\" name=\"password\"><br>
    <input type=\"submit\" value=\"Login\" formmethod=\"post\"><br>
    </form>
</HTML>",
        );
    } else {
        c.push_str(
            "
<table id=\"main-table\" border=\"0\" cellspacing=\"0\">
 <tbody>
  <tr>
   <td id=\"header\" colspan=\"3\">
    <!--[IF IE 7]>
	<style>
		div#header-div div.right-links{
			position:absolute;
		}
	</style>
    <![endif]-->
    <div id=\"header-div\">
     <div class=\"right-logo\">Management Console</div>
    </div>
   </td>
  </tr>
 </tbody>
</table>
You are logged in
</HTML>",
        )
    }
    //    s.ourcookie = None;
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(c));
    hyper::http::Response::from_parts(response, body);

    let mut html = html::root::Html::builder();
    html.head(|h| {
        h.title(|t| t.text("Rust IOT Management Console"));
        h.meta(|h| {
            h.http_equiv("content-type")
                .content("text/html;charset=utf-8")
        });
        h.link(|h| {
            h.href(format!("{}/css/main.css", s.proxy))
                .rel("stylesheet")
                .media("all")
        });
        h
    })
    .body(|b| {
        if let Some(certs) = s.user_certs.all_certs() {
            if !certs.is_empty() {
                b.text("You have a certificate");
                b.line_break(|fb| fb);
                for c in certs {
                    b.text(c.tbs_certificate.subject.to_string());
                    b.line_break(|fb| fb);
                    b.text(c.tbs_certificate.issuer.to_string());
                    b.line_break(|fb| fb);
                }
            }
        }

        if !logged_in {
            b.form(|fb| {
                fb.text("Username ")
                    .input(|ib| ib.type_("text").id("username").name("username"))
                    .line_break(|fb| fb)
                    .text("Password ")
                    .input(|ib| ib.type_("password").id("password").name("password"))
                    .line_break(|fb| fb)
                    .input(|ib| ib.type_("submit").value("Login").formmethod("post"))
                    .line_break(|fb| fb)
            });
        } else {
        }
        b
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: logincookie,
    }
}

///The page that redirects to /main.rs
async fn main_redirect(s: WebPageContext) -> webserver::WebResponse {
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    response.status = hyper::http::StatusCode::from_u16(302).unwrap();
    let url = format!("{}/main.rs", s.proxy);
    response
        .headers
        .insert("Location", HeaderValue::from_str(&url).unwrap());

    let body = http_body_util::Full::new(hyper::body::Bytes::from("I am GRooT?"));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

/// A test function that shows some demo content
async fn test_func3(s: WebPageContext) -> webserver::WebResponse {
    let mut html = html::root::Html::builder();
    html.head(|h| h).body(|b| {
        b.ordered_list(|ol| {
            for name in ["I", "am", "groot"] {
                ol.list_item(|li| li.text(name));
            }
            ol
        })
    });
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    webserver::WebResponse {
        response: hyper::http::Response::from_parts(response, body),
        cookie: s.logincookie,
    }
}

#[tokio::main]
async fn main() {
    let mut router = webserver::WebRouter::new();
    router.register("/asdf", test_func);
    router.register("/groot", test_func2);
    router.register("/groot2", test_func3);
    router.register("", main_redirect);
    router.register("/", main_redirect);
    router.register("/main.rs", main_page);
    ca::ca_register(&mut router);

    let settings_file = fs::read_to_string("./settings.ini");
    let settings_con = match settings_file {
        Ok(con) => con,
        Err(_) => "".to_string(),
    };
    let settings: MainConfiguration =
        toml::from_str(&settings_con).expect("Failed to parse configuration");

    let settings = Arc::new(settings);

    let mysql_pw = settings
        .database
        .get("password")
        .map(|a| a.to_owned())
        .unwrap_or(toml::Value::String("invalid".to_string()));
    let mysql_user = settings
        .database
        .get("username")
        .map(|a| a.to_owned())
        .unwrap_or(toml::Value::String("invalid".to_string()));
    let mysql_dbname = settings
        .database
        .get("name")
        .map(|a| a.to_owned())
        .unwrap_or(toml::Value::String("invalid".to_string()));
    let mysql_url = settings
        .database
        .get("url")
        .map(|a| a.to_owned())
        .unwrap_or(toml::Value::String("invalid".to_string()));
    let mysql_conn_s = format!(
        "mysql://{}:{}@{}/{}",
        mysql_user.as_str().unwrap(),
        mysql_pw.as_str().unwrap(),
        mysql_url.as_str().unwrap(),
        mysql_dbname.as_str().unwrap()
    );
    let mysql_opt = mysql::Opts::from_url(mysql_conn_s.as_str()).unwrap();
    let mysql_temp = mysql::Pool::new(mysql_opt);
    match mysql_temp {
        Ok(ref _bla) => println!("I have a bla"),
        Err(ref e) => println!("Error connecting to mysql: {}", e),
    }
    let mut mysql_pool = mysql_temp.ok();

    let mut mysql_conn_s = mysql_pool.as_mut().map(|s| s.get_conn().unwrap());

    let mut hc = HttpContext {
        dirmap: router,
        root: ".".to_string(),
        proxy: "".to_string(),
        cookiename: "rustcookie".to_string(),
        pool: mysql_pool,
        settings: settings.clone(),
    };

    if let Some(mysql_conn_s) = &mut mysql_conn_s {
        user::check_user_table(mysql_conn_s);
        user::check_login_table(mysql_conn_s);
        user::set_admin_login(mysql_conn_s, &settings);
    }

    hc.proxy = settings
        .general
        .get("proxy")
        .unwrap_or(&toml::Value::String("".to_string()))
        .as_str()
        .unwrap()
        .to_string();
    hc.cookiename = format!(
        "{}/{}",
        &hc.proxy,
        settings
            .general
            .get("cookie")
            .unwrap_or(&toml::Value::String("rustcookie".to_string()))
            .as_str()
            .unwrap()
            .to_string()
    );

    if hc.proxy != *"" {
        println!("Using {} as the proxy path", &hc.proxy);
    } else {
        println!("Not using a proxy path");
    }

    //    println!("{} is {}", "bob", settings.getint("general","bob").unwrap_or(None).unwrap_or(32));

    let http_enable = matches!(
        settings.http.get("enabled").unwrap().as_str().unwrap(),
        "yes"
    );
    let https_enable = matches!(
        settings.https.get("enabled").unwrap().as_str().unwrap(),
        "yes"
    );

    let hc = Arc::new(hc);

    let mut tasks: tokio::task::JoinSet<Result<(), webserver::ServiceError>> =
        tokio::task::JoinSet::new();

    let client_certs = webserver::tls::load_user_cert_data(&settings);

    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            ca::CaCertificateStorage::load_and_init(&settings).await;
        });
    });

    if http_enable {
        let http_port = settings
            .http
            .get("port")
            .unwrap_or(&toml::Value::Integer(3000))
            .as_integer()
            .unwrap_or(3000) as u16;
        println!("Listening http on port {}", http_port);

        let hc_http = hc.clone();
        if let Err(e) = http_webserver(hc_http, http_port, &mut tasks).await {
            println!("https web server errored {}", e);
        }
    }

    if https_enable {
        let https_port = settings
            .https
            .get("port")
            .unwrap_or(&toml::Value::Integer(3001))
            .as_integer()
            .unwrap_or(3001) as u16;
        println!("Listening https on port {}", https_port);

        let tls_pass = settings.https.get("certpass").unwrap().as_str().unwrap();
        let tls_cert = settings.https.get("certificate").unwrap().as_str().unwrap();
        let tls = TlsConfig::new(tls_cert, tls_pass);

        let hc_https = hc.clone();

        if let Err(e) = https_webserver(hc_https, https_port, tls, &mut tasks, client_certs).await {
            println!("https web server errored {}", e);
        }
    }

    futures::select! {
        r = tasks.join_next().fuse() => {
            println!("A task exited {:?}, closing server in 5 seconds", r);
            tokio::time::sleep(tokio::time::Duration::from_millis(5000)).await;
        }
        _ = tokio::signal::ctrl_c().fuse() => {
        }
    }
    println!("Closing server now");
}
