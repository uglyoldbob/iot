#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]

//! This program is for managing iot devices.

//For the html crate
#![recursion_limit = "512"]

mod ca;
mod tpm2;

use std::io::Write;
use std::sync::Arc;

use futures::FutureExt;
use hyper::header::HeaderValue;

mod user;
mod webserver;

mod main_config;
pub mod oid;
pub mod pkcs12;
pub use main_config::MainConfiguration;
use prompt::Prompting;
use tokio::io::AsyncReadExt;

use crate::webserver::tls::*;
use crate::webserver::*;

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
    let logincookie = s.logincookie;

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
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(c));
    hyper::http::Response::from_parts(response, body);

    let mut html = html::root::Html::builder();
    html.head(|h| {
        h.title(|t| t.text("Rust IOT Management Console"));
        h.meta(|h| {
            h.http_equiv("Content-Type")
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
        let certs = s.user_certs.all_certs();
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

use clap::Parser;
/// Arguments for creating an iot instance
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The config path to override the default with
    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let dirs = directories::ProjectDirs::from("com", "UglyOldBob", "Iot").unwrap();
    let config_path = if let Some(p) = args.config {
        std::path::PathBuf::from(p)
    } else {
        dirs.config_dir().to_path_buf()
    };

    println!("Load config from {:?}", config_path);

    let mut router = webserver::WebRouter::new();
    router.register("/asdf", test_func);
    router.register("/groot", test_func2);
    router.register("/groot2", test_func3);
    router.register("", main_redirect);
    router.register("/", main_redirect);
    router.register("/main.rs", main_page);
    ca::ca_register(&mut router);

    let mut settings_con = Vec::new();
    let mut f = tokio::fs::File::open(config_path.join("config.toml"))
        .await
        .unwrap();
    f.read_to_end(&mut settings_con).await.unwrap();

    let settings: MainConfiguration;

    let mut password: Option<String> = None;

    #[cfg(all(target_os = "linux", feature="systemd"))]
    {
        password = Some("moron".to_string());
        println!("Linux specific password get");
    }

    if password.is_none() {
        let mut password2: prompt::Password;
        loop {
            print!("Please enter a password:");
            std::io::stdout().flush().unwrap();
            password2 = prompt::Password::prompt(None).unwrap();
            if !password2.is_empty() {
                password = Some(password2.to_string());
                break;
            }
        }
    }

    let password = password.expect("No password provided");

    #[cfg(feature = "tpm2")]
    {
        let mut tpm_data = Vec::new();
        let mut f = tokio::fs::File::open(config_path.join("password.bin"))
            .await
            .unwrap();
        f.read_to_end(&mut tpm_data).await.unwrap();

        let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path());

        let tpm_data = tpm2::TpmBlob::rebuild(&tpm_data);

        let epdata = tpm2.decrypt(tpm_data).unwrap();
        let protected_password = tpm2::Password::rebuild(&epdata);

        let password_combined = [password.as_bytes(), protected_password.password()].concat();

        let pconfig = tpm2::decrypt(settings_con, &password_combined);

        let settings2 = toml::from_str(std::str::from_utf8(&pconfig).unwrap());
        if settings2.is_err() {
            panic!("Failed to parse configuration file");
        }
        settings = settings2.unwrap();
    }
    #[cfg(not(feature = "tpm2"))]
    {
        let password_combined = password.as_bytes();
        let pconfig = tpm2::decrypt(settings_con, &password_combined);
        let settings2 = toml::from_str(std::str::from_utf8(&pconfig).unwrap());
        if settings2.is_err() {
            panic!("Failed to parse configuration file");
        }
        settings = settings2.unwrap();
    }

    let settings = Arc::new(settings);

    let mysql_pw = &settings.database.password;
    let mysql_user = &settings.database.username;
    let mysql_dbname = &settings.database.name;
    let mysql_url = &settings.database.url;
    let mysql_conn_s = format!(
        "mysql://{}:{}@{}/{}",
        mysql_user, mysql_pw, mysql_url, mysql_dbname,
    );
    let mysql_opt = mysql::Opts::from_url(mysql_conn_s.as_str()).unwrap();
    let mysql_temp = mysql::Pool::new(mysql_opt);
    match mysql_temp {
        Ok(ref _bla) => println!("I have a bla"),
        Err(ref e) => println!("Error connecting to mysql: {}", e),
    }
    let mut mysql_pool = mysql_temp.ok();

    let mut mysql_conn_s = mysql_pool.as_mut().map(|s| s.get_conn().unwrap());

    let ca = ca::Ca::load(&settings).await;

    let ca = Arc::new(futures::lock::Mutex::new(ca));

    let mut hc = HttpContext {
        dirmap: router,
        root: settings.general.static_content.to_owned(),
        proxy: None,
        cookiename: "rustcookie".to_string(),
        pool: mysql_pool,
        settings: settings.clone(),
        ca,
    };

    if let Some(mysql_conn_s) = &mut mysql_conn_s {
        user::check_user_table(mysql_conn_s);
        user::check_login_table(mysql_conn_s);
        user::set_admin_login(mysql_conn_s, &settings);
    }

    hc.proxy = settings.general.proxy.to_owned();
    let proxy = if let Some(p) = &hc.proxy {
        p.to_owned()
    } else {
        String::new()
    };
    hc.cookiename = format!("/{}{}", proxy, settings.general.cookie);

    if let Some(proxy) = &hc.proxy {
        println!("Using {} as the proxy path", proxy);
    } else {
        println!("Not using a proxy path");
    }

    //    println!("{} is {}", "bob", settings.getint("general","bob").unwrap_or(None).unwrap_or(32));

    let http_enable = settings.http.enabled;
    let https_enable = settings.https.enabled;

    let hc = Arc::new(hc);

    let mut tasks: tokio::task::JoinSet<Result<(), webserver::ServiceError>> =
        tokio::task::JoinSet::new();

    let client_certs = webserver::tls::load_user_cert_data(&settings);

    if http_enable {
        let http_port = settings.get_http_port();
        println!("Listening http on port {}", http_port);

        let hc_http = hc.clone();
        if let Err(e) = http_webserver(hc_http, http_port, &mut tasks).await {
            println!("https web server errored {}", e);
        }
    }

    if https_enable {
        let https_port = settings.get_https_port();
        println!("Listening https on port {}", https_port);

        let tls_pass = settings.https.certpass.to_owned();
        let tls_cert = settings.https.certificate.to_owned();
        let tls = TlsConfig::new(tls_cert, tls_pass);

        let hc_https = hc.clone();

        if let Err(e) = https_webserver(
            hc_https,
            https_port,
            tls,
            &mut tasks,
            client_certs,
            settings.https.require_certificate,
        )
        .await
        {
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
