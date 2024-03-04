//For the html crate
#![recursion_limit = "512"]
use std::collections::HashMap;

use std::fs;
use std::sync::Arc;

use futures::FutureExt;

mod user;
mod webserver;

use crate::webserver::tls::*;
use crate::webserver::*;

fn test_func2(
    s: &mut WebPageContext,
    _bld: &mut hyper::http::response::Parts,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
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
    hyper::http::Response::from_parts(response, body)
}

fn test_func(
    s: &mut WebPageContext,
    _bld: &mut hyper::http::response::Parts,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    let mut html = html::root::Html::builder();
    html.head(|h| h).body(|b| {
        if s.get.len() > 0 {
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
    hyper::http::Response::from_parts(response, body)
}

fn main_page(
    s: &mut WebPageContext,
    _bld: &mut hyper::http::response::Parts,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    let mut c: String = "".to_string();

    let mut logged_in = false;
    let mut username: String = "".to_string();
    if let Some(pc) = &s.pc {
        c.push_str("you have a certificate<br>");
        for n in pc.subject_name().entries() {}
    }
    if let Some(cookie) = &s.logincookie {
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
            let value = s
                .pool
                .as_mut()
                .and_then(|f| Some(user::new_user_login(f, useru)));
            let print = format!("Login pass {:?}", value);
            c.push_str(&print);
            let cookieval = format!("{:?}", value);
            s.logincookie = Some(cookieval);
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
    .body(|b| b);
    let html = html.build();

    let response = hyper::Response::new("dummy");
    let (response, _dummybody) = response.into_parts();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(html.to_string()));
    hyper::http::Response::from_parts(response, body)
}

fn main_redirect(
    s: &mut WebPageContext,
    bld: &mut hyper::http::response::Parts,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    let response = hyper::Response::new("dummy");
    let (mut response, _dummybody) = response.into_parts();

    response.status = hyper::http::StatusCode::from_u16(302).unwrap();
    let url = format!("{}/main.rs", s.proxy.to_string());
    response.headers.insert(
        "Location",
        hyper::http::header::HeaderValue::from_str(&url).unwrap(),
    );

    let body = http_body_util::Full::new(hyper::body::Bytes::from("I am GRooT?"));
    hyper::http::Response::from_parts(response, body)
}

#[tokio::main]
async fn main() {
    let mut map: HashMap<String, Callback> = HashMap::new();
    map.insert("/asdf".to_string(), test_func);
    map.insert("".to_string(), main_redirect);
    map.insert("/".to_string(), main_redirect);
    map.insert("/main.rs".to_string(), main_page);

    let settings_file = fs::read_to_string("./settings.ini");
    let settings_con = match settings_file {
        Ok(con) => con,
        Err(_) => "".to_string(),
    };
    let mut settings = configparser::ini::Ini::new();
    let settings_result = settings.read(settings_con);
    if let Err(e) = settings_result {
        println!("Failed to read settings {}", e);
    }

    let mysql_pw = settings
        .get("database", "password")
        .unwrap_or("iinvalid".to_string());
    let mysql_user = settings
        .get("database", "username")
        .unwrap_or("invalid".to_string());
    let mysql_dbname = settings
        .get("database", "name")
        .unwrap_or("none".to_string());
    let mysql_url = settings
        .get("database", "url")
        .unwrap_or("invalid".to_string());
    let mysql_conn_s = format!(
        "mysql://{}:{}@{}/{}",
        mysql_user, mysql_pw, mysql_url, mysql_dbname
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
        dirmap: map.clone(),
        root: ".".to_string(),
        proxy: "".to_string(),
        cookiename: "rustcookie".to_string(),
        pool: mysql_pool,
    };

    if let Some(mysql_conn_s) = &mut mysql_conn_s {
        user::check_user_table(mysql_conn_s);
        user::check_login_table(mysql_conn_s);
        user::set_admin_login(mysql_conn_s, &settings);
    }

    hc.proxy = settings.get("general", "proxy").unwrap_or("".to_string());
    hc.cookiename = format!(
        "{}/{}",
        &hc.proxy,
        settings
            .get("general", "cookie")
            .unwrap_or("rustcookie".to_string())
    );

    if hc.proxy.clone() != "".to_string() {
        println!("Using {} as the proxy path", &hc.proxy);
    } else {
        println!("Not using a proxy path");
    }

    //    println!("{} is {}", "bob", settings.getint("general","bob").unwrap_or(None).unwrap_or(32));

    let http_enable = match settings.get("http", "enabled").unwrap().as_str() {
        "yes" => true,
        _ => false,
    };

    let https_enable = match settings.get("https", "enabled").unwrap().as_str() {
        "yes" => true,
        _ => false,
    };

    let hc = Arc::new(hc);

    if http_enable {
        let http_port = settings
            .getint("http", "port")
            .unwrap_or(None)
            .unwrap_or(3001) as u16;
        println!("Listening http on port {}", http_port);

        let hc_http = hc.clone();
        tokio::spawn(async move {
            if let Err(e) = http_webserver(hc_http, http_port).await {
                println!("https web server errored {}", e);
            }
        });
    }

    if https_enable {
        let https_port = settings
            .getint("https", "port")
            .unwrap_or(None)
            .unwrap_or(3001) as u16;
        println!("Listening https on port {}", https_port);

        let tls_cert = settings.get("https", "certificate").unwrap();
        let tls_pass = settings.get("https", "certpass").unwrap();
        let tls = TlsConfig::new(tls_cert, tls_pass);

        let hc_https = hc.clone();

        tokio::spawn(async move {
            if let Err(e) = https_webserver(hc_https, https_port, tls).await {
                println!("https web server errored {}", e);
            }
        });
    }

    loop {
        futures::select! {
            _ = tokio::signal::ctrl_c().fuse() => {
                break;
            }
        }
    }
    println!("Ending the server");
}
