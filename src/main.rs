use hyper::Body;
use std::collections::HashMap;

use std::fs;

use futures::FutureExt;

mod user;
mod webserver;

use crate::webserver::*;
use crate::webserver::tls::*;

fn test_func(s: &mut WebPageContext, _bld: &mut hyper::http::response::Parts) -> Body {
    s.logincookie = None;
    Body::from("this is a test".to_string())
}

fn main_page(s: &mut WebPageContext, _bld: &mut hyper::http::response::Parts) -> Body {
    let mut c : String = "".to_string();

    c.push_str(r#"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
 <meta hett-equiv="content-type" content="text/html;charset=utf-8"/>
 <title>Rust IOT Management Console</title>
"#);
    c.push_str(&format!("  <link href=\"{}/css/main.css\" rel=\"stylesheet\" type=\"text/css\" media=\"all\"/>", &s.proxy));
    c.push_str(r#"
</head>

"#);

    let mut logged_in = false;
    let mut username: String = "".to_string();
    if let Some(pc) = &s.pc {
        c.push_str("you have a certificate<br>");
        for n in pc.subject_name().entries() {
        }
    }
    if let Some(cookie) = &s.logincookie {
        //lookup login cookie
        let value = cookie.parse::<u64>();
        if let Ok(value) = value {
            let user = user::check_login_entry(&mut s.pool, value);
            if let Some(user) = user {
                logged_in = true;
                username = user;
            }
        }
    }
    if s.post.contains_key("username") && s.post.contains_key("password") {
        let uname = &s.post["username"];
        let pass = &s.post["password"];
    	let useri = user::get_user_info(&mut s.pool, uname.to_string());
        let login_pass = user::try_user_login2(
            &useri, pass.to_string());
        if login_pass {
            let useru = useri.unwrap();
            let value = user::new_user_login(&mut s.pool, useru);
            let print = format!("Login pass {}", value);
            c.push_str(&print);
            let cookieval = format!("{}", value);
            s.logincookie = Some(cookieval);
        }
        else {
            //login failed because account does not exist
            c.push_str("Login fail");
        }
    }
    /*user::try_user_hash(&mut s.pool, 
        s.session.user.to_owned(), 
        s.session.passhash.to_owned());*/
    if !logged_in {
    c.push_str("
Welcome to the login page!
<form>
    Username: 
    <input type=\"text\" id=\"username\" name=\"username\"><br>
    Password: 
    <input type=\"password\" id=\"password\" name=\"password\"><br>
    <input type=\"submit\" value=\"Login\" formmethod=\"post\"><br>
    </form>
</HTML>");
    }
    else
    {
        c.push_str("
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
</HTML>")
    }
//    s.ourcookie = None;
    Body::from(c)
}

fn main_redirect(s: &mut WebPageContext, bld: &mut hyper::http::response::Parts) -> Body {
    bld.status = hyper::http::StatusCode::from_u16(302).unwrap();
    let url = format!("{}/main.rs", s.proxy.to_string());
    bld.headers.insert("Location",hyper::http::header::HeaderValue::from_str(&url).unwrap());
    Body::from("redirect goes here")
}

#[tokio::main]
async fn main() {
    let mut map : HashMap<String, Callback> = HashMap::new();
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

    let mysql_pw = settings.get("database","password").unwrap_or("iinvalid".to_string());
    let mysql_user = settings.get("database", "username").unwrap_or("invalid".to_string());
    let mysql_dbname = settings.get("database", "name").unwrap_or("none".to_string());
    let mysql_url = settings.get("database", "url").unwrap_or("invalid".to_string());
    let mysql_conn_s = format!("mysql://{}:{}@{}/{}", mysql_user, mysql_pw, mysql_url, mysql_dbname);
    let mysql_opt = mysql::Opts::from_url(mysql_conn_s.as_str()).unwrap();
    let mysql_temp = mysql::Pool::new(mysql_opt);
    match mysql_temp {
        Ok(ref _bla) => println!("I have a bla"),
        Err(ref e) => println!("Error connecting to mysql: {}", e),
    }
    let mysql_pool = mysql_temp.unwrap();
    let mut mysql_conn_s = mysql_pool.get_conn().unwrap();

    let mut hc = HttpContext {
        dirmap: map.clone(),
        root: ".".to_string(),
        proxy: "".to_string(),
        cookiename: "rustcookie".to_string(),
        pool: mysql_pool,
    };

    user::check_user_table(&mut mysql_conn_s);
    user::check_login_table(&mut mysql_conn_s);
    user::set_admin_login(&mut mysql_conn_s, &settings);

    hc.proxy = settings.get("general","proxy").unwrap_or("".to_string());
    hc.cookiename = format!("{}/{}", &hc.proxy,settings.get("general","cookie").unwrap_or("rustcookie".to_string()));

    if hc.proxy.clone() != "".to_string() {
        println!("Using {} as the proxy path", &hc.proxy);
    } else {
        println!("Not using a proxy path");
    }


//    println!("{} is {}", "bob", settings.getint("general","bob").unwrap_or(None).unwrap_or(32));

    let http_enable = match settings.get("http","enabled").unwrap().as_str() {
        "yes" => true,
        _ => false,
    };

    let https_enable = match settings.get("https","enabled").unwrap().as_str() {
        "yes" => true,
        _ => false,
    };


    if http_enable {
        let http_port = settings.getint("http", "port").unwrap_or(None).unwrap_or(3001) as u16;
        println!("Listening http on port {}", http_port);

        let hc_http = hc.clone();
        tokio::spawn(async move {
        	http_webserver(hc_http, http_port).await;
	    });

    }

    if https_enable {
        let https_port = settings.getint("https", "port").unwrap_or(None).unwrap_or(3001) as u16;
        println!("Listening https on port {}", https_port);

        let tls_cert = settings.get("https","certificate").unwrap();
        let tls_pass = settings.get("https","certpass").unwrap();
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
