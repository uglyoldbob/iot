fn main() { cgi::handle(|request: cgi::Request| -> cgi::Response {
    cgi::html_response(200, "<html><body><h1>I am groot!</h1></body></html>")
})}