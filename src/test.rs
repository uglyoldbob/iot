#[derive(Debug, prompt::Prompting)]
struct TestMe {
    bob: u8,
    jim: Option<u8>,
    asdf: TestMe2,
}

#[derive(Debug, prompt::Prompting)]
struct TestMe2 {
    size: u8,
    number: Option<u8>,
}

#[tokio::main]
async fn main() {
    println!("Running test program");

    println!("Please enter a value");
    let s = <TestMe as prompt::Prompting>::prompt(None);
    if let Ok(s) = s {
        println!("You entered {:?}", s);
    }
}
