use prompt::Prompting;

mod tpm2;

#[allow(dead_code)]
#[derive(Debug, prompt::Prompting)]
struct TestMe {
    bob: u8,
    jim: Option<u8>,
    asdf: TestMe2,
    path: std::path::PathBuf,
}

#[allow(dead_code)]
#[derive(Debug, prompt::Prompting)]
struct TestMe2 {
    size: u8,
    number: Option<u8>,
}

#[tokio::main]
async fn main() {
    println!("Running test program");

    #[cfg(feature = "tpm2")]
    {
        let mut data: Vec<u8> = vec![0; 1024];
        for e in data.iter_mut() {
            *e = rand::random();
        }

        let mut password: String;
        loop {
            println!("Please enter a password:");
            password = String::prompt(None).unwrap();
            if !password.is_empty() {
                break;
            }
        }

        let config: Vec<u8>;
        let tpm_data: tpm2::TpmBlob;
        {
            let mut tpm2 = tpm2::Tpm2::new("/dev/tpmrm0");

            let password2: [u8; 32] = rand::random();

            let protected_password =
                tpm2::Password::build(&password2, std::num::NonZeroU32::new(2048).unwrap());

            let password_combined = [password.as_bytes(), protected_password.password()].concat();

            config = tpm2::encrypt(&data, &password_combined);

            let epdata = protected_password.data();
            tpm_data = tpm2.encrypt(&epdata).unwrap();
        }
        {
            let mut tpm2 = tpm2::Tpm2::new("/dev/tpmrm0");
            let epdata = tpm2.decrypt(tpm_data).unwrap();
            let protected_password = tpm2::Password::rebuild(&epdata);

            let password_combined = [password.as_bytes(), protected_password.password()].concat();

            let pconfig = tpm2::decrypt(config, &password_combined);

            assert_eq!(pconfig, data);
            println!("TPM2 testing passed");
        }
    }

    println!("Please enter a value");
    let s = TestMe::prompt(None);
    if let Ok(s) = s {
        println!("You entered {:?}", s);
    }
}
