#[path = "../src/tpm2.rs"]
mod tpm2;

#[path = "../src/utility.rs"]
mod utility;

#[allow(dead_code)]
#[derive(Debug, userprompt::Prompting)]
enum TestEnum {
    Option1,
    Option2,
    Option3(i8, i16),
    Option4 { a: u8, b: u16, c: String },
}

#[allow(dead_code)]
#[derive(Debug, userprompt::Prompting)]
struct TestMe {
    e: TestEnum,
    bob: u8,
    jim: Option<u8>,
    asdf: TestMe2,
    path: std::path::PathBuf,
}

#[allow(dead_code)]
#[derive(Debug, userprompt::Prompting)]
struct TestMe2 {
    size: u8,
    number: Option<u8>,
}

#[tokio::test]
async fn test_tpm2() {
    println!("Running test program");

    #[cfg(feature = "tpm2")]
    {
        let mut data: Vec<u8> = vec![0; 1024];
        for e in data.iter_mut() {
            *e = rand::random();
        }

        let mut password = utility::generate_password(32);

        let config: Vec<u8>;
        let tpm_data: tpm2::TpmBlob;
        {
            let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path()).expect("TPM2 hardware not found");

            let password2: [u8; 32] = rand::random();

            let protected_password =
                tpm2::Password::build(&password2, std::num::NonZeroU32::new(2048).unwrap());

            let password_combined = [password.as_bytes(), protected_password.password()].concat();

            config = tpm2::encrypt(&data, &password_combined);

            let epdata = protected_password.data();
            tpm_data = tpm2.encrypt(&epdata).unwrap();
        }
        {
            let mut tpm2 = tpm2::Tpm2::new(tpm2::tpm2_path()).expect("TPM2 hardware not found");
            let epdata = tpm2.decrypt(tpm_data).unwrap();
            let protected_password = tpm2::Password::rebuild(&epdata);

            let password_combined = [password.as_bytes(), protected_password.password()].concat();

            let pconfig = tpm2::decrypt(config, &password_combined);

            assert_eq!(pconfig, data);
            println!("TPM2 testing passed");
        }
    }
}
