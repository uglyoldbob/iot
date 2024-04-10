use der::DecodePem;
use der::Encode;
use ring::signature::UnparsedPublicKey;
use ring::signature::RSA_PKCS1_2048_8192_SHA256;
use tokio::io::AsyncReadExt;
use yasna::parse_der;

pub async fn verify_request2<'a>(
    csr: &'a x509_cert::request::CertReq,
) -> Result<&'a x509_cert::request::CertReq, ()> {
    let info = csr.info.to_der().unwrap();
    let pubkey = &csr.info.public_key;
    let signature = &csr.signature;

    let p = &pubkey.subject_public_key;
    let pder = p.to_der().unwrap();

    let pkey = parse_der(&pder, |r| {
        let (data, _size) = r.read_bitvec_bytes()?;
        Ok(data)
    })
    .unwrap();

    let csr_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pkey);
    println!("Cert is {:?}", csr_key);
    println!("info {:02X?}", info);
    csr_key
        .verify(&info, signature.as_bytes().unwrap())
        .map_err(|_| {
            println!("Error verifying the signature on the csr 1");
        })?;
    //TODO perform more validation of the csr
    Ok(csr)
}

#[tokio::main]
async fn main() {
    println!("Running test2 program");

    let mut settings_con = Vec::new();
    let mut f = tokio::fs::File::open("./cert.pub").await.unwrap();
    f.read_to_end(&mut settings_con).await.unwrap();
    let pem = std::str::from_utf8(&settings_con).unwrap();
    println!("{}", pem);
    let csr = x509_cert::request::CertReq::from_pem(pem).unwrap();
    let a = verify_request2(&csr).await;
    println!("Result is {:?}", a);
}
