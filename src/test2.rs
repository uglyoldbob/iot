use der::DecodePem;
use der::Encode;
use ring::signature::UnparsedPublicKey;
use ring::signature::RSA_PKCS1_2048_8192_SHA256;
use tokio::io::AsyncReadExt;
use yasna::parse_der;

pub async fn verify_request2(
    csr: &x509_cert::request::CertReq,
) -> Result<&x509_cert::request::CertReq, ()> {
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

    assert!(untrusted::Input::from(&pkey)
                .read_all(ring::error::Unspecified, |input| ring::io::der::nested(
                    input,
                    ring::io::der::Tag::Sequence,
                    ring::error::Unspecified,
                    |input| {
                        let _ = ring::io::der::positive_integer(input)?;
                        let _ = ring::io::der::positive_integer(input)?;
                        Ok(())
                    }
                ))
                .is_ok());

    println!("Public key is {:02X?}", pkey);

    let csr_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pkey);
    println!("Cert is {:?}", csr_key);
    println!("info {:02X?}", info);
    println!("Signature is {:02X?}", signature.as_bytes().unwrap());

    let info2 = [info.clone(), vec![0x80 as u8]].concat();

    let manual_sha256 = sha256::digest(&info);
    println!("Manual sha256 is {}", manual_sha256);

    use sha2::Digest;
    use sha2::digest::core_api::BlockSizeUser;
    let mut hash2 = sha2::Sha256::new();
    println!("STUFF 1 {}", sha2::Sha256::block_size());
    hash2.update(&info);
    let manual_sha2 = hash2.finalize();
    println!("Manual sha2 is {:02X?}", manual_sha2);

    let info2 = [&info, signature.as_bytes().unwrap()].concat();

    let e1 = csr_key
        .verify(&info, signature.as_bytes().unwrap())
        .map_err(|_| {
            println!("Error verifying the signature on the csr 1");
        });
    if e1.is_ok() {
        println!("SUCCESS VALIDATE SIGNATURE");
    }

    csr_key
        .verify(&info2, signature.as_bytes().unwrap())
        .map_err(|_| {
            println!("Error verifying the signature2 on the csr 1");
        })?;
    //TODO perform more validation of the csr
    Ok(csr)
}

#[tokio::main]
async fn main() {
    println!("Running test2 program");

    let mut settings_con = Vec::new();
    let mut f = tokio::fs::File::open("./server.csr").await.unwrap();
    f.read_to_end(&mut settings_con).await.unwrap();
    let pem = std::str::from_utf8(&settings_con).unwrap();
    println!("{}", pem);
    let csr = x509_cert::request::CertReq::from_pem(pem).unwrap();
    let a = verify_request2(&csr).await;
    println!("Result is {:?}", a);
}
