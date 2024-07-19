openssl genrsa -out example-private.pem 4096
openssl rsa -in example-private.pem -outform PEM -pubout -out example-public.pem
openssl rsa -pubin \
            -in example-public.pem \
            -inform PEM \
            -RSAPublicKey_out \
            -outform DER \
            -out example-public_key.der