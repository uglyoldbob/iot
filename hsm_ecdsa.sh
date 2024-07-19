#!/bin/sh
set -e

openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
openssl ec -in private.ec.key -pubout -out public.pem
openssl ec -inform pem -in public.pem -text -pubin

rm -f ecdsapub.key
rm -rf /home/thomas/iot/testing/tokens2
mkdir /home/thomas/iot/testing/tokens2
SOFTHSM2_CONF=/home/thomas/temp/SoftHSMv2/softhsm2.conf softhsm2-util --init-token --label ecdsa --so-pin hsm-owner --pin pac-afu-signer --free
SOFTHSM2_CONF=/home/thomas/temp/SoftHSMv2/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=ecdsa --login --pin pac-afu-signer --id 0 --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:prime256v1 --usage-sign --label root_key 
SOFTHSM2_CONF=/home/thomas/temp/SoftHSMv2/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=ecdsa --login --pin pac-afu-signer --list-objects
SOFTHSM2_CONF=/home/thomas/temp/SoftHSMv2/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=ecdsa --login --pin pac-afu-signer --id 0 --label root_key --read-object --type pubkey -o ecdsapub.key

hd ecdsapub.key
openssl ec -inform der -in ecdsapub.key -text -pubin

dd if=/dev/random of=./data.bin count=1023

openssl dgst -sha256 -binary data.bin > hash.bin

rm -f ./sig.bin
SOFTHSM2_CONF=/home/thomas/temp/SoftHSMv2/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=ecdsa --login --pin pac-afu-signer --id 0 --label root_key --mechanism ECDSA --sign -o sig.bin -i hash.bin --signature-format openssl
SOFTHSM2_CONF=/home/thomas/temp/SoftHSMv2/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=ecdsa --login --pin pac-afu-signer --id 0 --label root_key --mechanism ECDSA --sign -o sig2.bin -i hash.bin --signature-format openssl
hd ./sig.bin
hd ./sig2.bin
openssl pkeyutl -verify -in hash.bin -sigfile sig.bin -inkey ecdsapub.key -pubin
openssl dgst -sha256 -verify ecdsapub.key -signature sig.bin data.bin

openssl pkeyutl -verify -in hash.bin -sigfile sig2.bin -inkey ecdsapub.key -pubin
openssl dgst -sha256 -verify ecdsapub.key -signature sig2.bin data.bin