#!/bin/sh
set -e

SOFTHSM2_CONF=./hsmtest/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=InitialToken --login --pin asdf --list-objects
SOFTHSM2_CONF=./hsmtest/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=InitialToken --login --pin asdf --label testing --read-object --type pubkey -o ecdsapub.key

hd ecdsapub.key
openssl ec -inform der -in ecdsapub.key -text -pubin

dd if=/dev/random of=./data.bin count=1023

openssl dgst -sha256 -binary data.bin > hash.bin

rm -f ./sig.bin
SOFTHSM2_CONF=./hsmtest/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=InitialToken --login --pin asdf --label testing --mechanism ECDSA --sign -o sig.bin -i hash.bin --signature-format openssl
SOFTHSM2_CONF=./hsmtest/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=InitialToken --login --pin asdf --label testing --mechanism ECDSA --sign -o sig2.bin -i hash.bin --signature-format openssl
hd ./sig.bin
hd ./sig2.bin
openssl pkeyutl -verify -in hash.bin -sigfile sig.bin -inkey ecdsapub.key -pubin
openssl dgst -sha256 -verify ecdsapub.key -signature sig.bin data.bin

openssl pkeyutl -verify -in hash.bin -sigfile sig2.bin -inkey ecdsapub.key -pubin
openssl dgst -sha256 -verify ecdsapub.key -signature sig2.bin data.bin

openssl dgst -sha256 -binary ./hsmtest/data.bin > hash2.bin
SOFTHSM2_CONF=./hsmtest/softhsm2.conf pkcs11-tool --module=/home/thomas/temp/SoftHSMv2/src/lib/libsofthsm2.so --token-label=InitialToken --login --pin asdf --label testing --mechanism ECDSA --sign -o sig3.bin -i hash2.bin --signature-format openssl
openssl dgst -sha256 -verify ecdsapub.key -signature ./sig3.bin ./hsmtest/data.bin

openssl dgst -sha256 -binary ./hsmtest/data.bin > hashcheck.bin
openssl pkeyutl -verify -in ./hsmtest/hash.bin -sigfile ./hsmtest/sig_test.bin -inkey ecdsapub.key -pubin
openssl dgst -sha256 -verify ecdsapub.key -signature ./hsmtest/sig_test.bin ./hsmtest/data.bin