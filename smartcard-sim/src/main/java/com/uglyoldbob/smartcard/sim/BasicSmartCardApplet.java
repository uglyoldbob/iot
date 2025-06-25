package com.uglyoldbob.smartcard.sim;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Basic Smart Card Applet for cryptographic operations.
 *
 * This applet provides fundamental cryptographic services including:
 * - RSA key pair generation
 * - Digital signature creation
 * - Public key export
 * - PIN verification
 *
 * Command structure:
 * - CLA: 0x80 (proprietary class)
 * - INS: instruction byte
 *   - 0x10: Generate key pair
 *   - 0x20: Sign data
 *   - 0x30: Get public key
 *   - 0x40: Verify PIN
 *   - 0x50: Change PIN
 */
public class BasicSmartCardApplet extends Applet {

    // Instruction codes
    private static final byte INS_GENERATE_KEYPAIR = (byte) 0x10;
    private static final byte INS_SIGN_DATA = (byte) 0x20;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x30;
    private static final byte INS_VERIFY_PIN = (byte) 0x40;
    private static final byte INS_CHANGE_PIN = (byte) 0x50;
    private static final byte INS_STORE_CERTIFICATE = (byte) 0x60;
    private static final byte INS_GET_CERTIFICATE = (byte) 0x70;
    private static final byte INS_DELETE_CERTIFICATE = (byte) 0x80;

    // Response codes
    private static final short SW_PIN_VERIFICATION_REQUIRED = 0x6982;
    private static final short SW_PIN_TRIES_REMAINING = 0x63C0;
    private static final short SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;
    private static final short SW_INCORRECT_P1P2 = 0x6A86;
    private static final short SW_WRONG_DATA = 0x6A80;
    private static final short SW_FUNC_NOT_SUPPORTED = 0x6A81;

    // PIN configuration
    private static final byte PIN_TRY_LIMIT = (byte) 0x03;
    private static final byte MIN_PIN_SIZE = (byte) 0x04;
    private static final byte MAX_PIN_SIZE = (byte) 0x08;

    // Default PIN: "1234"
    private static final byte[] DEFAULT_PIN = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};

    // Key sizes
    private static final short KEY_SIZE_1024 = 1024;
    private static final short KEY_SIZE_2048 = 2048;
    private static final short KEY_SIZE_4096 = 4096;

    // Instance variables
    private OwnerPIN pin;
    private KeyPair rsaKeyPair;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private Cipher rsaCipher;
    private boolean keyPairGenerated;

    // Temporary buffer for operations
    private byte[] tempBuffer;
    private static final short TEMP_BUFFER_SIZE = 512;

    // Certificate storage
    private byte[] storedCertificate;
    private short certificateLength;
    private static final short MAX_CERTIFICATE_SIZE = 2048;
    private boolean certificateStored;

    // For chunked upload
    private short certChunkOffset = 0;

    /**
     * Constructor - called during applet installation
     */
    protected BasicSmartCardApplet() {
        // Initialize PIN with default value
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);

        // Initialize cipher for RSA operations
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        // Initialize temporary buffer
        tempBuffer = new byte[TEMP_BUFFER_SIZE];

        // Initialize certificate storage
        storedCertificate = new byte[MAX_CERTIFICATE_SIZE];
        certificateLength = 0;
        certificateStored = false;

        keyPairGenerated = false;
    }

    /**
     * Install method - called by JCRE during applet installation
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new BasicSmartCardApplet().register();
    }

    /**
     * Process incoming APDU commands
     */
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte ins = (byte) (buf[ISO7816.OFFSET_INS] & 0xFF);
        System.out.println("[BasicSmartCardApplet] process called, INS=" + String.format("%02X", ins));
        if (selectingApplet()) {
            System.out.println("[BasicSmartCardApplet] selectingApplet() == true, returning");
            return;
        }

        byte cla = buf[ISO7816.OFFSET_CLA];

        // Check CLA byte
        if (cla != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (ins) {
            case INS_VERIFY_PIN:
                verifyPIN(apdu);
                break;

            case INS_CHANGE_PIN:
                changePIN(apdu);
                break;

            case INS_GENERATE_KEYPAIR:
                generateKeyPair(apdu);
                break;

            case INS_SIGN_DATA:
                signData(apdu);
                break;

            case INS_GET_PUBLIC_KEY:
                getPublicKey(apdu);
                break;

            case INS_STORE_CERTIFICATE:
                storeCertificate(apdu);
                break;

            case INS_GET_CERTIFICATE:
                getCertificate(apdu);
                break;

            case INS_DELETE_CERTIFICATE:
                deleteCertificate(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Verify PIN command
     */
    private void verifyPIN(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if ((numBytes != byteRead) || (numBytes < MIN_PIN_SIZE) || (numBytes > MAX_PIN_SIZE)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        if (pin.check(buf, ISO7816.OFFSET_CDATA, numBytes) == false) {
            ISOException.throwIt((short) (SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }
    }

    /**
     * Change PIN command
     */
    private void changePIN(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if ((numBytes != byteRead) || (numBytes < MIN_PIN_SIZE) || (numBytes > MAX_PIN_SIZE)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        pin.update(buf, ISO7816.OFFSET_CDATA, numBytes);
    }

    /**
     * Generate RSA key pair
     */
    private void generateKeyPair(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buf = apdu.getBuffer();
        byte numBytes = buf[ISO7816.OFFSET_LC];

        short keySize = KEY_SIZE_2048; // default

        if (numBytes == 2) {
            apdu.setIncomingAndReceive();
            keySize = Util.getShort(buf, ISO7816.OFFSET_CDATA);

            // Validate key size
            if (keySize != KEY_SIZE_1024 && keySize != KEY_SIZE_2048 && keySize != KEY_SIZE_4096) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
        }

        try {
            // Generate new key pair
            rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, keySize);
            rsaKeyPair.genKeyPair();

            // Get references to the keys
            privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
            publicKey = (RSAPublicKey) rsaKeyPair.getPublic();

            keyPairGenerated = true;

        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    /**
     * Store certificate command (chunked upload)
     * P1 = 0x00: more chunks, P1 = 0x01: last chunk
     */
    private void storeCertificate(APDU apdu) {
        System.out.println("[BasicSmartCardApplet] storeCertificate called");
        if (!pin.isValidated()) {
            System.out.println("[BasicSmartCardApplet] storeCertificate: PIN not validated!");
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        short dataLength = apdu.setIncomingAndReceive();

        // Log the received data length for debugging
        System.out.println("[BasicSmartCardApplet] storeCertificate received dataLength=" + dataLength + " at offset=" + certChunkOffset);

        if (dataLength == 0 || certChunkOffset + dataLength > MAX_CERTIFICATE_SIZE) {
            System.out.println("[BasicSmartCardApplet] storeCertificate: dataLength invalid, throwing SW_WRONG_DATA");
            ISOException.throwIt(SW_WRONG_DATA);
        }

        // Copy chunk to certificate buffer
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, storedCertificate, certChunkOffset, dataLength);
        certChunkOffset += dataLength;

        if (p1 == (byte)0x01) { // last chunk
            certificateStored = true;
            certificateLength = certChunkOffset;
            certChunkOffset = 0;
            System.out.println("[BasicSmartCardApplet] storeCertificate: last chunk received, certificate stored, length=" + certificateLength);
        }
    }

    /**
     * Get certificate command
     */
    private void getCertificate(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        if (!certificateStored || certificateLength == 0) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        byte[] buf = apdu.getBuffer();
        // Use P1/P2 as offset (big endian)
        int offset = ((buf[ISO7816.OFFSET_P1] & 0xFF) << 8) | (buf[ISO7816.OFFSET_P2] & 0xFF);
        short le = apdu.setOutgoing();

        if (le == 0) {
            le = (short) 256; // Default expected length
        }

        // Clamp offset and length
        if (offset >= certificateLength) {
            apdu.setOutgoingLength((short)0);
            return;
        }
        short remaining = (short)(certificateLength - offset);
        short lengthToSend = (remaining < le) ? remaining : le;

        apdu.setOutgoingLength(lengthToSend);
        apdu.sendBytesLong(storedCertificate, (short) offset, lengthToSend);
    }

    /**
     * Delete certificate command
     */
    private void deleteCertificate(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        // Clear certificate data
        Util.arrayFillNonAtomic(storedCertificate, (short) 0, MAX_CERTIFICATE_SIZE, (byte) 0x00);
        certificateLength = 0;
        certificateStored = false;
    }

    /**
     * Sign data with private key
     */
    private void signData(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        if (!keyPairGenerated) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }

        byte[] buf = apdu.getBuffer();
        short numBytes = apdu.setIncomingAndReceive();

        if (numBytes == 0) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        try {
            // Initialize cipher for signing
            rsaCipher.init(privateKey, Cipher.MODE_ENCRYPT);

            // Sign the data
            short sigLen = rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, numBytes,
                                           buf, (short) 0);

            // Send response
            apdu.setOutgoingAndSend((short) 0, sigLen);

        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    /**
     * Get public key
     */
    private void getPublicKey(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        if (!keyPairGenerated) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }

        byte[] buf = apdu.getBuffer();
        short offset = 0;

        try {
            // Get modulus
            short modulusLength = publicKey.getModulus(tempBuffer, (short) 0);

            // Get exponent
            short exponentLength = publicKey.getExponent(tempBuffer, modulusLength);

            // Format response: [modulus_length][modulus][exponent_length][exponent]
            Util.setShort(buf, offset, modulusLength);
            offset += 2;

            Util.arrayCopyNonAtomic(tempBuffer, (short) 0, buf, offset, modulusLength);
            offset += modulusLength;

            Util.setShort(buf, offset, exponentLength);
            offset += 2;

            Util.arrayCopyNonAtomic(tempBuffer, modulusLength, buf, offset, exponentLength);
            offset += exponentLength;

            // Send response
            apdu.setOutgoingAndSend((short) 0, offset);

        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    /**
     * Deselect method - called when applet is deselected
     */
    public void deselect() {
        // Reset PIN validation state for security
        pin.reset();
    }
}
