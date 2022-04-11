package com.uglyoldbob.iotnode;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.X500NameBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public class MainActivity extends AppCompatActivity {
    private boolean have_server_name = false;
    private Context context;
    private static final String LOGTAG = "IotNode";

    String get_request(File f)
    {
        StringBuilder sb = new StringBuilder();
        try {
            if (f.exists()) {
                Log.e(LOGTAG, "opening existing request");
                FileInputStream fis = new FileInputStream(f);
                InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
                BufferedReader br = new BufferedReader(isr);
                String line = br.readLine();
                while (line != null) {
                    sb.append(line).append('\n');
                    line = br.readLine();
                }
            }
        } catch (FileNotFoundException e) {
            Log.e(LOGTAG, "file not found?");
        } catch (IOException e) {
            Log.e(LOGTAG, "error reading request file");
        }
        return sb.toString();
    }

    KeyPair make_keypair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        Log.d(LOGTAG, "generating certificate request");
        kpg.initialize(384);
        KeyPair key = kpg.generateKeyPair();
        return key;
    }

    KeyPair load_keypair(KeyStore ks) {
        KeyPair key = null;

        if (ks != null)
        {
            try {
                Key k = ks.getKey("selfsignkey", "hf6701238gh85p931g".toCharArray());
                if (k instanceof PrivateKey) {
                    Certificate cert = ks.getCertificate("selfsign");
                    PublicKey pk = cert.getPublicKey();
                    Log.e(LOGTAG, "loading key from keystore");
                    key = new KeyPair(pk, (PrivateKey)k);
                }
            }
            catch (Exception e) {
                Log.e(LOGTAG, "keystore Exception " + e.toString());
            }
        }
        //TODO attempt to load certificate

        return key;
    }

    Certificate load_certificate(KeyStore ks)
    {
        Certificate c = null;
        try {
            c = (Certificate)ks.getCertificate("selfsign");
        }
        catch (Exception e) {
            Log.e(LOGTAG, "Exception loading self signed certificate " + e.toString());
        }

        return c;
    }

    Certificate self_sign_certificate(KeyPair kp)
            throws OperatorCreationException, CertificateException
    {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 100);
        Date endDate = calendar.getTime();

        ContentSigner cs = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(kp.getPrivate());

        X500NameBuilder namebuilder = new X500NameBuilder();
        X500Name name = namebuilder.build();
        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                name,
                new BigInteger("1"),
                startDate, endDate,
                name,
                kp.getPublic()
        );
        return new JcaX509CertificateConverter()
                .getCertificate(cb.build(cs));
    }

    void make_request(File f, KeyPair key) {
        try {

            PKCS10CertificationRequestBuilder certbuilder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Principal("OU=Test,C=Test"), key.getPublic());
            JcaContentSignerBuilder csbuilder = new JcaContentSignerBuilder("SHA256withECDSA");
            ContentSigner cs = csbuilder.build(key.getPrivate());
            PKCS10CertificationRequest csr = certbuilder.build(cs);
            Log.e(LOGTAG, "Attempting to save the request");
            Log.e(LOGTAG, "Saving to " + f.getAbsolutePath());
            f.mkdir();
            f.delete();
            JcaPEMWriter w = new JcaPEMWriter(new FileWriter(f.getAbsolutePath()));
            w.writeObject(csr);
            w.close();
            Log.e(LOGTAG, "Done creating csr");
        }
        catch (OperatorCreationException e) {
            Log.e(LOGTAG, "Failed to create signer");
        }
        catch (IOException e) {
            Log.e(LOGTAG, "failed to write request to storage " + e.toString());
        }
    }

    KeyStore check_keystore() {
        File f = new File(context.getFilesDir(), "keystore.bks");
        char[] p = "@gjUcpWZ!h@g9JX?".toCharArray();
        String filename = f.toString();
        KeyStore k = null;
        if (!f.exists()) {
            Log.e(LOGTAG, "making keystore");
            try {
                k = KeyStore.getInstance("UBER", "SC");
                k.load(null, null);
                k.store(new FileOutputStream(filename), p);
            }
            catch (Exception e) {
                Log.e(LOGTAG, "keystore exception 1 " + e.toString());
            }
        }
        else
        {
            Log.e(LOGTAG, "loading keystore");
            try {
                k = KeyStore.getInstance("UBER", "SC");
                k.load(new FileInputStream(filename), p);
            }
            catch (Exception e) {
                Log.e(LOGTAG, "keystore exception 2 " + e.toString());
            }
        }
        return k;
    }

    void save_keystore(KeyStore ks)
    {
        Log.e(LOGTAG, "saving keystore");
        File f = new File(context.getFilesDir(), "keystore.bks");
        char[] p = "@gjUcpWZ!h@g9JX?".toCharArray();
        String filename = f.toString();
        try {
            ks.store(new FileOutputStream(filename), p);
        }
        catch (Exception e) {
            Log.e(LOGTAG, "exception saving keystore " + e.toString());
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
        context = getApplicationContext();

        SharedPreferences sp = context.getSharedPreferences("IotNode", MODE_PRIVATE);
        if (sp.contains("server")) {
            Log.e(LOGTAG, "I have the server name" + sp.getString("server", "none"));
        } else {
            Log.e(LOGTAG, "I do not have the server name");
        }

        KeyStore ks = check_keystore();
        KeyPair key = load_keypair(ks);
        if (key == null)
        {
            try {
                key = make_keypair();
            }
            catch (Exception e) {
                Log.e(LOGTAG, "Error making keypair " + e.toString());
            }
        }
        Certificate selfsign = null;

        selfsign = load_certificate(ks);
        File f = new File(context.getFilesDir() + "/cert/", "request.csr");
        if (selfsign == null) {
            try {
                Log.e(LOGTAG, "Making csr");
                selfsign = self_sign_certificate(key);
                ks.setCertificateEntry("selfsign", selfsign);
                Certificate[] certs = new Certificate[1];
                certs[0] = selfsign;
                ks.setKeyEntry("selfsignkey", key.getPrivate(),
                        "hf6701238gh85p931g".toCharArray(), certs);
                //load the request
                String path = context.getFilesDir() + "/cert/request.csr";
                f.mkdirs();
                f.delete();
                String con = new String();
                if (!f.exists()) {
                    make_request(f, key);
                }
            } catch (Exception e) {
                Log.e(LOGTAG, "Error making self signed certificate " + e.toString());
                e.printStackTrace();
            }
            save_keystore(ks);
        }

        String con = get_request(f);
        Log.e(LOGTAG, "The actual request is \n" + con);

        setContentView(R.layout.activity_main);
    }

    protected void onRestart() {
        super.onRestart();
    }

    protected void onStart() {
        super.onStart();
    }

    protected void onResume() {
        super.onResume();
    }

    protected void onPause() {
        super.onPause();
    }

    protected void onStop() {
        super.onStop();
    }

    protected void onDestroy() {
        super.onDestroy();
    }
}