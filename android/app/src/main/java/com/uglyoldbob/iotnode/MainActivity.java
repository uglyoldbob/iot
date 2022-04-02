package com.uglyoldbob.iotnode;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;

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
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;

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

    void make_request(File f) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            Log.d(LOGTAG, "generating certificate request");
            kpg.initialize(384);
            KeyPair key = kpg.generateKeyPair();

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
        catch (NoSuchAlgorithmException e) {
            Log.e(LOGTAG, "algorithm does not exist");
        }
        catch (OperatorCreationException e) {
            Log.e(LOGTAG, "Failed to create signer");
        }
        catch (IOException e) {
            Log.e(LOGTAG, "failed to write request to storage " + e.toString());
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

        //TODO attempt to load certificate

        //load the request
        String path = context.getFilesDir() + "/cert/request.csr";
        File f = new File(context.getFilesDir() + "/cert/", "request.csr");
        f.delete(); //TODO don't delete the file later, this is only to force a key generation during testing
        String con = new String();
        if (!f.exists()) {
            make_request(f);
        }
        con = get_request(f);
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