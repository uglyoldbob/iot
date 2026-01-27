package com.uglyoldbob.RustIotNfc;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class RegisterActivity extends Activity {

    static {
        System.loadLibrary("rust_iot_nfc"); // load Rust library for registration
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Uri data = getIntent().getData();
        if (data != null) {
            Log.d("RegisterActivity", "Deep link URL: " + data.toString());
            // Call Rust customization / registration code
            nativeDoCustomization(data.toString());
        }

        // Launch main Rust UI activity
        Intent intent = new Intent(this, ModdedActivity.class);
        startActivity(intent);
        finish(); // close RegisterActivity
    }

    private static native void nativeDoCustomization(String url);
}
