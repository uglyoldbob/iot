package com.uglyoldbob.RustIotNfc;

import android.app.NativeActivity;
import android.content.Intent;
import android.util.Log;

public class RegisterActivity extends NativeActivity {
    static {
        System.loadLibrary("rust_iot_nfc");
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        Log.e("RegisterActivity", "JAVA onNewIntent fired");
    }
}