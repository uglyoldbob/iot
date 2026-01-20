package com.uglyoldbob.RustIotNfc;

import android.app.NativeActivity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class ModdedActivity extends NativeActivity {
    static {
        System.loadLibrary("rust_iot_nfc");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Log.e("ModdedActivity", "JAVA onNewIntent fired: " + intent);
        notifyOnNewIntent(intent);
    }

    private native void notifyOnNewIntent(Intent intent);
}