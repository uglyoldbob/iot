package com.uglyoldbob.rust_iot_nfc;

import android.app.NativeActivity;
import android.content.Intent;
import android.os.Bundle;

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

        notifyOnNewIntent();
    }

    private native void notifyOnNewIntent();
}