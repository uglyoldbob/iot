package com.uglyoldbob.RustIotNfc;

import android.app.NativeActivity;
import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.util.Log;

public class ModdedActivity extends NativeActivity {
    static {
        System.loadLibrary("rust_iot_nfc");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.e("ModdedActivity", "JAVA onCreate fired");
    }

    @Override
    protected void onResume() {
        super.onResume();
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            adapter.enableForegroundDispatch(
                this,
                PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE),
                null,
                null
            );
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            adapter.disableForegroundDispatch(this);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Log.e("ModdedActivity", "JAVA onNewIntent fired: " + intent);
        notifyOnNewIntent(intent);
    }

    private native void notifyOnNewIntent(Intent intent);
}