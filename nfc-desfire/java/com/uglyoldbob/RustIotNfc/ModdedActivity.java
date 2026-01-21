package com.uglyoldbob.RustIotNfc;

import android.app.NativeActivity;
import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
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
            Log.e("ModdedActivity", "Enabling foreground dispatch");
            adapter.enableReaderMode(
                this,
                tag -> {
                    Log.e("ReaderMode", "Tag: " + tag);
                    runOnUiThread(() -> notifyOnTag(this, tag));
                },
                NfcAdapter.FLAG_READER_NFC_A
                    | NfcAdapter.FLAG_READER_NFC_B
                    | NfcAdapter.FLAG_READER_NFC_F
                    | NfcAdapter.FLAG_READER_NFC_V
                    | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                null
            );
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            adapter.disableReaderMode(this);
        }
    }

    private native void notifyOnTag(ModdedActivity ma, Tag tag);
}