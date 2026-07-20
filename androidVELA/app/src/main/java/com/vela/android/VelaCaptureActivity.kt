package com.vela.android

import android.os.Bundle
import android.view.WindowManager
import com.journeyapps.barcodescanner.CaptureActivity

class VelaCaptureActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // This activity scans the most sensitive inputs (enrollment QR carrying
        // the transfer key, and TOTP seeds). Prevent the camera preview from
        // leaking via task-switcher snapshots or screen recording, matching the
        // FLAG_SECURE already applied by MainActivity.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
}
