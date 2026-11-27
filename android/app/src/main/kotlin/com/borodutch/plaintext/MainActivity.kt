package com.borodutch.plaintext

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, screen recordings or recents thumbnails of any screen (dialogs and menus inherit it).
        // Debug builds leave it off so the screenshot script can capture screens.
        if (!BuildConfig.DEBUG) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        setContent { PlaintextTheme { Root() } }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        model.touch()
    }

    override fun onStart() {
        super.onStart()
        model.foregrounded()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) model.backgrounded()
    }
}
