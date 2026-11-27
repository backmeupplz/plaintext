package com.borodutch.plaintext

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter

class App : Application() {
    lateinit var model: Model
        private set

    override fun onCreate() {
        super.onCreate()
        model = Model(this)
        // Lock when the screen turns off.
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) = model.lock()
        }, IntentFilter(Intent.ACTION_SCREEN_OFF))
    }
}

val Context.model: Model get() = (applicationContext as App).model
