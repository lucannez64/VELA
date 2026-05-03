package com.vela.android

import android.app.Application
import com.vela.android.core.VelaRepositories

class VelaApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        VelaRepositories.init(this)
    }
}
