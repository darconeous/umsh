package com.voria.umsh.app

import android.app.Application
import android.content.Context
import androidx.test.runner.AndroidJUnitRunner

/** Runs instrumented tests under [TestUmshApplication]. */
class UmshTestRunner : AndroidJUnitRunner() {
    override fun newApplication(
        classLoader: ClassLoader,
        className: String,
        context: Context,
    ): Application = super.newApplication(classLoader, TestUmshApplication::class.java.name, context)
}
