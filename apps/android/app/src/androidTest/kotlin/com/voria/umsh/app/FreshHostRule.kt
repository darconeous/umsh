package com.voria.umsh.app

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.rules.ExternalResource

/**
 * A host of the test's own: new files and Keystore keys before it, all of
 * them deleted after. Order it before any rule that launches an activity,
 * so the activity meets the new host: `@get:Rule(order = 0)`.
 */
class FreshHostRule : ExternalResource() {
    private val application: TestUmshApplication
        get() = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as TestUmshApplication

    val host: AppCoreHost get() = application.coreHost

    override fun before() = application.reset()

    override fun after() {
        application.discard()
    }
}
