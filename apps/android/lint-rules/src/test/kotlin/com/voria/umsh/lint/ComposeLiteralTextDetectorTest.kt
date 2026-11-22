package com.voria.umsh.lint

import com.android.tools.lint.checks.infrastructure.LintDetectorTest
import com.android.tools.lint.checks.infrastructure.TestFile
import com.android.tools.lint.detector.api.Detector
import com.android.tools.lint.detector.api.Issue

class ComposeLiteralTextDetectorTest : LintDetectorTest() {
    override fun getDetector(): Detector = ComposeLiteralTextDetector()

    override fun getIssues(): List<Issue> = listOf(ComposeLiteralTextDetector.ISSUE)

    /** Just enough of Compose for the calls below to resolve. */
    private val material3Stubs: TestFile = kotlin(
        """
        package androidx.compose.material3

        fun Text(text: String, maxLines: Int = 1) {}
        fun Icon(id: Int, contentDescription: String?) {}
        class SnackbarHostState {
            suspend fun showSnackbar(message: String, actionLabel: String? = null): Boolean = true
        }
        """,
    ).indented()

    private val foundationStubs: TestFile = kotlin(
        """
        package androidx.compose.foundation

        fun clickable(onClickLabel: String? = null, onClick: () -> Unit) {}
        fun toggleable(stateDescription: String? = null) {}
        """,
    ).indented()

    private val semanticsStubs: TestFile = kotlin(
        """
        package androidx.compose.ui.semantics

        class SemanticsPropertyReceiver
        var SemanticsPropertyReceiver.contentDescription: String
            get() = ""
            set(value) {}
        var SemanticsPropertyReceiver.stateDescription: String
            get() = ""
            set(value) {}
        fun semantics(properties: SemanticsPropertyReceiver.() -> Unit) {}
        """,
    ).indented()

    private val annotatedStringStubs: TestFile = kotlin(
        """
        package androidx.compose.ui.text

        class AnnotatedString(val text: String, val spanCount: Int = 0) {
            class Builder {
                fun append(text: String) {}
                fun append(char: Char) {}
                fun toAnnotatedString(): AnnotatedString = AnnotatedString("")
            }
        }
        fun buildAnnotatedString(builder: AnnotatedString.Builder.() -> Unit): AnnotatedString =
            AnnotatedString.Builder().apply(builder).toAnnotatedString()
        """,
    ).indented()

    /** Names that look like text but are not shown. */
    private val nonUiStubs: TestFile = kotlin(
        """
        package androidx.compose.animation.core

        fun animateFloatAsState(targetValue: Float, label: String = "FloatAnimation"): Float = targetValue
        """,
    ).indented()

    private val appLogger: TestFile = kotlin(
        """
        package com.voria.umsh.runtime

        object CoreLogger {
            fun log(message: String) {}
        }
        """,
    ).indented()

    private val glyphs: TestFile = kotlin(
        "src/main/kotlin/com/voria/umsh/designsystem/Glyphs.kt",
        """
        package com.voria.umsh.designsystem

        import androidx.compose.material3.Text

        object Glyphs {
            const val HEART = "❤️"
            const val SEPARATOR = "·"
        }

        fun glyphPreview() {
            Text("❤️")
        }
        """,
    ).indented()

    fun testLiteralsAreFlagged() {
        lint().files(
            material3Stubs,
            foundationStubs,
            semanticsStubs,
            annotatedStringStubs,
            kotlin(
                """
                package com.voria.umsh.features

                import android.content.Context
                import android.widget.Toast
                import androidx.compose.foundation.clickable
                import androidx.compose.foundation.toggleable
                import androidx.compose.material3.Icon
                import androidx.compose.material3.SnackbarHostState
                import androidx.compose.material3.Text
                import androidx.compose.ui.semantics.contentDescription
                import androidx.compose.ui.semantics.semantics
                import androidx.compose.ui.semantics.stateDescription
                import androidx.compose.ui.text.AnnotatedString
                import androidx.compose.ui.text.buildAnnotatedString

                suspend fun Screen(name: String?, flag: Boolean, mode: Int, host: SnackbarHostState, context: Context) {
                    Text("Welcome to UMSH")
                    Text(text = "Hello, ${'$'}name")
                    Text(if (flag) "On" else "")
                    Text(name ?: "Unknown")
                    Text(when (mode) { 0 -> "Zero"; else -> "" })
                    Icon(1, contentDescription = "Search")
                    semantics { contentDescription = "Muted" }
                    semantics { stateDescription = "Selected" }
                    clickable(onClickLabel = "Open") {}
                    toggleable(stateDescription = "Checked")
                    host.showSnackbar(message = "Link copied", actionLabel = "Undo")
                    AnnotatedString("Styled")
                    buildAnnotatedString { append("Draft: ") }
                    Toast.makeText(context, "Copied", Toast.LENGTH_SHORT)
                }
                """,
            ).indented(),
        ).run().expect(
            """
            src/com/voria/umsh/features/test.kt:17: Error: Literal text for text: use a string resource [ComposeLiteralText]
                Text("Welcome to UMSH")
                     ~~~~~~~~~~~~~~~~~
            src/com/voria/umsh/features/test.kt:18: Error: Literal text for text: use a string resource [ComposeLiteralText]
                Text(text = "Hello, ＄name")
                            ~~~~~~~~~~~~~~
            src/com/voria/umsh/features/test.kt:19: Error: Literal text for text: use a string resource [ComposeLiteralText]
                Text(if (flag) "On" else "")
                     ~~~~~~~~~~~~~~~~~~~~~~
            src/com/voria/umsh/features/test.kt:20: Error: Literal text for text: use a string resource [ComposeLiteralText]
                Text(name ?: "Unknown")
                     ~~~~~~~~~~~~~~~~~
            src/com/voria/umsh/features/test.kt:21: Error: Literal text for text: use a string resource [ComposeLiteralText]
                Text(when (mode) { 0 -> "Zero"; else -> "" })
                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            src/com/voria/umsh/features/test.kt:22: Error: Literal text for contentDescription: use a string resource [ComposeLiteralText]
                Icon(1, contentDescription = "Search")
                                             ~~~~~~~~
            src/com/voria/umsh/features/test.kt:23: Error: Literal text for contentDescription: use a string resource [ComposeLiteralText]
                semantics { contentDescription = "Muted" }
                                                 ~~~~~~~
            src/com/voria/umsh/features/test.kt:24: Error: Literal text for stateDescription: use a string resource [ComposeLiteralText]
                semantics { stateDescription = "Selected" }
                                               ~~~~~~~~~~
            src/com/voria/umsh/features/test.kt:25: Error: Literal text for onClickLabel: use a string resource [ComposeLiteralText]
                clickable(onClickLabel = "Open") {}
                                         ~~~~~~
            src/com/voria/umsh/features/test.kt:26: Error: Literal text for stateDescription: use a string resource [ComposeLiteralText]
                toggleable(stateDescription = "Checked")
                                              ~~~~~~~~~
            src/com/voria/umsh/features/test.kt:27: Error: Literal text for actionLabel: use a string resource [ComposeLiteralText]
                host.showSnackbar(message = "Link copied", actionLabel = "Undo")
                                                                         ~~~~~~
            src/com/voria/umsh/features/test.kt:27: Error: Literal text for message: use a string resource [ComposeLiteralText]
                host.showSnackbar(message = "Link copied", actionLabel = "Undo")
                                            ~~~~~~~~~~~~~
            src/com/voria/umsh/features/test.kt:28: Error: Literal text for text: use a string resource [ComposeLiteralText]
                AnnotatedString("Styled")
                                ~~~~~~~~
            src/com/voria/umsh/features/test.kt:29: Error: Literal text for text: use a string resource [ComposeLiteralText]
                buildAnnotatedString { append("Draft: ") }
                                              ~~~~~~~~~
            src/com/voria/umsh/features/test.kt:30: Error: Literal text for text: use a string resource [ComposeLiteralText]
                Toast.makeText(context, "Copied", Toast.LENGTH_SHORT)
                                        ~~~~~~~~
            15 errors
            """,
        )
    }

    fun testResourcesGlyphsBlanksAndNonUiNamesAreClean() {
        lint().files(
            material3Stubs,
            annotatedStringStubs,
            nonUiStubs,
            appLogger,
            glyphs,
            kotlin(
                """
                package com.voria.umsh.features

                import androidx.compose.animation.core.animateFloatAsState
                import androidx.compose.material3.Icon
                import androidx.compose.material3.Text
                import androidx.compose.ui.text.buildAnnotatedString
                import com.voria.umsh.designsystem.Glyphs
                import com.voria.umsh.runtime.CoreLogger

                fun Screen(name: String, resource: (Int) -> String, count: Int) {
                    Text(Glyphs.HEART)
                    Text(resource(1))
                    Text(name)
                    Text("${'$'}count")
                    Text("")
                    Icon(1, contentDescription = null)
                    animateFloatAsState(1f, label = "pillFill")
                    CoreLogger.log(message = "store opened")
                    buildAnnotatedString { append(name); append(' ') }
                }
                """,
            ).indented(),
        ).run().expectClean()
    }

    fun testGlyphsFileIsExempt() {
        lint().files(material3Stubs, glyphs).run().expectClean()
    }

    /** Only the design system's `Glyphs.kt` is exempt, not any file by that name. */
    fun testOtherGlyphsFileIsNotExempt() {
        lint().files(
            material3Stubs,
            kotlin(
                "src/main/kotlin/com/voria/umsh/features/Glyphs.kt",
                """
                package com.voria.umsh.features

                import androidx.compose.material3.Text

                fun glyphPreview() {
                    Text("Hello")
                }
                """,
            ).indented(),
        ).run().expect(
            """
            src/main/kotlin/com/voria/umsh/features/Glyphs.kt:6: Error: Literal text for text: use a string resource [ComposeLiteralText]
                Text("Hello")
                     ~~~~~~~
            1 error
            """,
        )
    }
}
