package com.voria.umsh.lint

import com.android.tools.lint.client.api.UElementHandler
import com.android.tools.lint.detector.api.Category
import com.android.tools.lint.detector.api.Detector
import com.android.tools.lint.detector.api.Implementation
import com.android.tools.lint.detector.api.Issue
import com.android.tools.lint.detector.api.JavaContext
import com.android.tools.lint.detector.api.Scope
import com.android.tools.lint.detector.api.Severity
import com.android.tools.lint.detector.api.SourceCodeScanner
import org.jetbrains.uast.UBinaryExpression
import org.jetbrains.uast.UBlockExpression
import org.jetbrains.uast.UCallExpression
import org.jetbrains.uast.UElement
import org.jetbrains.uast.UExpression
import org.jetbrains.uast.UExpressionList
import org.jetbrains.uast.UIfExpression
import org.jetbrains.uast.ULiteralExpression
import org.jetbrains.uast.UPolyadicExpression
import org.jetbrains.uast.UQualifiedReferenceExpression
import org.jetbrains.uast.USimpleNameReferenceExpression
import org.jetbrains.uast.USwitchClauseExpressionWithBody
import org.jetbrains.uast.USwitchExpression
import org.jetbrains.uast.UYieldExpression
import org.jetbrains.uast.UastBinaryOperator
import org.jetbrains.uast.skipParenthesizedExprDown

/**
 * Flags a string literal shown to the user: passed to `Text`/`BasicText`, to a
 * Compose UI parameter that names visible or spoken text (a label, a title, a
 * snackbar message), to an `AnnotatedString` or its builder's `append`, or to
 * `Toast.makeText`, or assigned to a semantics description. Those strings
 * belong in resources.
 *
 * Parameter names are matched only on the UI toolkits and the app's own code:
 * the `label` that `animateFloatAsState` and the transition APIs take names
 * the animation for tooling and is never shown.
 *
 * The design system's `Glyphs.kt` holds the app's non-linguistic constants
 * (reaction emoji, separators inside identifiers) and is exempt; code that
 * uses its constants passes references, not literals. Empty and
 * whitespace-only strings are not text and are not flagged.
 */
class ComposeLiteralTextDetector : Detector(), SourceCodeScanner {
    override fun getApplicableUastTypes(): List<Class<out UElement>> =
        listOf(UCallExpression::class.java, UBinaryExpression::class.java)

    override fun createUastHandler(context: JavaContext): UElementHandler? {
        if (context.file.invariantSeparatorsPath.endsWith(EXEMPT_FILE)) return null
        return object : UElementHandler() {
            override fun visitCallExpression(node: UCallExpression) {
                val method = node.resolve() ?: return
                // A compiled function with value-class parameters (Compose's
                // `Text` takes `Color`, `TextUnit`) has a mangled JVM name,
                // `Text-Nvy7gAk`; its source name is the part before the dash.
                val methodName = method.name.substringBefore('-')
                val pkg = "${context.evaluator.getPackage(method)?.qualifiedName}."
                val uiCall = UI_PACKAGES.any { pkg.startsWith(it) }
                val textCall = uiCall && methodName in TEXT_FUNCTIONS
                val stringCall = "${method.containingClass?.qualifiedName}.$methodName" in TEXT_METHODS
                for ((argument, parameter) in context.evaluator.computeArgumentMapping(node, method)) {
                    val name = parameter.name
                    val shown = when {
                        uiCall && name in TEXT_PARAMETERS -> true
                        pkg.startsWith(MATERIAL3) && name in MATERIAL3_TEXT_PARAMETERS -> true
                        textCall -> name == "text"
                        // These take the text as their one string parameter.
                        stringCall -> parameter.type.canonicalText in STRING_TYPES
                        else -> false
                    }
                    if (shown && isLiteralText(argument)) report(context, argument, name)
                }
            }

            override fun visitBinaryExpression(node: UBinaryExpression) {
                if (node.operator != UastBinaryOperator.ASSIGN) return
                val name = assignedName(node.leftOperand) ?: return
                if (name in SEMANTICS_PROPERTIES && isLiteralText(node.rightOperand)) {
                    report(context, node.rightOperand, name)
                }
            }
        }
    }

    private fun report(context: JavaContext, argument: UExpression, name: String) {
        context.report(
            ISSUE,
            argument,
            context.getLocation(argument),
            "Literal text for `$name`: use a string resource",
        )
    }

    /** The property name an assignment's left side names, qualified or not. */
    private fun assignedName(target: UExpression): String? =
        when (val e = target.skipParenthesizedExprDown()) {
            is USimpleNameReferenceExpression -> e.identifier
            is UQualifiedReferenceExpression -> assignedName(e.selector)
            else -> null
        }

    /** True when [expression] is a string that carries literal characters. */
    private fun isLiteralText(expression: UExpression): Boolean {
        val type = expression.getExpressionType()?.canonicalText
        if (type != null && type != "java.lang.String") return false
        return when (val e = expression.skipParenthesizedExprDown()) {
            is ULiteralExpression -> (e.value as? String)?.isNotBlank() == true
            // String templates and concatenations.
            is UPolyadicExpression -> e.operands.any(::isLiteralText)
            is UIfExpression -> listOfNotNull(e.thenExpression, e.elseExpression).any(::isLiteralText)
            is USwitchExpression ->
                e.body.expressions.filterIsInstance<USwitchClauseExpressionWithBody>().any { clause ->
                    clause.body.expressions.lastOrNull()?.let(::isLiteralText) == true
                }
            // A branch written as a block yields its last expression.
            is UBlockExpression -> e.expressions.lastOrNull()?.let(::isLiteralText) == true
            is UExpressionList -> e.expressions.lastOrNull()?.let(::isLiteralText) == true
            is UYieldExpression -> e.expression?.let(::isLiteralText) == true
            else -> false
        }
    }

    companion object {
        private const val EXEMPT_FILE = "/com/voria/umsh/designsystem/Glyphs.kt"

        /** Owners whose parameter names are trusted to mean shown text. */
        private val UI_PACKAGES = listOf(
            "androidx.compose.material3.",
            "androidx.compose.foundation.",
            "androidx.compose.ui.",
            "com.voria.umsh.",
        )
        private val TEXT_FUNCTIONS = setOf("Text", "BasicText")
        private val TEXT_PARAMETERS = setOf(
            "contentDescription",
            "label",
            "placeholder",
            "title",
            "onClickLabel",
            "onLongClickLabel",
            "stateDescription",
        )

        /**
         * `SnackbarHostState.showSnackbar`'s text. Matched on Material 3 only:
         * `message` is a log or exception message almost everywhere else.
         */
        private const val MATERIAL3 = "androidx.compose.material3."
        private val MATERIAL3_TEXT_PARAMETERS = setOf("message", "actionLabel")

        /** Calls, as `owner.method`, whose string parameter is shown text. */
        private val TEXT_METHODS = setOf(
            "androidx.compose.ui.text.AnnotatedString.AnnotatedString",
            "androidx.compose.ui.text.AnnotatedString.Builder.append",
            "android.widget.Toast.makeText",
        )
        private val STRING_TYPES = setOf("java.lang.String", "java.lang.CharSequence")
        private val SEMANTICS_PROPERTIES = setOf("contentDescription", "stateDescription")

        @JvmField
        val ISSUE: Issue = Issue.create(
            id = "ComposeLiteralText",
            briefDescription = "Literal text in Compose code",
            explanation = """
                Every string the user sees or hears is a string resource, so it can be \
                translated and reviewed. Use `stringResource`, `pluralStringResource` or a \
                resource read through `Context`. Non-linguistic glyphs go in `Glyphs.kt`.
                """,
            category = Category.I18N,
            priority = 7,
            severity = Severity.ERROR,
            implementation = Implementation(ComposeLiteralTextDetector::class.java, Scope.JAVA_FILE_SCOPE),
        )
    }
}
