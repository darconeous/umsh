package com.voria.umsh.app

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation3.runtime.NavBackStack
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.ui.NavDisplay
import kotlinx.serialization.Serializable
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * The pages above the shell ([rememberAppStackDecorators]) each have
 * ViewModels of their own: kept across a recreation, cleared when popped.
 * The keys are this test's own; the app's own pages there arrive with
 * their stages.
 */
class AppStackStoreTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Serializable
    private data class Page(val name: String) : NavKey

    class Probe : ViewModel() {
        var cleared = false
            private set

        override fun onCleared() {
            cleared = true
        }
    }

    private val seen = HashMap<String, Probe>()
    private lateinit var stack: NavBackStack<NavKey>

    private val content: @androidx.compose.runtime.Composable () -> Unit = {
        val pages = rememberNavBackStack(Page("root"))
        stack = pages
        NavDisplay(
            backStack = pages,
            onBack = { pages.removeLastOrNull() },
            entryDecorators = rememberAppStackDecorators(),
            entryProvider = entryProvider {
                entry<Page> { page ->
                    seen[page.name] = viewModel<Probe>()
                    Text(page.name, Modifier.testTag(page.name))
                }
            },
        )
    }

    /** Drawn by the activity itself, so a recreation can draw it again. */
    private fun show() {
        compose.activityRule.scenario.onActivity { it.setContent(content = content) }
    }

    private fun push(name: String) {
        compose.runOnIdle { stack.add(Page(name)) }
        compose.onNodeWithTag(name).assertIsDisplayed()
    }

    @Test
    fun twoPagesOfOneKindHaveTheirOwnViewModels() {
        show()
        compose.onNodeWithTag("root").assertIsDisplayed()
        push("a")
        push("b")
        compose.runOnIdle {
            assertNotSame(seen.getValue("root"), seen.getValue("a"))
            assertNotSame(seen.getValue("a"), seen.getValue("b"))
        }
    }

    @Test
    fun aPagesViewModelOutlivesARecreationAndGoesWhenItIsPopped() {
        show()
        push("a")
        push("b")
        val a = compose.runOnIdle { seen.getValue("a") }
        val b = compose.runOnIdle { seen.getValue("b") }

        // A configuration change: the activity goes and comes back.
        compose.activityRule.scenario.recreate()
        show()
        compose.onNodeWithTag("b").assertIsDisplayed()
        compose.runOnIdle {
            assertSame(b, seen.getValue("b"))
            assertFalse(b.cleared)
        }

        compose.runOnIdle { stack.removeLastOrNull() }
        compose.onNodeWithTag("a").assertIsDisplayed()
        compose.runOnIdle {
            assertTrue("popped: cleared", b.cleared)
            assertFalse(a.cleared)
            assertSame(a, seen.getValue("a"))
        }
    }
}
