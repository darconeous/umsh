package com.voria.umsh.app

import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.models.KeyProtection
import com.voria.umsh.services.identity.IdentityOperations
import com.voria.umsh.services.location.FakeLocationSource
import com.voria.umsh.services.location.LocationGrant
import com.voria.umsh.services.preferences.AppPreferences
import com.voria.umsh.services.preferences.OnboardingStep
import java.io.File
import java.time.Clock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Share location's stored and effective policy over the preferences
 * (§3.8): the user's choice is stored as made, and the effective precision
 * stops at about 9.8 km while only approximate location is granted; a
 * precise grant restores it untouched. What reaches the core, and in what
 * order, is [com.voria.umsh.services.location.LocationGateTest]'s.
 */
class ShareLocationPolicyTest {
    @get:Rule val temp = TemporaryFolder()

    @Test
    fun theStoredChoiceIsClampedByTheGrant() = runBlocking<Unit> {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val store = MobileAppStore.open(temp.newFolder().resolve("live.sqlite").path)
        val core = MobileAppCore(store, MemorySecretVault("live", VaultLog()), MobileAppConfigRecord(temp.newFolder().path, 65026u))
        val owner = MobileIdentity.unlock(ByteArray(32) { 9 }).use { it.publicIdentity() }
        val source = FakeLocationSource(grant = LocationGrant.Approximate)
        val runtime = AppRuntime(
            core = core,
            kind = CoreKind.Live,
            generation = 1,
            owner = owner,
            identityOps = IdentityOperations(MemoryIdentityVault(VaultLog())),
            protection = { KeyProtection.Software },
            preferences = AppPreferences(File(temp.newFolder(), "p.preferences_pb"), scope),
            initialOnboarding = OnboardingStep.Done,
            seed = null,
            foregroundSignals = emptyFlow(),
            clock = Clock.systemUTC(),
            scope = scope,
            location = source,
        )
        suspend fun effective(expected: UByte?) = withTimeout(TIMEOUT_MS) {
            runtime.effectivePolicy.first { it.locationPrecision == expected }
        }

        // Off by default: nothing to clamp.
        assertNull(runtime.effectivePolicy.first().locationPrecision)

        runtime.setPolicy { shareLocation = true }.await()
        assertEquals(5.toUByte(), runtime.policy.first().locationPrecision)
        effective(3u)

        // Precise granted later: the choice comes back by itself.
        source.grant.value = LocationGrant.Precise
        effective(5u)

        // A coarse choice is never made finer, under either grant.
        runtime.setPolicy { locationPrecision = 2 }.await()
        effective(2u)
        source.grant.value = LocationGrant.Approximate
        effective(2u)

        // Refused: the choice stands, and nothing is read to share under it.
        runtime.setPolicy { locationPrecision = 6 }.await()
        source.grant.value = LocationGrant.None
        effective(6u)

        runtime.setPolicy { shareLocation = false }.await()
        effective(null)
        // Kept for the next time it is turned on.
        runtime.setPolicy { shareLocation = true }.await()
        effective(6u)

        core.close()
        store.close()
        scope.cancel()
    }

    private companion object {
        const val TIMEOUT_MS = 5_000L
    }
}
