package com.voria.umsh.services.location

import com.voria.umsh.core.MobileAppPolicyRecord
import com.voria.umsh.services.mobilecore.AppLog
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** The two core calls the gate orders; the core in the app, a recording fake in tests. */
interface CoreSettingsSink {
    suspend fun setPolicy(policy: MobileAppPolicyRecord)

    /** A reading, or null to withdraw the shared position. */
    suspend fun setLocation(fix: PhoneFix?)
}

/**
 * Policies and readings go to the core one at a time, since each depends
 * on the other: the core takes a reading only while the policy shares, and
 * does not coarsen one by its accuracy.
 *
 * Readings are taken for [shared], which follows what the core was given,
 * never the stored preference: a reading never arrives before the policy
 * it is shared under, and one still in flight after sharing stops is
 * dropped, not kept for the next time.
 */
class LocationGate(private val sink: CoreSettingsSink, private val sizes: SharedPrecision) {
    private val lock = Mutex()

    /** The last policy the core was given; under [lock]. */
    private var pushedPolicy: MobileAppPolicyRecord? = null

    /** The last reading the core was given while sharing; under [lock]. */
    private var held: PhoneFix? = null

    private val pushed = MutableStateFlow<Pair<UByte?, LocationGrant>?>(null)

    /** The precision the core was given and the grant it was clamped for, once given. */
    val shared: Flow<Pair<UByte?, LocationGrant>> = pushed.filterNotNull()

    /** Give the core [policy], clamped for [grant]. */
    suspend fun push(policy: MobileAppPolicyRecord, grant: LocationGrant) = lock.withLock {
        val precision = policy.locationPrecision
        val fix = held
        if (precision == null) {
            held = null
        } else if (fix != null && fix.approximate && !sizes.allows(precision, LocationGrant.Approximate)) {
            // An approximate reading never goes out as a finer cell: it is
            // withdrawn before the finer precision is set, and the next
            // precise reading replaces it.
            sink.setLocation(null)
            held = null
        }
        // A grant change that leaves the policy as it was is the relay's alone.
        if (policy != pushedPolicy) sink.setPolicy(policy)
        pushedPolicy = policy
        pushed.value = precision to grant
    }

    /** A reading, or null to withdraw the shared position. */
    suspend fun deliver(fix: PhoneFix?) = lock.withLock {
        val precision = pushed.value?.first
        if (precision == null) {
            // Read before sharing stopped: the core ignores it, and nothing is kept.
            return@withLock
        }
        if (fix != null && fix.approximate && !sizes.allows(precision, LocationGrant.Approximate)) {
            // Read under the grant just replaced: never shared as the finer cell.
            AppLog.d(TAG, "approximate reading dropped at precision $precision")
            return@withLock
        }
        held = fix
        sink.setLocation(fix)
    }

    private companion object {
        const val TAG = "umsh.location"
    }
}
