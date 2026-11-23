package com.voria.umsh.services.location

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged

/**
 * Which readings reach the core (§3.8, §7.6). While sharing, at the
 * precision the core is given:
 * - with a grant and the app in use, readings good to that cell;
 * - with the app stopped, nothing new: the core keeps the last position,
 *   for as long as the process lives;
 * - with no grant (refused, or revoked), the position is withdrawn
 *   ([deliver] null), and readings resume by themselves once allowed.
 * Not sharing, nothing is read; the core drops the position with the policy.
 */
class LocationRelay(
    /**
     * The precision the core is given and the grant it was clamped for, as
     * one value: read apart, a grant change would briefly pair the new
     * grant with the old precision.
     */
    private val shared: Flow<Pair<UByte?, LocationGrant>>,
    private val source: PhoneLocationSource,
    private val sizes: SharedPrecision,
    private val deliver: suspend (PhoneFix?) -> Unit,
) {
    private data class Wanted(val precision: UByte?, val grant: LocationGrant, val inUse: Boolean)

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun run() {
        combine(shared, source.inUse) { (precision, grant), inUse -> Wanted(precision, grant, inUse) }
            .distinctUntilChanged()
            .collectLatest { wanted ->
                val precision = wanted.precision ?: return@collectLatest
                if (wanted.grant == LocationGrant.None) {
                    deliver(null)
                    return@collectLatest
                }
                if (!wanted.inUse) return@collectLatest
                val cell = sizes.cellMeters(precision) ?: return@collectLatest
                source.fixes(wanted.grant, cell).collect { deliver(it) }
            }
    }
}
