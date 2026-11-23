package com.voria.umsh.services.location

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.CancellationSignal
import androidx.core.content.ContextCompat
import com.voria.umsh.core.MobilePositionRecord
import com.voria.umsh.services.mobilecore.AppLog
import java.util.concurrent.Executor
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.onEach

/**
 * One reading of this phone's position. [approximate]: read under an
 * approximate grant, so good only to [SharedPrecision.approximateCeiling].
 */
data class PhoneFix(
    val latitudeDegrees: Double,
    val longitudeDegrees: Double,
    val accuracyMeters: Double?,
    val approximate: Boolean,
) {
    fun record() = MobilePositionRecord(latitudeDegrees, longitudeDegrees, accuracyMeters)
}

/**
 * Where this phone's readings come from, and what Android allows of them.
 * A seam so the runtime's rules run in JVM tests without `LocationManager`.
 */
interface PhoneLocationSource {
    val grant: StateFlow<LocationGrant>

    /** The app is in use (started): readings are taken only then (D9, no background location). */
    val inUse: StateFlow<Boolean>

    /** Read the grant again: after a permission dialog, and on every start. */
    fun refresh()

    /** Readings good to about [cellMeters], while collected; nothing when [grant] allows none. */
    fun fixes(grant: LocationGrant, cellMeters: Double): Flow<PhoneFix>

    /** No location at all: tests that never share one. */
    object None : PhoneLocationSource {
        override val grant: StateFlow<LocationGrant> = MutableStateFlow(LocationGrant.None)
        override val inUse: StateFlow<Boolean> = MutableStateFlow(false)

        override fun refresh() = Unit

        override fun fixes(grant: LocationGrant, cellMeters: Double): Flow<PhoneFix> = emptyFlow()
    }
}

/** The location permissions: precise and approximate are asked for together; Android lets the user pick. */
object LocationPermission {
    val permissions = arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)

    fun read(context: Context): LocationGrant = when {
        granted(context, Manifest.permission.ACCESS_FINE_LOCATION) -> LocationGrant.Precise
        granted(context, Manifest.permission.ACCESS_COARSE_LOCATION) -> LocationGrant.Approximate
        else -> LocationGrant.None
    }

    /** A request's answer as a grant. */
    fun answered(results: Map<String, Boolean>): LocationGrant = when {
        results[Manifest.permission.ACCESS_FINE_LOCATION] == true -> LocationGrant.Precise
        results[Manifest.permission.ACCESS_COARSE_LOCATION] == true -> LocationGrant.Approximate
        else -> LocationGrant.None
    }

    private fun granted(context: Context, permission: String) =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
}

/**
 * This phone's position from `LocationManager`, with no Play services:
 * the fused provider where the phone has one, else GPS and network
 * (network alone under approximate). Readings start with one current fix,
 * then follow the phone every minute, or as it moves half a cell (at
 * least 25 m). Nothing here stores a coordinate.
 */
class PhoneLocation(private val context: Context) : PhoneLocationSource {
    private val manager: LocationManager? = context.getSystemService(LocationManager::class.java)

    private val _grant = MutableStateFlow(LocationPermission.read(context))
    override val grant: StateFlow<LocationGrant> = _grant.asStateFlow()

    private val _inUse = MutableStateFlow(false)
    override val inUse: StateFlow<Boolean> = _inUse.asStateFlow()

    override fun refresh() {
        val now = LocationPermission.read(context)
        if (_grant.value != now) AppLog.i(TAG, "location grant: $now")
        _grant.value = now
    }

    /** From the process's lifecycle: started or stopped. */
    fun setInUse(inUse: Boolean) {
        _inUse.value = inUse
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    override fun fixes(grant: LocationGrant, cellMeters: Double): Flow<PhoneFix> {
        val manager = manager ?: return emptyFlow()
        if (grant == LocationGrant.None) return emptyFlow()
        // Android leaves a request made while system location is off
        // inactive once it is turned on, so requests follow the switch.
        return locationOn(manager).flatMapLatest { on -> if (on) listening(manager, grant, cellMeters) else emptyFlow() }
    }

    /** The system location switch, now and as it changes. */
    private fun locationOn(manager: LocationManager): Flow<Boolean> = callbackFlow {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                trySend(manager.isLocationEnabled)
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(LocationManager.MODE_CHANGED_ACTION),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        trySend(manager.isLocationEnabled)
        awaitClose { context.unregisterReceiver(receiver) }
    }.distinctUntilChanged().onEach { on -> if (!on) AppLog.i(TAG, "system location off") }

    private fun listening(manager: LocationManager, grant: LocationGrant, cellMeters: Double): Flow<PhoneFix> =
        callbackFlow {
            val approximate = grant == LocationGrant.Approximate
            val send = { location: Location -> trySend(location.fix(approximate)).let { } }
            val listener = LocationListener { send(it) }
            val direct = Executor(Runnable::run)
            val providers = providers(manager, grant)
            if (providers.isEmpty()) AppLog.w(TAG, "no location provider")
            val minDistance = maxOf(cellMeters / 2, MIN_DISTANCE_METERS).toFloat()
            // One signal per request: a signal cancels only the last request given it.
            val signals = providers.map { CancellationSignal() }
            providers.zip(signals).forEach { (provider, signal) ->
                // Apart, so a refused one-shot read leaves the updates requested.
                try {
                    manager.getCurrentLocation(provider, signal, direct) { location -> location?.let(send) }
                } catch (error: SecurityException) {
                    refused(provider, error)
                } catch (error: IllegalArgumentException) {
                    unavailable(provider)
                }
                try {
                    manager.requestLocationUpdates(provider, INTERVAL_MS, minDistance, direct, listener)
                } catch (error: SecurityException) {
                    refused(provider, error)
                } catch (error: IllegalArgumentException) {
                    unavailable(provider)
                }
            }
            AppLog.i(TAG, "listening (${providers.joinToString()}, ${grant.name.lowercase()})")
            awaitClose {
                signals.forEach { it.cancel() }
                manager.removeUpdates(listener)
                AppLog.i(TAG, "stopped listening")
            }
        }

    /** The phone's providers, by what it has rather than what is on now. */
    private fun providers(manager: LocationManager, grant: LocationGrant): List<String> {
        if (manager.hasProvider(LocationManager.FUSED_PROVIDER)) return listOf(LocationManager.FUSED_PROVIDER)
        val wanted = when (grant) {
            LocationGrant.Precise -> listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
            else -> listOf(LocationManager.NETWORK_PROVIDER)
        }
        return wanted.filter(manager::hasProvider).ifEmpty {
            listOf(LocationManager.PASSIVE_PROVIDER).filter(manager::hasProvider)
        }
    }

    /** Revoked between the check and the request: the next refresh reads it. */
    private fun refused(provider: String, error: SecurityException) =
        AppLog.w(TAG, "$provider refused: ${error.javaClass.simpleName}")

    private fun unavailable(provider: String) = AppLog.w(TAG, "$provider unavailable")

    private fun Location.fix(approximate: Boolean) = PhoneFix(
        latitudeDegrees = latitude,
        longitudeDegrees = longitude,
        accuracyMeters = if (hasAccuracy()) accuracy.toDouble() else null,
        approximate = approximate,
    )

    private companion object {
        const val TAG = "umsh.location"
        const val INTERVAL_MS = 60_000L
        const val MIN_DISTANCE_METERS = 25.0
    }
}
