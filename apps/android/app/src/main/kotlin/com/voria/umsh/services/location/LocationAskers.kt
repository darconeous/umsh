package com.voria.umsh.services.location

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import com.voria.umsh.services.permissions.PermissionAsker
import com.voria.umsh.services.permissions.openAppSettings
import com.voria.umsh.services.permissions.rememberAsker
import com.voria.umsh.services.preferences.AppPreferences

/** Share location's two asks (`permissions.svg` 4–6). */
class LocationAskers(
    /** Any location: Share location turned on, and Allow under "Location is off". Precise requested. */
    val location: PermissionAsker,
    /** Precise over an approximate grant: the Precision dialog's Allow. */
    val precise: PermissionAsker,
)

/**
 * Both ask for precise and approximate together, as Android requires;
 * Android lets the user grant approximate instead. [grant] is the grant
 * the page shows, read when an ask is made; [onAnswered] reads it again.
 */
@Composable
fun rememberLocationAskers(
    preferences: AppPreferences,
    grant: () -> LocationGrant,
    onAnswered: () -> Unit,
): LocationAskers {
    val current by rememberUpdatedState(grant)
    val location = rememberAsker(
        permissions = LocationPermission.permissions,
        granted = { current() != LocationGrant.None },
        blocked = preferences.locationBlocked,
        setBlocked = preferences::setLocationBlocked,
        openSettings = ::openAppSettings,
        name = "location",
        onAnswered = onAnswered,
        satisfied = { LocationPermission.answered(it) != LocationGrant.None },
    )
    val precise = rememberAsker(
        permissions = LocationPermission.permissions,
        granted = { current() == LocationGrant.Precise },
        blocked = preferences.preciseLocationBlocked,
        setBlocked = preferences::setPreciseLocationBlocked,
        openSettings = ::openAppSettings,
        name = "precise location",
        onAnswered = onAnswered,
        satisfied = { LocationPermission.answered(it) == LocationGrant.Precise },
    )
    return LocationAskers(location, precise)
}
