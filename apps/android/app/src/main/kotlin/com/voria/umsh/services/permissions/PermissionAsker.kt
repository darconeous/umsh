package com.voria.umsh.services.permissions

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.preferences.AppPreferences
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch

/** What asking for a permission does now, by what Android will still show. */
enum class PermissionRequest {
    AlreadyGranted,

    /** Android's own dialog. */
    Ask,

    /** Android stopped asking: the app's settings page, where the user can grant it. */
    OpenSettings,
}

object PermissionAsking {
    /**
     * Ask unless Android has stopped showing its dialog ([blocked], from the
     * last request's result) and has no rationale to show. A dialog the user
     * only dismissed is still shown, so it is asked for again.
     */
    fun decide(granted: Boolean, blocked: Boolean, showRationale: Boolean): PermissionRequest = when {
        granted -> PermissionRequest.AlreadyGranted
        showRationale || !blocked -> PermissionRequest.Ask
        else -> PermissionRequest.OpenSettings
    }

    /**
     * After a refusal: whether Android has stopped showing its dialog.
     * [dialogShown]: the activity paused for it; a request Android answers
     * at once with nothing shown is already blocked. Shown, it is blocked
     * when the rationale it had is gone: a second refusal. Back or a tap
     * outside leaves the rationale where it was, and the dialog still shows.
     */
    fun blockedAfterRefusal(dialogShown: Boolean, rationaleBefore: Boolean, rationaleAfter: Boolean): Boolean = when {
        rationaleAfter -> false
        !dialogShown -> true
        else -> rationaleBefore
    }
}

/** Nearby devices: `BLUETOOTH_SCAN` and `BLUETOOTH_CONNECT`, one prompt. */
object NearbyDevicesPermission {
    val permissions = arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)

    fun granted(context: Context): Boolean = permissions.all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }
}

/**
 * The banner's Allow (`radio-control.svg`): asks for Nearby devices, or
 * opens the app's settings once Android stops asking. The same button
 * either way, so the user is never left with one that does nothing.
 * [onGranted] runs when a request this asker made is granted.
 */
@Composable
fun rememberNearbyDevicesAsker(preferences: AppPreferences, onGranted: () -> Unit = {}): () -> Unit {
    val application = LocalContext.current.applicationContext as? UmshApplication
    return rememberPermissionAsker(
        permissions = NearbyDevicesPermission.permissions,
        granted = NearbyDevicesPermission::granted,
        blocked = preferences.nearbyDevicesBlocked,
        setBlocked = preferences::setNearbyDevicesBlocked,
        openSettings = ::openAppSettings,
        name = "nearby devices",
        // The app reads the answer at once: the banners, a waiting radio and its service follow it.
        onAnswered = { application?.nearbyDevicesAnswered() },
        onGranted = onGranted,
    )
}

/**
 * One permission set's ask: Android's dialog while it will still show it,
 * else [openSettings], where the user can grant it. Whether Android has
 * stopped asking is kept in [blocked], from the last request's result.
 */
@Composable
fun rememberPermissionAsker(
    permissions: Array<String>,
    granted: (Context) -> Boolean,
    blocked: Flow<Boolean>,
    setBlocked: suspend (Boolean) -> Unit,
    openSettings: (Context) -> Unit,
    name: String,
    onAnswered: () -> Unit = {},
    onGranted: () -> Unit = {},
): () -> Unit {
    val asker = rememberAsker(permissions, granted, blocked, setBlocked, openSettings, name, onAnswered, onGranted)
    return remember(asker) { asker::ask }
}

/** A permission set's ask, from [rememberAsker]. */
class PermissionAsker internal constructor(private val run: (openSettingsWhenBlocked: Boolean) -> Unit) {
    /** Android's dialog, or the app's settings page once Android stops showing it. */
    fun ask() = run(true)

    /** Android's dialog if it will still show it; nothing otherwise. */
    fun askIfAskable() = run(false)
}

/**
 * [rememberPermissionAsker]'s ask as an object, for a control that should
 * only raise Android's dialog. [satisfied] reads a request's answer: every
 * permission granted unless said otherwise (location's approximate grant
 * answers a request for precise and approximate).
 */
@Composable
fun rememberAsker(
    permissions: Array<String>,
    granted: (Context) -> Boolean,
    blocked: Flow<Boolean>,
    setBlocked: suspend (Boolean) -> Unit,
    openSettings: (Context) -> Unit,
    name: String,
    onAnswered: () -> Unit = {},
    onGranted: () -> Unit = {},
    satisfied: (Map<String, Boolean>) -> Boolean = { results -> results.isNotEmpty() && results.values.all { it } },
): PermissionAsker {
    val context = LocalContext.current
    val activity = LocalActivity.current
    val scope = rememberCoroutineScope()
    val isBlocked by blocked.collectAsStateWithLifecycle(initialValue = false)
    val blockedNow by rememberUpdatedState(isBlocked)
    val grantedNow by rememberUpdatedState(onGranted)
    val answeredNow by rememberUpdatedState(onAnswered)
    val grantCheck by rememberUpdatedState(granted)
    val satisfiedBy by rememberUpdatedState(satisfied)
    // The request in flight, kept across a recreation while Android's dialog is up.
    var pending by rememberSaveable { mutableStateOf(false) }
    var rationaleBefore by rememberSaveable { mutableStateOf(false) }
    var dialogShown by rememberSaveable { mutableStateOf(false) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_PAUSE && pending) dialogShown = true
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { results ->
        val all = satisfiedBy(results)
        val nowBlocked = !all && PermissionAsking.blockedAfterRefusal(
            dialogShown = dialogShown,
            rationaleBefore = rationaleBefore,
            rationaleAfter = activity?.let { showsRationale(it, permissions) } ?: false,
        )
        pending = false
        AppLog.i(TAG, "$name: ${if (all) "granted" else if (nowBlocked) "refused, not asked again" else "refused"}")
        scope.launch { runCatching { setBlocked(nowBlocked) } }
        answeredNow()
        if (all) grantedNow()
    }
    return remember(context, activity, launcher) {
        PermissionAsker { openSettingsWhenBlocked ->
            val rationale = activity?.let { showsRationale(it, permissions) } ?: false
            val decision = PermissionAsking.decide(
                granted = grantCheck(context),
                blocked = blockedNow,
                showRationale = rationale,
            )
            when (decision) {
                PermissionRequest.AlreadyGranted -> grantedNow()
                PermissionRequest.Ask -> {
                    pending = true
                    rationaleBefore = rationale
                    dialogShown = false
                    launcher.launch(permissions)
                }
                PermissionRequest.OpenSettings -> if (openSettingsWhenBlocked) openSettings(context)
            }
        }
    }
}

/**
 * The banner's Turn on: Android's own Bluetooth request. It needs Nearby
 * devices, so without it that is asked for first, and Bluetooth once it is
 * granted.
 */
@Composable
fun rememberBluetoothEnabler(preferences: AppPreferences): () -> Unit {
    val context = LocalContext.current
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        AppLog.i(TAG, "bluetooth request: ${if (result.resultCode == Activity.RESULT_OK) "turned on" else "declined"}")
    }
    val requestBluetooth = {
        val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter
        if (adapter?.isEnabled != true) {
            try {
                launcher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
            } catch (_: ActivityNotFoundException) {
                AppLog.w(TAG, "no Bluetooth request on this device")
            }
        }
    }
    return rememberNearbyDevicesAsker(preferences, onGranted = requestBluetooth)
}

private fun showsRationale(activity: Activity, permissions: Array<String>): Boolean =
    permissions.any { ActivityCompat.shouldShowRequestPermissionRationale(activity, it) }

fun openAppSettings(context: Context) {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        AppLog.w(TAG, "no app settings page")
    }
}

private const val TAG = "umsh.permissions"
