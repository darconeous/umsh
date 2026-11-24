package com.voria.umsh.features.scanner

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.compose.runtime.Composable
import androidx.core.content.ContextCompat
import com.voria.umsh.services.permissions.PermissionAsker
import com.voria.umsh.services.permissions.openAppSettings
import com.voria.umsh.services.permissions.rememberAsker
import com.voria.umsh.services.preferences.AppPreferences

/** The camera, for the QR scanner (`permissions.svg` 2–3). */
object CameraPermission {
    val permissions = arrayOf(Manifest.permission.CAMERA)

    fun granted(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
}

/**
 * The scanner's camera ask, on the shared asker: Android's dialog while it
 * will still show it, else (Allow camera) the app's settings page.
 */
@Composable
fun rememberCameraAsker(preferences: AppPreferences, onAnswered: () -> Unit): PermissionAsker = rememberAsker(
    permissions = CameraPermission.permissions,
    granted = CameraPermission::granted,
    blocked = preferences.cameraBlocked,
    setBlocked = preferences::setCameraBlocked,
    openSettings = ::openAppSettings,
    name = "camera",
    onAnswered = onAnswered,
    onGranted = onAnswered,
)
