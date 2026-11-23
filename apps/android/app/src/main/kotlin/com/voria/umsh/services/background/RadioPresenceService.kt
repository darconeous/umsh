package com.voria.umsh.services.background

import android.companion.AssociationInfo
import android.companion.CompanionDeviceService
import android.companion.DevicePresenceEvent
import android.os.Build
import androidx.annotation.RequiresApi
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.services.mobilecore.AppLog
import kotlinx.coroutines.launch

/**
 * What Android's companion presence says about the associated radio
 * (§7.3, D6): when it appears, the radio's foreground service starts (from
 * the background if need be: an associated app is exempt), brings the live
 * core up headless and seeks the radio. A disappearance only drops an
 * appearance held for Bluetooth to come on: the link's own loss is what the
 * app acts on.
 *
 * Android binds this service (exported, behind
 * `BIND_COMPANION_DEVICE_SERVICE`) only for an association the app asked
 * it to observe ([RadioPresence]), which starts the process if it is not
 * running. Each API level calls its own form: the address on 31–32, the
 * association on 33–35, a presence event on 36 and later (which still
 * calls the 33–35 form too; that one is ignored there). A second start
 * for one appearance is harmless: it finds the service running and the
 * radio already sought.
 */
class RadioPresenceService : CompanionDeviceService() {
    /**
     * Android binds this service only while an observed radio is present,
     * and rebinds it after the app is updated or its process ends, with no
     * new appearance for a radio already present. So the bind itself is
     * one: without it, an update while the radio is in range leaves it
     * unsought until it leaves and comes back.
     */
    override fun onCreate() {
        super.onCreate()
        appeared(associationId = null, address = null)
    }

    @Deprecated("API 31–32 form")
    override fun onDeviceAppeared(address: String) {
        appeared(associationId = null, address = address)
    }

    @Deprecated("API 33–35 form")
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    override fun onDeviceAppeared(associationInfo: AssociationInfo) {
        if (eventsArrive) return
        appeared(associationId = associationInfo.id, address = associationInfo.deviceMacAddress?.toString())
    }

    @Deprecated("API 31–32 form")
    override fun onDeviceDisappeared(address: String) {
        disappeared("the radio")
    }

    @Deprecated("API 33–35 form")
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    override fun onDeviceDisappeared(associationInfo: AssociationInfo) {
        if (eventsArrive) return
        disappeared("association ${associationInfo.id}")
    }

    @RequiresApi(Build.VERSION_CODES.BAKLAVA)
    override fun onDevicePresenceEvent(event: DevicePresenceEvent) {
        when (event.event) {
            DevicePresenceEvent.EVENT_BLE_APPEARED -> appeared(associationId = event.associationId, address = null)
            DevicePresenceEvent.EVENT_BLE_DISAPPEARED -> disappeared("association ${event.associationId}")
            else -> AppLog.d(TAG, "presence: event ${event.event} for association ${event.associationId}")
        }
    }

    private fun disappeared(what: String) {
        AppLog.i(TAG, "presence: $what disappeared")
        (application as UmshApplication).radioService.presenceEnded()
    }

    /** Both null: bound, so the one radio observed is present. */
    private fun appeared(associationId: Int?, address: String?) {
        val what = associationId?.let { "association $it" } ?: address?.let { "the radio" } ?: "bound; the observed radio"
        AppLog.i(TAG, "presence: $what appeared")
        val application = application as UmshApplication
        application.backgroundScope.launch {
            application.radioService.startForPresence { radio ->
                (associationId == null && address == null && radio.associationId != null) ||
                    application.associations.names(radio, associationId, address)
            }
        }
    }

    private companion object {
        const val TAG = "umsh.presence"

        /** API 36 and later: [onDevicePresenceEvent] reports each appearance. */
        val eventsArrive = Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA
    }
}
