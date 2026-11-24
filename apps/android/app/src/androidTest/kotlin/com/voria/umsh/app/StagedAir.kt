package com.voria.umsh.app

import com.voria.umsh.services.radio.StagingRadioConnection

/** The staged air under a [FreshHostRule]'s staging host: the failures only tests arrange. */
val FreshHostRule.stagedAir: StagingRadioConnection
    get() = checkNotNull(host.stagingRadio.value) { "no staged air" }

/**
 * While not [reachable], the managed repeater (Tallac Ridge) neither hears
 * nor is heard: a ping or a Peer Repeaters ask to it meets silence and
 * times out. ([StagingRadioConnection.setTransmissionsFailing] fails the
 * phone's own transmissions; a ping then times out the same way.)
 */
fun StagingRadioConnection.setRemoteDeviceReachable(reachable: Boolean) = air.setRemoteDeviceReachable(reachable)
