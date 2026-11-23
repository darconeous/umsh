package com.voria.umsh.services.radio

/** Release builds have no bridged radio; the debug source set's is the real one. */
@Suppress("UNUSED_PARAMETER")
fun bridgedRadioConnection(radio: BoundRadio, registry: RadioRegistry, events: RadioConnectionEvents): RadioConnection? = null
