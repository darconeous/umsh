## Companion Radio

> [!NOTE]
> This section is a work-in-progress.

Each companion radio hosts at least one node directly on the device that represents the companion radio itself. By default, this node is not advertised by sending beacons. This companion node provides a way to remotely manage the companion radio in-band, even when it is not connected to a phone.

Unlike Meshtastic or Meshcore, the software (usually running on a phone) that a companion radio connects to is what owns the long-term identities of the person using the radio. In this way, the node that a person advertises to others and uses for texting lives on the phone, not the companion radio.

This also means that the companion radio cannot itself usually decrypt messages on behalf of the node that lives on the phone. However, there are some exceptions, which are detailed below.

There are two non-exclusive ways that a phone or computer can interact with a companion radio:

1. Tethered. (via bluetooth or USB) The phone is allowed to use the companion radio directly, as if it owned it. This use is not exclusive (because the companion radio itself has a node), but it kinda feels like it is.
2. Bridged. (via bluetooth, wifi, etc) One or more phones are allowed to use the companion radio as a bridge, just like any repeater or bridge. This allows multiple in an area to share the same LoRa radio.

Both can be in use at once.

Tethered mode allows the companion radio to act in a limited capacity on the phone-node's behalf when the phone is disconnected: packets are collected and stored, etc. Channel keys and *pairwise symmetric keys* can optionally be loaded into the companion firmware to enable more sophisticated alerting, such as for text message keywords. The private key for the node on the phone never gets stored on the companion radio, but pairwise keys for specific known nodes may be sent over for this purpose. This allows the companion radio to send acks on the phone node's behalf when the phone node is not connected.

The tethered interface provides for the following:

* Ability to configure the LoRa radio for all appropriate LoRa parameters. In some cases the underlying radio might not be LoRa, so this mechanism needs to not be LoRa specific.
* Ability to transmit raw UMSH frames.
* Ability to set a filter on what UMSH frames to receive. These filters include, but might not be limited to:
	* Destination hint
	* Channel
	* Ack Tag
	* Packet Type
	* ALL PACKETS
* Ability to set beacons/advertisements to periodically broadcast.
* Ability to set keys associated with a node that lives on the phone for when the phone is disconnected:
	* Channel keys
	* Pair-wise keys and the source nodes they are associated with

