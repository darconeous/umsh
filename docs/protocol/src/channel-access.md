# Channel Access

This chapter describes how UMSH nodes contend for channel access before transmitting. These procedures apply to all transmissions — original packets, forwarded packets, and acknowledgments — unless otherwise specified.

## Frame Duration

**T_frame** is the maximum on-air duration of a LoRa frame at the configured channel settings (spreading factor, bandwidth, coding rate, and maximum payload size). T_frame is not a fixed protocol constant; implementations derive it from the channel configuration. All timing parameters in this chapter are expressed as multiples of T_frame.

For reference, typical T_frame values for a maximum-length (255-byte) packet using common MeshCore-style channel settings:

| Region | Settings | T_frame |
|---|---|---|
| USA (915 MHz) | BW 62.5 kHz, SF7, CR 4/5 | ~0.8 s |
| Europe (868 MHz) | BW 62.5 kHz, SF8, CR 4/8 | ~2.2 s |

## Channel Sensing

In general, before transmitting any packet, a node SHOULD perform Channel Activity Detection (CAD),
or whatever the appropriate analogous mechanism is for the given physical layer.
CAD is a LoRa hardware primitive that detects preamble energy on the channel with minimal power draw.

- If CAD indicates the channel is idle, proceed to transmit.
- If CAD indicates the channel is busy, enter the backoff procedure.

## Backoff Procedure

When CAD indicates the channel is busy:

1. Wait a random duration uniformly sampled from [T_frame/40, T_frame/4].
2. Perform CAD again.
3. Repeat up to 15 more times (16 CAD attempts total).
4. If the channel remains busy after all attempts, drop the packet silently.

## Flood Forwarding Contention Window

When a repeater is eligible to flood-forward a packet, it SHOULD NOT just transmit like it would any other packet. Instead, it waits a contention delay proportional to the power of the received signal yet also inversely proportional to the quality of the received signal. Nodes that heard the packet cleanly but faintly transmit first; nodes that barely met the signal threshold, or heard it very strongly, wait longer. When a well-positioned repeater transmits, others overhear it, recognize the packet via duplicate suppression, and usually defer or abandon their own pending forwarding.

> [!NOTE]
> This guidance is still provisional and should be treated as a starting point until it is validated with real-world measurements.

Although the contention parameters below are configurable in principle, nodes in the same mesh SHOULD use the same values so that forwarding behavior remains predictable. Unless a deployment intentionally overrides them, implementations SHOULD use the defaults in this section.

For the first forwarding decision after reception, compute the contention window as:

```text
SNR_low = -9 dB
SNR_high = 3 dB
RSSI_low = -100 dBm
RSSI_high = -70 dBm

W_min = 0
W_max = T_frame/2
W_jitter = T_frame/10

quality = clamp((received_SNR − SNR_low) / (SNR_high − SNR_low), 0, 1)
signal = clamp((received_RSSI − RSSI_low) / (RSSI_high − RSSI_low), 0, 1)

W       = W_min + (W_max − W_min) × max((1 − quality), signal)
delay   = D_ack + W + uniform_random(0, W_jitter)
```

Where:

- When flood-forwarding, the effective minimum SNR threshold is the higher of the Minimum SNR packet option (if present) and any locally configured minimum SNR. A repeater MUST NOT flood-forward if the received SNR is below that effective threshold. (Signal-quality thresholds do not apply to source-routed hops.)
- `SNR_low`/`SNR_high` and `RSSI_low`/`RSSI_high` define the clamp ranges that normalize the two measurements for the contention heuristic.
- `W_min` is the minimum contention window for strong receptions.
- `W_max` is the maximum intentional forwarding-delay window.
- `W_jitter` bounds the random tie-breaking delay added after the deterministic window, so that nodes whose measurements agree do not transmit in the same instant.
- `received_SNR` and `received_RSSI` are the SNR and RSSI measured during reception of the packet being forwarded.
- `D_ack` is the [ACK protection interval](#ack-protection-interval): a guard delay that applies when the forwarded packet may elicit an immediate ACK from its destination, and zero otherwise.

After computing the delay, the repeater waits. Other packets SHOULD continue to be forwarded while waiting, assuming the channel is clear.

If the repeater overhears the same packet forwarded by another node (identified by MIC in the duplicate cache) before the delay expires, it SHOULD defer rather than transmit. A safe default is to recalculate a new delay using the same `W_min`/`W_max` limits—including `D_ack` when it applies, since the overheard copy may itself elicit an immediate ACK from the destination—and restart the waiting period. A repeater SHOULD NOT do this more than 3 times; after the third such deferral it SHOULD abandon the pending forward.

If the repeater instead overhears a MAC ack whose `ack_mic` matches the pending packet's MIC prefix, it SHOULD [cancel the pending forward outright](repeater-operation.md#ack-cancellation) rather than defer: the destination provably has the packet.

This deferral behavior is intended only for the first local forwarding decision after reception. Once a repeater has actually transmitted its own copy, any later retransmission behavior is governed by [Repeater Operation](repeater-operation.md#forwarding-confirmation).

Nodes waiting for implicit forwarding confirmation MUST size their confirmation timeout to include this full forwarding-delay window. A safe default is to allow:

- up to `D_ack` of ACK protection delay, when it applies
- up to `W_max + W_jitter` of intentional forwarding delay
- up to `T_frame` for the forwarded transmission itself
- an additional guard margin of up to `T_frame`

## ACK Protection Interval

The final destination of an ack-requested packet transmits its ACK as soon as the packet ends, without performing CAD (see [Immediate ACK Transmission](#immediate-ack-transmission)). CAD alone cannot protect that ACK from flood forwarders triggered by the end of the same reception: the contention delay `W + uniform_random(0, W_jitter)` may be arbitrarily small, CAD detects preamble energy and may miss an ACK already past its preamble, and a forwarder may not be able to hear the destination at all.

`D_ack` therefore provides deterministic separation. When the packet being flood-forwarded requests an ACK (UNAR or BUAR) and was received with no remaining source-route hops — the conditions under which its destination transmits an immediate ACK — the forwarder MUST delay by at least `D_ack` before transmitting, in addition to the computed contention delay. `D_ack` SHOULD cover the destination's receive-to-transmit turnaround plus the on-air duration of a MAC Ack packet at the configured channel settings. The suggested default is **0.25 × T_frame**; implementations that compute the actual MAC Ack airtime MAY use a tighter bound.

A packet received with source-route hops still pending does not elicit an immediate ACK from its destination, so `D_ack` does not apply when forwarding it.

## Immediate ACK Transmission

When a node is the final destination of an ack-requested packet (UNAR or BUAR) and the packet has no remaining source route hops, the node SHOULD transmit the ACK immediately — without performing CAD — provided the radio is available for transmission. This is warranted because the channel is known to have been clear at the moment the received packet ended, and flood forwarders hold their transmissions back by the [ACK protection interval](#ack-protection-interval) so the ACK gets first use of the channel.

If the radio is not immediately available for transmission, the node SHOULD perform normal CAD and backoff before transmitting the ACK.
