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

Before transmitting any packet, a node MUST perform Channel Activity Detection (CAD). CAD is a LoRa hardware primitive that detects preamble energy on the channel with minimal power draw.

- If CAD indicates the channel is idle, proceed to transmit.
- If CAD indicates the channel is busy, enter the backoff procedure.

## Backoff Procedure

When CAD indicates the channel is busy:

1. Wait a random duration uniformly sampled from [0, T_frame].
2. Perform CAD again.
3. Repeat up to 4 more times (5 CAD attempts total).
4. If the channel remains busy after all attempts, drop the packet silently.

## Flood Forwarding Contention Window

When a repeater is eligible to flood-forward a packet, it SHOULD NOT transmit immediately. Instead, it waits a contention delay inversely proportional to the quality of the received signal. Nodes that heard the packet most clearly transmit first; nodes that barely met the signal threshold wait longer. When a well-positioned repeater transmits, others overhear it, recognize the packet via duplicate suppression, and usually defer or abandon their own pending forwarding.

> [!NOTE]
> This guidance is still provisional and should be treated as a starting point until it is validated with real-world measurements.

Although the contention parameters below are configurable in principle, nodes in the same mesh SHOULD use the same values so that forwarding behavior remains predictable. Unless a deployment intentionally overrides them, implementations SHOULD use the defaults in this section.

For the first forwarding decision after reception, compute the contention window as:

```text
quality = clamp((received_SNR − SNR_low) / (SNR_high − SNR_low), 0, 1)
W       = W_min + (W_max − W_min) × (1 − quality)
delay = uniform_random(0, W)
```

Where:

- `SNR_low` and `SNR_high` define the clamp range used for the contention heuristic. The suggested defaults are **−6 dB** and **+15 dB**, respectively.
- The effective minimum SNR threshold is still the higher of the Minimum SNR packet option (if present) and any locally configured minimum SNR. A repeater MUST NOT forward at all if the received SNR is below that effective threshold.
- `W_min` is the minimum contention window for strong receptions. The suggested default is **0.2 × T_frame**.
- `W_max` is the maximum intentional forwarding-delay window. The suggested default is **2 × T_frame**.
- `received_SNR` is the SNR measured during reception of the packet being forwarded.

If SNR is unavailable but RSSI is, the same formula MAY be applied with RSSI values substituted for SNR, using appropriate threshold and range parameters.

After computing the delay, the repeater waits.

If it overhears the same packet forwarded by another node (identified by MIC in the duplicate cache) before the delay expires, it SHOULD defer rather than transmit immediately. A safe default is to resample a delay using the same `W_min`/`W_max` limits and restart the waiting period. A repeater SHOULD NOT do this more than 3 times; after the third such deferral it SHOULD abandon the pending forward.

This deferral behavior is intended only for the first local forwarding decision after reception. Once a repeater has actually transmitted its own copy, any later retransmission behavior is governed by [Repeater Operation](repeater-operation.md#forwarding-confirmation).

Nodes waiting for implicit forwarding confirmation MUST size their confirmation timeout to include this full forwarding-delay window. A safe default is to allow:

- up to `W_max` of intentional forwarding delay
- up to `T_frame` for the forwarded transmission itself
- an additional guard margin of up to `T_frame`

## Immediate ACK Transmission

When a node is the final destination of an ack-requested packet (UNAR or BUAR) and the packet has no remaining source route hops, the node SHOULD transmit the ACK immediately — without performing CAD — provided the radio is available for transmission. This is warranted because the channel is known to have been clear at the moment the received packet ended.

If the radio is not immediately available for transmission, the node SHOULD perform normal CAD and backoff before transmitting the ACK.
