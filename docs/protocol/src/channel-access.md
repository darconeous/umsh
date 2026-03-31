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

When a repeater is eligible to flood-forward a packet, it SHOULD NOT transmit immediately. Instead, it waits a contention delay inversely proportional to the quality of the received signal. Nodes that heard the packet most clearly transmit first; nodes that barely met the signal threshold wait longer. When a well-positioned repeater transmits, others overhear it, recognize the packet via duplicate suppression, and cancel their own pending forwarding.

> [!NOTE]
> These calculations and constants have been written by an LLM and have not yet been fully verified for correctness.

Compute the contention delay as:

```text
W     = W_max × clamp(1 − (received_SNR − SNR_threshold) / SNR_range, 0, 1)
delay = uniform_random(0, W)
```

Where:

- `SNR_threshold` is the effective minimum SNR: the higher of the Minimum SNR packet option (if present) and any locally configured minimum SNR. If neither is configured, `SNR_threshold = 0 dB`.
- `SNR_range` is a configurable parameter; the suggested default is **20 dB**.
- `W_max` is a configurable parameter; the suggested default is **T_frame**.
- `received_SNR` is the SNR measured during reception of the packet being forwarded.

If SNR is unavailable but RSSI is, the same formula MAY be applied with RSSI values substituted for SNR, using appropriate threshold and range parameters.

After computing the delay, the repeater waits. If it overhears the same packet forwarded by another node (identified by MIC in the duplicate cache) before the delay expires, it MUST cancel its own pending transmission.

## Immediate ACK Transmission

When a node is the final destination of an ack-requested packet (UACK or BUAK) and the packet has no remaining source route hops, the node SHOULD transmit the ACK immediately — without performing CAD — provided the radio is available for transmission. This is warranted because the channel is known to have been clear at the moment the received packet ended.

If the radio is not immediately available for transmission, the node SHOULD perform normal CAD and backoff before transmitting the ACK.
