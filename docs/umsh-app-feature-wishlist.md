# UMSH iOS App — Feature Wishlist 2026-07-27

Checked against the app sources on 2026-07-30. `[x]` means the feature is
present in the shipping iOS app; `[ ]` means it is not, with a note where
something partial exists. Checking an item off is a statement about the iOS
UI, not about firmware or protocol support — several unchecked items already
work at the ULCP layer and only lack a phone-side surface.

## 1. Device Connection & Pairing

The underlying primitive: **connect to any UMSH device over BLE for configuration,
independently of which device (if any) is currently this phone's companion radio.**

- [x] Discover and connect to a UMSH device for configuration/setup.
  - [x] Works on an unconfigured device (first-time provisioning) and on an
    already-configured one (revisit/adjust).
  - [x] Works while another companion radio is actively paired and connected, so
    stand-alone devices can be set up in the field.
- [ ] Update/Change settings individually or from a pre-configured template for mass commissioning.
  — individual editing is done; there is a regional radio-profile preset, but no
  saveable multi-setting template.
- [x] Promote a connected device to this phone's companion radio.

Guided setup flows built on top of that primitive:

- [x] Set up a new device as a **tracker**.
- [x] Set up a new device as a **repeater**.
- [x] Set up a new device as this phone's **companion radio**.

## 2. Device Configuration (over BLE)

### Identity & presence
- [x] Name
- [x] Role
- [x] Mobile / fixed
- [ ] Location
- [ ] Advertisements
  - [ ] Send advertisement on boot
  - [ ] Broadcast interval (default: 4 hours)
  - [ ] Include full key in advertisement (default: false)
  - [ ] Channel used for automatic advertisements
- [ ] Channel membership — the channels the *device identity* has joined. Used for the device's own advertisements, blind unicast addressing, and repeater filtering. Not used by the phone identity.

### Radio
- [x] Regional presets
- [x] LoRa settings (custom overrides to regional presets) — frequency, transmit
  power, bandwidth, spreading factor, coding rate
- [x] Duty cycle requirements (Custom overrides to regional presets)
- [ ] Amateur radio operation
  - [ ] Mode
    - [ ] Unlicensed/Licensed-Only
    - [ ] Hybrid
  - [ ] Callsign

### Repeater
- [x] Enabled / disabled
- [x] Supported regions
- [x] Default region
- [x] Minimum RSSI to flood-forward
- [x] Minimum SNR to flood-forward

### GNSS
- [ ] Enabled / disabled
- [ ] Location auto-update
  - [ ] Enabled / disabled
  - [ ] Default precision (0–7, higher is more precise)

### Local UX & power
- [ ] Button functions
- [ ] Silent mode
- [ ] Power schedule
- [ ] Time / date

### BLE security
- [ ] Pairing bonds: view / rename / delete
- [ ] Enter BLE pairing mode
- [ ] Set a PIN for the next pairing session

## 3. Device Actions (over BLE)

- [ ] Reboot — only reachable bundled into factory reset, not as its own action
- [ ] Sleep / power-down
- [ ] Enter USB DFU mode
- [ ] Enter wireless DFU mode
- [x] Factory reset
- [ ] Send advertisement/beacon now — the phone can broadcast *its own* identity
  from Discover; asking the device to beacon is not exposed
- [x] Find this device — locate alert (beep/flash), cancelled from the phone, by
  a button press on the device, or by its own timeout
- [ ] Backup Configuration (omits private keys)
- [ ] Restore Configuration (omits private keys)

## 4. Phone-Local Settings

- [ ] Default hop count
- [ ] Default region (or no region)
- [ ] Default channel

## 5. Peer Management

### Lists
- [x] View/list saved peers
	- [x] ordering selectable: alphabetic, heard recently, or latest messages
	- [ ] filterable by role, capability, favorite, etc. — role filter, text
	  search, and a favorites group exist; capability is not a filter
	- [ ] Display as list or on a map — the list is done; Map is a placeholder
	  with no map rendering
- [x] View/list transient peers (peers that have given us their full address but
  aren't on our peer list. They may have sent us a unicast message or it could be from an identity announcement)
- [x] Add a saved peer
	- [x] specified manually via URI or public key
	- [x] promoting a transient peer to saved
- [x] Remove a saved peer
- [x] Discover new peers

### Peer properties (observed)
- [x] Identity information, if any
  - [x] Official name
  - [x] Role
  - [x] Capabilities
  - [ ] Callsign
  - [x] Location — shown as a value; no map view
- [x] Saved status
- [x] Last seen
- [x] Last-seen hop count
- [x] Last contacted date
- [x] Current source route
- [ ] Blinding channel in use, if any
- [ ] PFS session status

### Peer settings (user-assigned)
- [x] Alias
- [ ] Permissions
- [x] "Shared with UMSH Device" — saved separately to this phone and to the
  companion radio's device identity
- [ ] Notify on received message — notifications are global, not per-peer
- [x] Favorite / unfavorite
	- [x] Favorited peers get a star in the upper-right corner of their icon.
- [ ] Group membership (organizational / ACL)
- [ ] Manually set source route
- [ ] Which blind unicast channel to use, or none (joined channels only)

### Peer actions
- [ ] Initiate / end a PFS session
- [x] Request an identity data update
- [ ] Discover a source route — an observed route is displayed, but there is no
  action to probe for one

## 6. Conversation Management

- [x] View existing text conversations
- [x] Start a new text conversation with a peer
- [x] Sorted by most recent activity. Unread messages should indicate in the row somehow.
- [ ] Select/Change a channel for a conversation
- [ ] Participate in existing text conversations
	- [x] Send messages
	- [ ] Emote messages sent to you
	- [ ] Reply to messages sent to you
	- [x] Edit a previously sent message
	- [x] Delete a previously sent message
	- [ ] Properly display all of the above
- [x] Delete an existing text conversation
- [x] See metadata about a specific received message (hop count, routing path, etc.)

## 7. Channel Management

Channels are joined per-identity. The phone identity and the companion radio's
device identity keep independent channel sets with independent keys; a channel
present in both is a convention, not a shared object.

`public` and `EMERGENCY` are joined on first run with notifications off, and
can be left; leaving keeps the record so the join flow can offer them back.

- [x] List channels (both local and device) — device membership is listed by
  the identifiers it reports; a channel whose key this phone lacks is shown but
  cannot be named
- [x] Join a channel (Public channels with a name, private channels with a URI)
- [x] Leave a channel
- [x] Create a new private channel
- [ ] Configure a channel
  - [x] Region
  - [x] Alias
  - [x] Local, device, or both — which identity has joined the channel: the phone,
    the companion radio's device identity, or each of them separately
  - [ ] Allow other members to request identity and public key — no layer scopes
    identity requests per channel yet; the responder would have to filter on the
    channel a request arrived on before this can be offered

## 8. Channel Group Chat

Locally-joined channels only. Group chat is the phone identity participating, so
device-joined channels are out of scope by construction.

- [x] Group chat channels are displayed alongside uncast chats in the conversations tab, not in a separate sheet or section. Groups chats are subject to the same ordering rules: new messages push conversations to the top.
- [x] Join a channel group chat — joining from Settings is membership alone; a
  conversation is created on request, or automatically when joined through the
  conversations tab. `public` always has one while joined.
- [x] Participate in a channel group chat
- [x] Leave a channel group chat — removes the local transcript and keeps
  channel membership
- [x] Request the identity of a group chat participant — sent over the channel,
  filtered to the member's hint, routed by what their own frames showed
- [x] See metadata about a specific received group message (hop count, routing path,
  node hint, etc.)
