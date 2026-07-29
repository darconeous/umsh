# UMSH iOS App — Feature Wishlist 2026-07-27

## 1. Device Connection & Pairing

The underlying primitive: **connect to any UMSH device over BLE for configuration,
independently of which device (if any) is currently this phone's companion radio.**

- Discover and connect to a UMSH device for configuration/setup.
  - Works on an unconfigured device (first-time provisioning) and on an
    already-configured one (revisit/adjust).
  - Works while another companion radio is actively paired and connected, so
    stand-alone devices can be set up in the field.
- Update/Change settings individually or from a pre-configured template for mass commissioning. 
- Promote a connected device to this phone's companion radio.

Guided setup flows built on top of that primitive:

- Set up a new device as a **tracker**.
- Set up a new device as a **repeater**.
- Set up a new device as this phone's **companion radio**.

## 2. Device Configuration (over BLE)

### Identity & presence
- Name
- Role
- Mobile / fixed
- Location
- Advertisements
  - Send advertisement on boot
  - Broadcast interval (default: 4 hours)
  - Include full key in advertisement (default: false)
  - Channel used for automatic advertisements
- Channel membership — the channels the *device identity* has joined. Used for the device's own advertisements, blind unicast addressing, and repeater filtering. Not used by the phone identity.

### Radio
- Regional presets
- LoRa settings (custom overrides to regional presets)
- Duty cycle requirements (Custom overrides to regional presets)
- Amateur radio operation
  - Mode (Unlicensed, Licensed-Only, Hybrid)
  - Callsign

### Repeater
- Enabled / disabled
- Supported regions
- Default region
- Minimum RSSI to flood-forward
- Minimum SNR to flood-forward

### GNSS
- Enabled / disabled
- Location auto-update
  - Enabled / disabled
  - Default precision (0–7, higher is more precise)

### Local UX & power
- Button functions
- Silent mode
- Power schedule
- Time / date

### BLE security
- Pairing bonds: view / rename / delete
- Enter BLE pairing mode
- Set a PIN for the next pairing session

## 3. Device Actions (over BLE)

- Reboot
- Sleep / power-down
- Enter USB DFU mode
- Enter wireless DFU mode
- Factory reset
- Send advertisement/beacon now
- Backup Configuration (omits private keys)
- Restore Configuration (omits private keys)

## 4. Phone-Local Settings

- Default hop count
- Default region (or no region)
- Default channel

## 5. Peer Management

### Lists
- View/list saved peers
	- ordering selectable: alphabetic, heard recently, or latest messages
	- filterable by role, capability, favorite, etc. 
	- Display as list or on a map
- View/list transient peers (peers that have given us their full address but
  aren't on our peer list. They may have sent us a unicast message or it could be from an identity announcement)
- Add a saved peer
	- specified manually via URI or public key
	- promoting a transient peer to saved
- Remove a saved peer
- Discover new peers

### Peer properties (observed)
- Identity information, if any
  - Official name
  - Role
  - Capabilities
  - Callsign
  - Location (Option to view on map)
- Saved status
- Last seen
- Last-seen hop count
- Last contacted date
- Current source route
- Blinding channel in use, if any
- PFS session status

### Peer settings (user-assigned)
- Alias
- Permissions
- "Shared with UMSH Device"
- Notify on received message
- Favorite / unfavorite
	- Favorited peers get a star in the upper-right corner of their icon.
- Group membership (organizational / ACL)
- Manually set source route
- Which blind unicast channel to use, or none (joined channels only)

### Peer actions
- Initiate / end a PFS session
- Request an identity data update
- Discover a source route

## 6. Conversation Management

- View existing text conversations
- Start a new text conversation with a peer
- Participate in existing text conversations
	- Send messages
	- Emote messages sent to you
	- Reply to messages sent to you
	- Edit a previously sent message
	- Delete a previously sent message
	- Properly display all of the above
- Delete an existing text conversation
- See metadata about a specific received message (hop count, routing path, etc.)

## 7. Channel Management

Channels are joined per-identity. The phone identity and the companion radio's
device identity keep independent channel sets with independent keys; a channel
present in both is a convention, not a shared object.

- List channels (both local and device)
- Add a channel
- Delete a channel
- Configure a channel
  - Region
  - Alias
  - Local, device, or both — which identity has joined the channel: the phone,
    the companion radio's device identity, or each of them separately
  - Allow other members to request identity and public key

## 8. Channel Group Chat

Locally-joined channels only. Group chat is the phone identity participating, so
device-joined channels are out of scope by construction.

- Join a channel group chat
- Participate in a channel group chat
- Leave a channel group chat
- Request the identity of a group chat participant
- See metadata about a specific received group message (hop count, routing path,
  node hint, etc.)* 
