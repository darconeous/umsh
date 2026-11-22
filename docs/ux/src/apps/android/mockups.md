# Android Screen Mockups

The approved mockups are the specification for every Android screen. No Compose
code is written for a screen until its section here is approved, and a built
screen that needs to depart from its approved drawing comes back for review
first, with the drawing updated to match.

Navigation, panes, and app-level chrome are specified in
[Android product structure](product-structure.md). Questions raised while
drawing are in [Android open decisions](open-decisions.md).

## Reading the drawings

- One SVG per feature, boards in a row: the title above each board, notes below.
- Boards are drawn at device size in dp: phones at 412 × 915, tablets at
  1280 × 800, an unfolded foldable at 841 × 701, and a medium-width window at
  701 × 841.
- App chrome uses the fallback color scheme. On a device it takes dynamic color
  from the wallpaper, so hues will differ; roles will not.
- Peer avatars, channel badges, and hint colors are drawn by their canonical
  rules; the sample hints and names are made up, apart from the four canonical
  examples.
- A dashed box marks content that a later batch draws.

## Review status

| Batch | Section | Status |
|---|---|---|
| 1 | [A. Design language](#a-design-language) | Approved 2026-11-17 |
| 1 | [B. Avatars and channel badges](#b-avatars-and-channel-badges) | Approved 2026-11-17 |
| 1 | [C. Navigation bar, rail, and back](#c-navigation-bar-rail-and-back) | Approved 2026-11-17 |
| 1 | [D. Radio control and problem banner](#d-radio-control-and-problem-banner) | Approved 2026-11-17 |
| 1 | [E. List-detail on tablets and foldables](#e-list-detail-on-tablets-and-foldables) | Approved 2026-11-17 |
| 1 | [F. Storage unavailable](#f-storage-unavailable) | Approved 2026-11-17 |
| 2 | [G. Conversation list](#g-conversation-list) | Approved 2026-11-18 |
| 2 | [H. Threads](#h-threads) | Approved 2026-11-18 |
| 2 | [I. Bubbles, delivery, and the message menu](#i-bubbles-delivery-and-the-message-menu) | Approved 2026-11-18 |
| 2 | [J. Replies and reactions](#j-replies-and-reactions) | Approved 2026-11-18 |
| 2 | [K. Composer](#k-composer) | Approved 2026-11-18 |
| 2 | [L. Conversation info](#l-conversation-info) | Approved 2026-11-18 |
| 2 | [M. Notifications](#m-notifications) | Approved 2026-11-18 |
| 2 | [N. Conversations on tablets](#n-conversations-on-tablets) | Approved 2026-11-18 |
| 3 | [O. Onboarding](#o-onboarding) | Approved 2026-11-18 |
| 3 | [P. Adding a radio](#p-adding-a-radio) | Approved 2026-11-18 |
| 3 | [Q. Permissions](#q-permissions) | Approved 2026-11-18 |
| 3 | [R. Your identity](#r-your-identity) | Approved 2026-11-18 |
| 3 | [S. Manage space](#s-manage-space) | Approved 2026-11-18 |
| 4 | [T. Peers list](#t-peers-list) | Approved 2026-11-18 |
| 4 | [U. Peer page](#u-peer-page) | Approved 2026-11-18 |
| 4 | [V. Ping and Route](#v-ping-and-route) | Approved 2026-11-18 |
| 4 | [W. Manual path](#w-manual-path) | Approved 2026-11-18 |
| 4 | [X. Repeaters and Discover](#x-repeaters-and-discover) | Approved 2026-11-18 |
| 4 | [Y. Add peer and import](#y-add-peer-and-import) | Approved 2026-11-18 |
| 4 | [Z. Exchanging contacts](#z-exchanging-contacts) | Approved 2026-11-18 |
| 4 | [AA. QR scanner](#aa-qr-scanner) | Approved 2026-11-18 |
| 4 | [AB. Sharing](#ab-sharing) | Approved 2026-11-18 |
| 4 | [AC. Channels](#ac-channels) | Approved 2026-11-18 |
| 5 | [AD. Map](#ad-map) | Approved 2026-11-18 |
| 5 | [AE. Place picker](#ae-place-picker) | Approved 2026-11-18 |
| 5 | [AF. Region suggestion](#af-region-suggestion) | Approved 2026-11-18 |
| 5 | [AG. Radio Detail](#ag-radio-detail) | Approved 2026-11-18 |
| 5 | [AH. Choosing a radio](#ah-choosing-a-radio) | Approved 2026-11-18 |
| 5 | [AI. Setting up a device](#ai-setting-up-a-device) | Approved 2026-11-18 |
| 5 | [AJ. Remote management](#aj-remote-management) | Approved 2026-11-18 |
| 5 | [AK. Remote management, continued](#ak-remote-management-continued) | Approved 2026-11-18 |
| 5 | [AL. Settings](#al-settings) | Approved 2026-11-18 |

# Batch 1: Design language and shell

Batch 1 fixes the visual language every later batch uses, so it is reviewed and
approved before the others are drawn in detail.

## A. Design language

[![Design language mockups: color roles in light and dark, the fixed colors on both surfaces, the type scale, and the shape scale](mockups/design-language.svg)](mockups/design-language.svg)

- **Color:** Material 3 dynamic color for chrome. The fallback scheme comes from
  the communicator firmware's palette: its own colors in dark, the same hues
  extrapolated to light. No in-app theme picker.
- **Warning:** one role added to Material's set, the communicator's amber, for
  attention banners.
- **Fixed colors:** peer avatars, channel badges, and sent bubbles never take
  theme color. Public and EMERGENCY follow iOS's light and dark pair. A sent
  bubble is blue, green, or violet by who can read it, the same in every theme.
- **Type:** the system sans at the Material 3 scale; the system monospace for
  addresses, hints, and hex.
- **Shape:** the Material 3 corner scale for containers; the canonical outlines
  for avatars and badges, outside that scale.

## B. Avatars and channel badges

[![Avatar and badge mockups: the canonical peer avatar examples and sizes, the sent-bubble tints that show PFS instead, channel badges with their titles, and conversation and peer rows in light and dark](mockups/avatars-and-badges.svg)](mockups/avatars-and-badges.svg)

- Drawn from [Peer Identity](../peer-identity-and-sessions.md) and
  [Channel Badges](../channel-badges.md) without restyling: fill, lettering,
  outline, and text color all follow the canonical rules.
- Sizes: 32 dp in a top app bar, 40 dp in a list, 56 dp on a card, 96 dp at the
  top of a page.
- Avatars carry no session state. PFS shows as the violet of a bubble sent under
  a PFS session, as on iOS and the communicator. Text names PFS only where a
  choice depends on it, such as resending a message first sent under it.

## C. Navigation bar, rail, and back

[![Navigation mockups: Conversations and Peers roots with the bottom bar in light and dark, a pushed peer page keeping the bar, a thread hiding it, predictive back from a thread, and the wide rail at medium width](mockups/navigation.svg)](mockups/navigation.svg)

- Four destinations in the iOS order, as a bottom bar under 600 dp and a rail
  from 600 dp.
- The Conversations item badges the count of conversations with unread
  messages.
- Roots carry **Search** and **Scan**; the radio control is always the last
  thing in the top app bar.
- Threads hide the bar; other pushed pages keep it.
- Back is predictive, and a destination's stack is kept when switching away.

## D. Radio control and problem banner

[![Radio control and banner mockups: every radio control state in light and dark with its TalkBack label, every problem banner in light and dark, and the banner on a Conversations root and in a thread](mockups/radio-control.svg)](mockups/radio-control.svg)

- The control is a fixed-width tonal pill holding the link glyph and the power
  glyph, so screen actions never shift as the radio's state changes.
- A cached battery reading is dimmed; its age is in the banner and the TalkBack
  label.
- The banner sits in the app-level slot under the top app bar, with one action.
  Bluetooth off and the Nearby devices permission are Android's own banners.

## E. List-detail on tablets and foldables

[![List-detail mockups: Conversations on a tablet with a thread open, Peers on a tablet with nothing open and the radio banner, and Settings on an unfolded foldable](mockups/list-detail.svg)](mockups/list-detail.svg)

- `ListDetailPaneScaffold` for Conversations, Peers, and Settings from 840 dp.
- On rail layouts the radio control lives in the rail's header and the banner
  spans the content area, so neither belongs to a pane.
- An empty detail pane shows the destination's icon and one line; Settings
  opens on Your identity instead.

## F. Storage unavailable

[![Storage unavailable mockups in light and dark](mockups/storage-unavailable.svg)](mockups/storage-unavailable.svg)

- Replaces the whole app: no navigation, radio control, or banner.
- The copy is adapted to Android, where uninstalling also erases the identity
  and an older build cannot be installed over a newer one.
- **Copy details** puts the error on the clipboard.

# Batch 2: Conversations

Drawn from the iOS app as built. Where Android departs from it, the board's
notes say so and [open decisions](open-decisions.md#conversations) explain why.

## G. Conversation list

[![Conversation list mockups: the list with every preview kind, empty and loading states, search with results and with none, the new-chat sheet, swipe to delete, and the two delete confirmations](mockups/conversation-list.svg)](mockups/conversation-list.svg)

- One list for direct and channel conversations, newest first, with iOS's
  previews: "You:", the channel sender, "Draft:", "Message deleted", and
  "No messages yet".
- **New chat** is an extended FAB opening a sheet with iOS's two ways in.
- Search is full screen and grouped as on iOS. It finds conversations, peers,
  joined channels, and heard nodes, not message text.
- Swiping a row away asks first: Delete for a direct conversation, Leave for a
  channel chat, with iOS's wording.

## H. Threads

[![Thread mockups: a direct thread, a channel thread with senders and a gap, jump to latest, an empty thread, and the EMERGENCY certification sheet](mockups/threads.svg)](mockups/threads.svg)

- The top app bar holds Back, the avatar and title, and the radio control.
  There is no subtitle, and tapping the title opens conversation info.
- Threads hide the navigation bar; the composer owns the bottom edge.
- A time line appears after an hour's gap. Channel runs are named above and
  carry the sender's avatar.
- A gap of missing messages is a tappable placeholder.
- EMERGENCY asks for certification before the first action after each launch.

## I. Bubbles, delivery, and the message menu

[![Bubble mockups: delivery captions, message kinds in dark, the long-press reactions and menu, delete and resend confirmations, and message details for a sent and a received message](mockups/bubbles.svg)](mockups/bubbles.svg)

- Received bubbles use the surface container. Mine are the fixed blue, green,
  or violet.
- Runs join with tight corners instead of tails.
- Delivery is a caption in iOS's words, in sentence case. The two failures are
  red, with a retry button.
- Long press shows the reaction bar and a menu. Delete is "Delete for
  everyone".
- Resending a message first sent under PFS offers to send it without forward
  secrecy, the one place text names PFS.
- Message details is a full page with iOS's sections.

## J. Replies and reactions

[![Reply and reaction mockups: swipe to reply, the composer while replying, quotes in bubbles, jumping to a quoted message, and reaction chips](mockups/replies-reactions.svg)](mockups/replies-reactions.svg)

- Swipe or Reply puts a quote strip in the composer. A sent reply carries its
  quote inside the bubble.
- Tapping a quote jumps to the original and highlights it briefly.
- Reaction chips sit across the bubble's bottom edge. Mine is filled with the
  conversation's color; one that failed is faded.

## K. Composer

[![Composer mockups: empty, typing in each security color, while the radio reconnects, blocked with no radio, a long draft, editing, and the not-sent alert](mockups/composer.svg)](mockups/composer.svg)

- Send appears only when there is text, in the color the message will be
  sent in.
- While the link is transient, Send is dimmed and waits.
- With no radio, the draft stays editable and Send shows blocked. A line above
  the field gives the reason and the way out. Nothing is queued.
- Editing happens in the composer under an "Editing message" strip.

## L. Conversation info

[![Conversation info mockups: a channel conversation's page with its routing, the EMERGENCY variant, adding a region, the hop limit menu, the clear confirmation, and the channel member sheet](mockups/conversation-info.svg)](mockups/conversation-info.svg)

- A channel conversation has its own page, as on iOS; a direct conversation's
  title opens the peer page (batch 4).
- **Routing** limits what this phone sends in the channel: any number of
  regions, or none, and a maximum hop count. Public and EMERGENCY keep the
  protocol's fixed 10 hops.
- **Clear all messages** erases only this phone's history and keeps the
  conversation.
- A channel sender's avatar opens a member sheet with **Request identity**
  for someone not saved.

## M. Notifications

[![Notification mockups: message notifications in the system shade, inline reply, the states of the ongoing radio notification, the private lock screen, and failure notices](mockups/notifications.svg)](mockups/notifications.svg)

- The boards show Android's own shade and lock screen; the app has no
  notification list of its own.
- Messages use MessagingStyle conversations with the canonical avatar or
  channel badge, and offer Reply and Mark as read.
- The radio's ongoing notification is silent. It always states the power
  state and opens Radio Detail.
- The lock screen version hides sender and content. iOS's failure notices are
  kept word for word.

## N. Conversations on tablets

[![Tablet conversation mockups: the list and an open channel thread in light, and the same with the radio disconnected in dark](mockups/conversations-tablet.svg)](mockups/conversations-tablet.svg)

- The batch 1 list-detail layout with a thread in the detail pane. Its top app
  bar has no Back; the overflow holds conversation info.
- The banner spans both panes, and the composer blocks Send as on a phone.

# Batch 3: Onboarding and identity

Drawn from the iOS app as built, with Android's own pairing, permissions, and
key storage. Where Android departs from it, the board's notes say so and
[open decisions](open-decisions.md#onboarding-and-identity) explain why.

## O. Onboarding

[![Onboarding mockups: the welcome page with its learn-more link and name field, with the keyboard, and with the save failure dialog; the connect-a-radio step searching, with radios and their board photos, connecting, failed, and without the Nearby devices permission; and the first conversation list with the notification prompt](mockups/onboarding.svg)](mockups/onboarding.svg)

- Two steps, as on iOS: Welcome, then Connect a radio. The identity exists
  before Welcome appears, and Welcome asks only for an optional name.
- **Learn more about UMSH** opens umsh.dev in the browser.
- A failure that won't fix itself, such as the name not saving, opens a dialog
  with what happened and why.
- Connect a radio lists radios in pairing mode with their board photos, as
  iOS's picker does. Tapping one adds it; **Set up later** skips.
- Onboarding ends on Conversations with Public and EMERGENCY joined and
  muted. There is no preset or completion step.

## P. Adding a radio

[![Radio pairing mockups: the Nearby devices permission, the Bluetooth request, the system confirmation for the chosen radio, and the pairing dialog for a PIN and for a compared code](mockups/radio-pairing.svg)](mockups/radio-pairing.svg)

- Opening Connect a radio asks, only as needed, for Nearby devices and to turn
  on Bluetooth. Tapping a radio raises Android's confirmation for it, then the
  pairing dialog.
- The system dialogs are drawn for order and wording, not exact appearance.

## Q. Permissions

[![Permission mockups: when each permission is asked and what refusing it does, the camera prompt and the scanner after a refusal, the location prompt with its precise and approximate choice, the precision choices with approximate location only, and the identity page after a refusal](mockups/permissions.svg)](mockups/permissions.svg)

- Each permission is asked by the action that needs it: Nearby devices when
  Connect a radio opens, notifications after the first radio connects, the camera when
  the scanner first opens, precise location when sharing is turned on or a
  device is set to this phone's position.
- Refusing never blocks the rest of the app, and the same button opens
  system settings once Android stops asking.

## R. Your identity

[![Identity mockups: the redesigned Your identity page at the top and with location shared, the QR code sheet, editing the name, advertising, the precision choices, the key protection values, the Erase identity confirmation, and the page on a tablet](mockups/identity.svg)](mockups/identity.svg)

- Re-imagined rather than ported; iOS follows later. The top shows the
  avatar, name, and address, with four actions: **QR code**, **Share**,
  **Advertise**, and **Edit name**.
- **Announcements** holds what nearby nodes learn; **Key** holds the key
  protection Android reported and **Erase identity**.
- Reach and Start over move out of this page (batch 5).

## S. Manage space

[![Manage space mockups: the system storage page with Manage space in place of Clear storage, UMSH's storage screen, and Start over's two confirmations there](mockups/manage-space.svg)](mockups/manage-space.svg)

- UMSH declares a manage-space screen, so the system storage page offers
  **Manage space** instead of Clear storage.
- The screen offers Erase identity and Start over with their usual
  confirmations, then closes back to the system page. Start over asks twice.

# Batch 4: Peers and channels

Drawn from the iOS app as built, with the iOS peer-page redesign. Where Android
departs from it, the board's notes say so and
[open decisions](open-decisions.md#peers-and-channels) explain why.

## T. Peers list

[![Peers mockups: the list with its sort and filter chips, the sort menu, search with saved and discovered nodes, the long-press menu, the remove confirmation, and the empty state](mockups/peers-list.svg)](mockups/peers-list.svg)

- iOS's sections: Favorites, Saved, and the companion radio's own identity,
  then **Discover peers**.
- Sort and the role filters are chips under the top app bar, so the current
  choice is always visible. They stay on the search screen.
- Search finds every known node, saved first, then nodes heard but not saved.
- Long press offers Favorite, Share, and Remove peer. Remove keeps iOS's
  choices and wording.

## U. Peer page

[![Peer page mockups: a chat peer at the top and scrolled to the end, a repeater, a node that never advertised, a node opened from a link, renaming, and the page in the Peers list-detail layout on a tablet](mockups/peer-page.svg)](mockups/peer-page.svg)

- The iOS redesign: name, verbs, the Heard / Route / Distance strip, the map
  card, Notifications, About, then Clear all messages and Remove peer.
- Verbs follow advertised capabilities, never role. A node that never
  advertised gets every verb, led by **Identify**.
- An unsaved node shows **Add to Peers**. A link opens the page above the
  shell, with Close.
- Tapping the name opens **Rename**; the line under the field is what the node
  calls itself.

## V. Ping and Route

[![Ping and Route mockups: the Ping sheet with a reply, waiting, and with no reply, and the Route page for a learned route and for a held manual path](mockups/ping-route.svg)](mockups/ping-route.svg)

- Ping is a bottom sheet that sends as it opens: round trip, hops, the reply's
  path with each leg's signal, **Reset route**, and this visit's earlier pings.
- Route is a page with the numbered path, what the next send will do, **Ask
  near this node**, and Reset route or **Clear manual path**.
- An unmatched router hint has the lookup button; a named repeater opens its
  page.

## W. Manual path

[![Manual path mockups: the editor, a direct path, adding a hop from a repeater's neighbors, entering a router hint, two hints that fit, discarding changes, and the learned-path prompt in a thread](mockups/manual-path.svg)](mockups/manual-path.svg)

- Edit on Route opens the editor as a full-screen dialog: hops drag and are
  removed, **Then flood** runs Off to 15, **Ping along path** tests the
  unsaved path, and the hold runs 30 minutes to 1 day.
- **Add hop** offers the previous hop's neighbors or the known repeaters, and
  **Enter router hint** takes a Base58 prefix or 4 hex digits.
- Leaving with changes asks first. The learned-path prompt keeps iOS's rules
  and wording.

## X. Repeaters and Discover

[![Mockups for a repeater's neighbors, read and unanswered, and for Discover peers, listening, asking near a node, and the announce confirmation](mockups/repeaters-discover.svg)](mockups/repeaters-discover.svg)

- **Neighboring repeaters** reads one page per Refresh, with Load more;
  opening it sends nothing.
- **Discover peers** is a page in the Peers stack: ask, a live list of nodes
  heard since it opened, and **Announce my identity** with a confirmation.

## Y. Add peer and import

[![Add peer mockups: the page with nearby devices, the identity field and your code, without a radio and with a link that does not parse, and the import preview signed and unsigned](mockups/add-peer.svg)](mockups/add-peer.svg)

- The Add peer FAB pushes a page: Nearby first, then the identity field with
  its scan button, then **Show your code**.
- Every node link, typed, opened, or scanned, goes through the same import
  preview: a bottom sheet with the advertised details, their signature
  status, and a local name, ending in **Save peer** or **Message**.

## Z. Exchanging contacts

[![Contact exchange mockups: being asked, waiting, comparing codes, after Same, codes that differ, the unsaved peer afterward, and the nearby glyphs](mockups/nearby-exchange.svg)](mockups/nearby-exchange.svg)

- The iOS flow on Android pages: being asked is a sheet over Add peer; the
  exchange is pushed in the Peers stack.
- Same and Different sit at the bottom. The new peer's page replaces the
  exchange, so Back never returns to the code.

## AA. QR scanner

[![QR scanner mockups: scanning, a code that is not a UMSH code, a node code opening the import preview over Peers, and a channel code opening the join preview over Conversations](mockups/qr-scanner.svg)](mockups/qr-scanner.svg)

- One scanner, full screen above the shell, opened by **Scan** on the
  Conversations and Peers roots and by the scan button in the Add peer and
  Join channel fields.
- Only `umsh:` codes are accepted; anything else is reported as **Not a UMSH
  code** while scanning continues.
- A recognized code opens its preview as a bottom sheet over the screen the
  scan began on.

## AB. Sharing

[![Sharing mockups: sharing a peer, the Android Sharesheet, the system's copy confirmation, and your own code from Add peer](mockups/share.svg)](mockups/share.svg)

- Sharing a peer reuses Your identity's QR sheet: code, address, **Copy
  link**, and **Share**, which opens the Android Sharesheet.
- On Android 13 and later the system confirms a copy, so the app shows
  nothing of its own.

## AC. Channels

[![Channel mockups: the channels list, the add menu, the empty state, creating a private channel, joining by name or invitation with each preview, the channel page, leaving, the invitation sheet, and the list-detail layout on a tablet](mockups/channels.svg)](mockups/channels.svg)

- **Settings › Channels** lists the channels this phone has joined. The FAB
  offers **Join channel** and **New private channel**.
- Join channel takes a name or an invitation and previews it without joining.
  A key already held updates its details; a name already in use gets a
  suggestion to choose another, never a requirement.
- The channel page holds the channel's details, alias, Share, and Leave
  channel. Routing stays in Conversation info.
- Nothing here concerns the radio's own channels, which will be managed
  separately.
- A private channel's invitation shows its warning before the code.

# Batch 5: Map, radio, and management

Drawn from the iOS app as built. Where the built screen is weaker than the iOS
spec, as with Radio Detail and the Settings overview, the drawing follows the
spec instead. Where Android departs from iOS, the board's notes say so and
[open decisions](open-decisions.md#map-radio-and-management) explain why. No
screen in this batch shows or edits the radio's own channel list.

## AD. Map

[![Map mockups: the map with its node list at the peek height, a selected node, the capability filter, a row's long-press menu, the two empty states, and the map on a tablet with the list as a side sheet](mockups/map.svg)](mockups/map.svg)

- MapLibre, with every node that reports a position as its avatar on a pin.
  The companion radio's own fix is **This radio**.
- A cell is drawn only when it is coarse, reported by a router, or selected.
  Router-reported and unverified positions carry iOS's badges.
- The node list is a standard bottom sheet on phones and a side sheet on
  tablets. Selecting a pin or a row flies to the node and lifts its row.
- iOS's filter menu becomes three chips: Show, Heard, and Capabilities.

## AE. Place picker

[![Place picker mockups: choosing a place with its cell, after the phone could not find itself, and without a precision](mockups/place-picker.svg)](mockups/place-picker.svg)

- A full-screen dialog with a fixed crosshair over a panning map. **My
  location** centers on the phone.
- From a device's Identity it shows the cell at the chosen precision; from
  region suggestion it only fills in coordinates.

## AF. Region suggestion

[![Region suggestion mockups: regions suggested from this phone's position, from typed coordinates, and when the position is too coarse](mockups/region-suggestion.svg)](mockups/region-suggestion.svg)

- **Update based on location** in a repeater's routing regions opens
  **Regions for this place**: the place's source, what covers it, and what
  each choice would change.
- **Add** keeps what is listed; **Replace all** drops what does not cover the
  place. Either fills in the editor, which is applied as usual.

## AG. Radio Detail

[![Radio Detail mockups: the companion radio connected, the rest of the page, waiting for the radio, a failed connection, the factory reset confirmation, and Radio Detail on a tablet](mockups/radio-detail.svg)](mockups/radio-detail.svg)

- The board photo, name, model, state, and battery lead, with **Disconnect**
  and **Forget** under them. **Manage device** opens Remote management.
- Then Mesh radio, Connection, Offline assistance, Radio identity, and
  Maintenance, with iOS's confirmations.
- The app sets up whichever radio it connects to for this phone, without
  asking. Radio Detail shows no host and offers nothing to take over; a failed
  connection says why, with **Reconnect**.

## AH. Choosing a radio

[![Mockups for choosing another companion radio: the scan list with board photos and the current radio checked, and the system confirmation for a new one](mockups/radio-picker.svg)](mockups/radio-picker.svg)

- **Choose another radio** opens the scan list from onboarding. A radio not
  yet associated raises Android's confirmation, then pairing.

## AI. Setting up a device

[![Device setup mockups: choosing what the device is for, choosing the device, connecting, the repeater form at the top and further down, the result, and a readback that does not match](mockups/device-setup.svg)](mockups/device-setup.svg)

- **Set up a device** opens a full-screen flow: the goal, the scan list with
  board photos, connecting, then one form and **Set up**.
- Each device gets its own one-device association; this phone's radio stays
  connected and cannot be chosen.
- The result offers **Save to Peers**, **Review all settings**, and **Set up
  another device**. A failed or mismatched write gets the failure dialog.

## AJ. Remote management

[![Remote management mockups: Manage device for a repeater over the mesh, no answer from a device, the Radio category with edits, leaving with changes, the mesh warning before a radio change, the Identity category waiting with a rejected value, Repeater, Power, entering DFU mode, and Manage device for the companion radio on a tablet](mockups/manage-device.svg)](mockups/manage-device.svg)

- **Manage device** leads with the device card, then the categories the
  device reports, in iOS's order, then Maintenance.
- A category edits in place; **Refresh** becomes **Apply** once anything
  changes. Leaving with changes asks first.
- The strip under the top bar shows a spinner while asking and the problem
  when there is one. A rejected value is an error field with iOS's reason.
- Over the mesh, changes that can strand a device confirm first.

## AK. Remote management, continued

[![More remote management mockups: Bluetooth, Wi-Fi, joining a network, Network, Bridge, Peer nodes with a row's menu, and Time](mockups/manage-connectivity.svg)](mockups/manage-connectivity.svg)

- Bluetooth, Wi-Fi, Network, Bridge, Peer nodes, and Time, each with iOS's
  rows and confirmations.
- Joining or editing a Wi-Fi network is a full-screen dialog.
- Peer nodes applies each change at once, so it has no Apply.

## AL. Settings

[![Settings mockups: the overview, Routing and its warning, Notifications, Storage, Diagnostics with the share preview, About, and Settings on a tablet](mockups/settings.svg)](mockups/settings.svg)

- The overview: Identity, Radios, Mesh, and This app. Nothing destructive is
  on it.
- **Routing** holds Reach; **Storage** holds Start over. Both moved out of
  Your identity.
- **Notifications** lists the notification channels and the lock-screen
  option. **Diagnostics** and **About** are new; neither app has them yet.
