# Android Product Structure

This chapter applies the [mobile application guidelines](../mobile-guidelines.md)
to Android phones, tablets, and foldables. It specifies the information
architecture, navigation, and app-level chrome. What each screen looks like is
set by the [Android mockups](mockups.md), once approved.

The Android app is designed as an Android app. Someone who knows the iOS app
should find the same destinations, concepts, verbs, and safety boundaries, but
not the same chrome: layout, density, where actions live, gestures, and back
behavior follow Material 3 and Android conventions.

## Shared with iOS

These do not change between platforms:

- the four destinations, their names, and their order;
- the concepts and their names (the guidelines' terms table), the verbs, and
  the delivery and readiness states;
- what each screen is for and what information it carries;
- each destructive action's own wording and its own confirmation; and
- the canonical rendering of addresses, hints, peer avatars, and channel
  badges ([Peer Identity](../peer-identity-and-sessions.md),
  [Channel Badges](../channel-badges.md)).

## Platform character

- Jetpack Compose and Material 3 components, with Material 3 dynamic color for
  app chrome. Avatars, channel badges, and message bubbles keep the fixed colors
  their canonical rules give them.
- Material Symbols for icons, auto-mirrored in right-to-left layouts except
  where direction is literal (a bearing arrow).
- Edge-to-edge drawing with window insets. The composer follows the IME inset.
- `ModalBottomSheet` where iOS uses a sheet for a short task, a full-screen
  dialog where iOS uses an editing sheet, `AlertDialog` for confirmations,
  long-press `DropdownMenu` for context menus, the Android Sharesheet for
  sharing.
- Font scale, TalkBack, high-contrast text, remove-animations, and switch
  access are supported on every screen. Touch targets are at least 48 dp.

## Destinations

| Order | Destination | Icon | Holds |
|---|---|---|---|
| 1 | **Conversations** | `forum` | Direct and channel conversations, drafts, unread state |
| 2 | **Peers** | `hub` | Known nodes, saved peers, repeaters, discovery, adding peers |
| 3 | **Map** | `map` | Nodes with usable location, and the node cards and list over them |
| 4 | **Settings** | `settings` | Your identity and its channels, the radio, devices, routing, regions, notifications, storage, diagnostics, about |

The selected item uses the filled icon; the others use the outlined one.
Conversations is the start destination.

The Conversations item carries a numbered badge with the count of conversations
that have unread messages, not the count of messages. No other item is badged
for routine activity.

## Navigation shell

The shell is a `NavigationSuiteScaffold`. The navigation component follows the
window width, not the device type:

| Window width | Navigation | Panes |
|---|---|---|
| Compact, under 600 dp (phones, folded foldables) | `NavigationBar` at the bottom | One |
| Medium, 600–839 dp (small tablets portrait, unfolded foldables portrait) | Collapsed `WideNavigationRail` (96 dp) at the start edge | One |
| Expanded, 840 dp and wider (tablets, unfolded foldables landscape, desktop windows) | Collapsed `WideNavigationRail` (96 dp) at the start edge | Two for Conversations, Peers, and Settings; one for Map |

A window resize or a fold change moves between these without changing the
selected destination, the open item, or any draft.

### Back stacks

Each destination owns one Navigation 3 back stack. Stacks survive destination
switches, configuration changes, and process death.

1. Selecting a different destination shows that destination's stack as it was
   left.
2. Selecting the destination already shown pops its stack to its root, and
   scrolls the root to the top if it is already there.
3. Back pops the current destination's stack.
4. Back at the root of Peers, Map, or Settings selects Conversations.
5. Back at the root of Conversations leaves the app.

Back is predictive throughout: the system's back gesture previews the screen
underneath before it is committed, and previews leaving the app at the
Conversations root. A screen that would lose unsaved input on back (a
full-screen editor with changes) asks before discarding instead of taking part
in the preview.

### Where the navigation bar shows

On compact widths the navigation bar shows on each destination's root and on
pages pushed above it. It hides on screens whose bottom edge belongs to their
own input or controls:

- conversation threads, where the composer owns the bottom edge;
- full-screen dialogs (editors such as the manual path editor and channel
  creation);
- the QR scanner; and
- onboarding, Storage unavailable, and the two identity screens, which replace
  the shell.

On medium and expanded widths the rail is always shown alongside the content,
except on the screens that replace the shell.

### Panes on tablets and foldables

Conversations, Peers, and Settings use `ListDetailPaneScaffold`:

| Destination | List pane | Detail pane |
|---|---|---|
| Conversations | Conversation list | The open conversation |
| Peers | Peers list | The open peer page, and what it pushes |
| Settings | Settings overview | The open settings page, and what it pushes |

- On expanded widths both panes show. The list pane keeps a fixed width and the
  detail pane takes the rest. On a foldable the scaffold keeps the hinge
  between the panes.
- On medium and compact widths one pane shows, and the detail pane is pushed
  over the list as on a phone.
- With nothing open, the detail pane shows a quiet placeholder with the
  destination's icon. Settings opens Your identity by default, since an empty
  pane beside a settings list reads as a missing page.
- Back from a detail pane with a deeper page pops that page. Back from the
  detail pane's first page clears the selection; on expanded widths this
  returns focus to the list without hiding it.

Map is one full pane at every width. Its node list is a bottom sheet on compact
widths and a side sheet, in the list pane's place, on expanded ones.

## App-level chrome

### Top app bar

Every screen inside the shell uses `UmshTopAppBar`, a Material 3 top app bar
with three parts:

- **Navigation:** Back (`arrow_back`) on pushed pages; nothing on destination
  roots.
- **Title:** the screen's title, or for a conversation its avatar or badge and
  title.
- **Actions:** at most two screen actions, then an overflow menu when the
  screen has more, then the radio control at the end.

The radio control sits at the end of the bar on every screen, in the place
Google's own apps keep the account avatar, so it never moves as screens add or
remove actions. Screen actions are placed before it.

On medium and expanded widths, where the rail is shown, the radio control moves
out of the top app bar into the rail's header, above the destinations. It is
then in one place for every destination and both panes, and belongs to neither
pane.

### Radio control

The radio control reports the companion radio, never the phone, and always
includes its power state per the guidelines.

- **Visible:** a link glyph followed by a power glyph, in a tonal pill. It does
  not show the radio's name or the word **Connected**.
- **Target:** 48 by 48 dp at least.
- **TalkBack label:** the full state, such as **Companion radio T1000-E,
  connected, battery 78 percent**, with the action **Show radio details**.
- **Action:** opens Radio Detail.

| State | Link glyph | Power glyph |
|---|---|---|
| Connected, battery reading | `sensors` | Battery bars for the level |
| Connected, charging | `sensors` | Battery bars and `bolt` |
| Connected, external power without a level | `sensors` | `power` |
| Connected, level unavailable | `sensors` | `battery_unknown` |
| Connected, radio measures no power state | `sensors` | None |
| Connecting, reconnecting, pairing, synchronizing | `sensors` inside an indeterminate ring | Last reading, dimmed |
| Disconnected, waiting for the radio, Bluetooth off | `sensors_off` | Last reading, dimmed |
| Failed | `error` | Last reading, dimmed |

A dimmed power glyph is a cached reading. Its age is stated in the problem
banner and the TalkBack label (**last battery 78 percent, 12 minutes ago**);
it is never shown as live.

### Problem banner

Disconnected, failed, incompatible, or attention-required radio states add a
banner in a fixed app-level slot:

- on compact widths, directly below the top app bar and above the screen's
  content;
- on medium and expanded widths, across the top of the content area beside the
  rail, above both panes.

The banner belongs to the app, not the screen: it stays in place as screens
change and is never drawn inside a list or a thread. It has an icon, the
problem in one line, the radio's state with its last battery reading and age on
a second line, and one action:

| Problem | Action |
|---|---|
| No radio set up | **Choose radio** (opens the scan list from onboarding; Android confirms a new radio) |
| Radio disconnected or out of reach | **Details** (opens Radio Detail) |
| Bluetooth is off | **Turn on** (the system Bluetooth request) |
| Nearby devices permission denied | **Allow** (asks again, or opens app settings once Android stops asking) |
| Radio failed or rejected a transmission | **Details** |

Recovery removes the banner. A failure to load the app's data uses the same
slot with **Retry**, above any radio banner.

### Radio Detail

Radio Detail opens from the radio control as an app-level page above the
shell, outside every destination's back stack, so opening it never changes the
selected destination. Back returns to the screen it was opened from. It is also
reachable as **Companion radio** in Settings, inside the Settings stack; on
expanded widths it then opens in the Settings detail pane.

## Global actions

Each global action from the guidelines has one place:

| Action | Where |
|---|---|
| Scan a UMSH QR code | **Scan** (`qr_code_scanner`) in the top app bar of the Conversations and Peers roots, and the scan button in the Add peer and Join channel fields |
| Import a pasted or opened `umsh:` URI | Deep link, the Add peer page, and Join channel |
| Share your public identity | Your identity in Settings, and the Add peer flow |
| Create or join a channel | Settings, and the new-chat action in Conversations |
| Find observed nodes | **Discover** in Peers, and on a peer page |
| Inspect and change the radio | The radio control |
| Understand why sending is unavailable | The problem banner, and the blocked Send button |
| Diagnostics | Settings |

### QR scanner

The scanner is one shared action with one flow, reachable from both
Conversations and Peers:

1. **Scan**, or the scan button in the Add peer or Join channel field, opens
   the scanner as an app-level full-screen page above the shell. It asks for
   the camera permission the first time it opens.
2. The scanner accepts only `umsh:` codes. Any other code is reported as not a
   UMSH code, and the scanner keeps running.
3. A recognized code closes the scanner and opens the same import preview a
   pasted or opened URI opens, as a bottom sheet over the screen the scan
   started from.
4. Confirming the preview saves and then navigates as a deep link would.
   Dismissing it returns to the screen the scan started from.

The iOS app has no in-app scanner yet; when it gets one, it takes the same
place.

## Deep links

The app handles the `umsh` scheme through an intent filter, routed as the iOS
app routes `onOpenURL`. Links are held until launch has loaded the store.

1. `umsh:cs:` and `umsh:ck:` are channels. Settings is selected, and the
   channel join preview opens over it.
2. Any other `umsh:` link is looked up as a node.
   1. A link that does not parse opens the import preview, which says what is
      wrong with it.
   2. A link to this phone's own identity selects Settings at Your identity.
   3. Any other node opens its peer page as an app-level page above whatever
      was showing. Back or Close returns there. Its verbs, such as **Message**,
      navigate into the destinations.

### Notification taps

1. A message notification selects Conversations and opens that conversation
   above the list.
2. A notification about a node that sends text messages does the same, opening
   an empty conversation if there is none.
3. A notification about any other node selects Peers and opens its peer page.

## Screens that replace the shell

| Screen | When |
|---|---|
| Storage unavailable | The app database cannot be opened |
| Identity unavailable | Android's keystore fails in a way that can pass |
| Identity can't be opened | The stored identity can never be opened again |
| Onboarding | First launch, until finished |

They draw no navigation component, no top app bar radio control, and no
problem banner. Storage unavailable and both identity screens outrank
onboarding.
