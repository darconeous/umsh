# Android Open Decisions

Design questions raised while drawing the Android app. Each has a
recommendation; the drawings and [product structure](product-structure.md)
already follow it, so approving a batch approves the recommendations it
depends on unless one is called out.

## Shell and navigation

### Where the radio control sits in the top app bar

The plan's starting point made the radio control the first trailing action.
Screens have different numbers of actions, so a control placed first moves from
screen to screen, and putting it after the overflow menu breaks Android's
habit of keeping overflow last.

**Recommendation:** put it at the very end of every top app bar, where Google's
apps keep the account avatar: app-level, always in the same place, opening a
page about something other than the current screen. Screen actions and the
overflow menu come before it. The pill has a fixed width, so a state change
never shifts the actions beside it.

### Where the radio control sits on tablets and foldables

With two panes, putting the control in either pane's top app bar makes it look
as if it belongs to that pane, and it would move between destinations that have
one pane (Map) and those that have two.

**Recommendation:** wherever the rail is shown (600 dp and wider), the radio
control is the rail's header, above the destinations. The rule is tied to the
navigation component, not to the device: bottom bar means top app bar, rail
means rail header. This needs a custom navigation suite
(`NavigationSuiteScaffoldLayout`) rather than the default one.

### Where the problem banner sits on rail layouts

The guideline places the banner "immediately below the top toolbar". On rail
layouts there is no app-wide toolbar, only one per pane.

**Recommendation:** span the content area beside the rail, at its top, above
both panes. It stays app-level and never looks like part of a pane. See
[Reconciling the shared chapters](#reconciling-the-shared-chapters) for the
guideline wording.

### Rail width and the Conversations label

The standard 80 dp `NavigationRail` cannot fit **Conversations** at 12 sp
without clipping. Shortening the label to "Chats" would break the shared
destination names.

**Recommendation:** use Material 3's `WideNavigationRail` in its collapsed
form, 96 dp wide, which fits the full name. Phones keep the standard 80 dp
`NavigationBar`, whose items are wide enough.

### The unread badge on Conversations

The guidelines and the iOS product structure specify a badge counting unread
conversations, but the iOS app as built shows no tab badge.

**Recommendation:** Android shows the badge, counting conversations with unread
messages, never messages, and iOS adds the same badge so the two apps match.

### Navigation bar on pushed pages

**Recommendation:** keep the bar on pushed pages (peer page, settings pages) so
switching destinations stays one tap away, and hide it on conversation threads,
full-screen dialogs, and the QR scanner, where the bottom edge belongs to the
composer or the screen's own controls. This matches iOS, which hides the tab
bar only in threads.

### The phone's battery beside the radio's

On a phone the system status bar's battery icon sits directly above the radio
control's battery glyph, and both are the same vertical battery shape.

**Recommendation:** keep the Material battery glyphs, inside the tonal pill and
always after the link glyph, so the pair reads as one radio status rather than
as a second phone battery. Check it in the first usability pass on hardware;
if people still confuse them, the fallback is the horizontal battery glyphs.

### Radio Detail outside the destinations

**Recommendation:** the radio control opens Radio Detail as an app-level page
above the shell, outside every back stack, so opening it never changes the
selected destination and Back returns to where the user was. Settings keeps its
own **Companion radio** entry, inside the Settings stack.

### A linked peer opens above whatever was showing

iOS opens a tapped or scanned peer link as a sheet over the current screen.
Android has no sheet that holds a whole peer page well, and pushing it onto the
Peers stack would switch destinations under the user.

**Recommendation:** open it as an app-level page above the shell with Close
and Back, the Android counterpart to the iOS sheet. Its verbs navigate into the
destinations as usual.

### The QR scanner's place

**Recommendation:** **Scan** (`qr_code_scanner`) is a top app bar action on the
Conversations and Peers roots, beside Search. Both open the same app-level
scanner, which hands a recognized code back to the screen the scan started
from, handled there as typed text (an unsaved node's in the import preview, as
a bottom sheet; see product-structure, "QR scanner"). When iOS gets an in-app scanner it takes
the same place, in the same two toolbars.

### Settings on tablets opens a page

**Recommendation:** Settings opens with Your identity in the detail pane, since
an empty pane beside a settings list reads as a missing page. Conversations and
Peers show a quiet placeholder until something is opened.

## Visual language

### Dynamic color and the fallback scheme

Every device the app supports (API 31 and later) has dynamic color.

**Recommendation:** use dynamic color for all chrome with no in-app switch to
turn it off. Keep one fallback scheme for previews, screenshot tests, and the
drawings, taken from the communicator firmware's palette
(`crates/umsh-ux-communicator/src/theme.rs`):

- **Dark** is the communicator's own colors on Material 3 roles. Its
  background, chrome, panel, field, menu, and inbound grays are the surface
  containers from lowest to highest. Its accent `#4DA3FF` is primary, its
  outbound blue `#2A62C9` the primary container, its focus blue `#18304D` the
  secondary container (the selected row and navigation indicator), and its
  forward-secrecy violet `#A585FF` tertiary.
- **Light** extrapolates the same hues at light-theme tones: cool blue-gray
  surfaces from `#F7F9FC`, primary `#2A62C9`, and the violet as `#7045CC`.

Every text pairing in both schemes clears 4.5:1. If the app should look like
the communicator on every phone rather than follow the wallpaper, the
alternative is to make this scheme the only one; revisit that only if the
dynamic version feels like it loses the UMSH look.

### A warning role for banners

Material 3 has no warning color, and the attention banners need one that
dynamic color cannot turn into something else.

**Recommendation:** add one role, a warning container and its text color, from
the communicator's amber in both schemes: `#FFE9C2` in light and `#3A2A0E` in
dark. The same pair is used under dynamic color. Harmonizing it toward the
wallpaper, still amber, waits for a port of Material's color utilities to
Compose.

### Sent-bubble colors

A sent message and the send button are blue, green, or violet by who can read
the message: encrypted, an open channel, or forward secret. These are fixed
colors, not theme roles, and the same in light, dark, and dynamic color. iOS
uses `systemBlue` (`accentColor`, since the app sets no accent), `systemGreen`,
and `#7045CC`; the communicator uses `#2A62C9`, `#1E7B45`, and `#7045CC`. White
text reaches 5.7:1, 5.3:1, and 6.2:1 on the communicator's colors, but only
2.2:1 on `systemGreen` and 3.7:1 to 4.0:1 on `systemBlue`.

**Recommendation:** Android uses the communicator's three. iOS adopts the same
two it differs on, so a message looks the same on every UMSH screen. Batch 2
draws the bubbles.

### Banner tones

Material 3 has no banner component, and dynamic color makes tints unpredictable.

**Recommendation:** attention states (no radio, disconnected, Bluetooth off,
permission) use the warning container; failures (connection failed,
transmission rejected, data load failed) use the error container. The icon and
the wording carry the difference, never the tint alone.

### Material 3 Expressive

**Recommendation:** use baseline Material 3 components where the two differ,
with the one exception of the wide rail above. Expressive's motion and shape
morphing can be adopted later without redrawing, since the layouts do not
depend on them.

### Contrast of the Public and EMERGENCY badges

iOS draws them with `systemBlue` and `systemRed`, which change between light
and dark appearance (`#007AFF`/`#0A84FF` and `#FF3B30`/`#FF453A`); the
communicator, dark only, uses the dark pair. White text reaches only 3.4:1 to
4.0:1 on these, below the 4.5:1 that derived badges are moved to clear.
`channel-badges.md` names the colors but gives no values.

**Recommendation:** give the two badges sRGB values in `channel-badges.md`,
shared by every platform, that clear 4.5:1 against white: for example
`#0062CC` (5.8:1) and `#D70015` (5.4:1). Until then Android draws iOS's pair
for each appearance, so all three match.

### Very dark avatars on a dark surface

A peer whose hint bytes make a near-black fill nearly disappears against the
dark theme's surface, and its outline, which carries the node's kind, goes with
it. The lettering still reads.

**Recommendation:** no change on Android alone: the canonical rule says only
the outline changes, and a theme-dependent stroke would make the same peer look
different across apps. If it proves a problem in practice, add a rule to
`peer-identity-and-sessions.md` for both apps, such as a hairline in the
surface's outline-variant color whenever the fill's contrast against the
surface falls below a threshold.

### Emoji-only channel titles

A channel named only an emoji needs a title. iOS shows the name as written.
Naming the emoji ("🔥" as **Fire**) needs CLDR's emoji annotations, which
`android.icu` does not expose.

**Recommendation:** a flag's title is its region code, as `channel-badges.md`
gives it (🇫🇷 is **FR**), which reads the same in every locale. Any other
emoji-only name is its own title, as on iOS. Short names come later, on both
platforms at once, if the annotations are bundled.

### Storage-unavailable wording

The iOS screen tells the user that reinstalling the previous version restores
everything. On Android that is not possible without uninstalling first, which
erases the database and, unlike iOS, the identity with it.

**Recommendation:** the Android copy says not to uninstall or clear storage,
that doing so also erases the identity, and that an update fixing the error
restores everything. **Clear storage** in system settings leads to the app's
manage-space screen (batch 3), not a wipe.

## Conversations

### Reactions the system font can't draw

🩷 leads the reaction palette but needs Emoji 15.0, which Android 12 and 13
fonts lack; without Play services they never download it.

**Recommendation:** where the font has no glyph for 🩷, its chip and TalkBack
label show ❤️, and the stored reaction is unchanged. Bundling an emoji font
(`emoji2-bundled`) costs about 10 MB.

### The blocked composer keeps the field

When sending is impossible, iOS replaces the text field with the reason and a
button, so the draft is hidden until the radio returns. The guidelines ask
that a draft stay and that Send look blocked and explain itself.

**Recommendation:** Android keeps the field and the draft editable. Send is
drawn blocked, and a line above the field gives the reason and the way out
(Connect radio, Radio settings); tapping Send explains in an alert. iOS
adopts the same so a long draft never disappears under a banner.

### The thread header carries no subtitle

A subtitle such as "Chat · heard 2 min. ago" could sit under the title. iOS
shows only the avatar and title, and tapping either opens the info page.

**Recommendation:** match iOS. Presence from routing or recent traffic is weak
evidence; it belongs on the peer page, worded as such, not as a standing claim
in every thread.

### How an unnamed channel sender is labeled

iOS names a channel sender by saved name, then the name they gave, then the
first 10 characters of their address, then "Member" and the node hint. The
conversation list uses the first 6 characters of the address. Neither prefix
is a form the shared presentation rules define, and the hint already is the
address's prefix.

**Recommendation:** after the saved name and the name they gave, both apps
show "Member" and the node hint (for example "Member BtC5"), in the thread and
the list alike. The full address stays on the member sheet.

### Bubbles join instead of having tails

iOS bubbles have tails on the last of a run. Android's messaging apps instead
round every corner and tighten the corners where a run continues.

**Recommendation:** Android uses grouped corners, with no tails, and keeps
iOS's spacing: tight within a run, wider between runs.

### Reaction chips at the bubble's bottom edge

iOS places reaction chips over the bubble's top outer corner, where they can
cover the end of the message above.

**Recommendation:** Android places them across the bottom edge, on the side
toward the screen's middle, where Android users expect them and where they
never cover another message.

### Editing in the composer

iOS edits a message in a sheet with Cancel and Save.

**Recommendation:** Android loads the message into the composer under an
"Editing message" strip, with a check to save and a close button to cancel,
so writing always happens in the same place. The 4-hour limit is unchanged.

### Message details as a page

**Recommendation:** a full page pushed in the thread's stack, with iOS's
sections and wording. On tablets it opens in the detail pane over the thread.

### No unread count on Back

iOS's Back button in a thread counts unread conversations elsewhere ("99+").
Android's Back is an arrow with no label, and badging it is not an Android
pattern.

**Recommendation:** no count on Android. Notifications and the list's badge
already say that something else needs attention.

### Mark as read on message notifications

iOS's message notifications offer only Reply.

**Recommendation:** Android offers Reply and Mark as read, the pair Android's
messaging apps use. iOS adds Mark as read as well.

### Hiding notification contents on the lock screen

The guidelines ask for an in-app option to hide sender and content on the
lock screen. iOS has none and relies on the system's Show Previews.

**Recommendation:** Android adds the option in notification settings (batch
5). Message notifications are always private with a public version, so the
system setting already works; the option forces the public version. iOS adds
the same option.

### Warning before a message needs several frames

The guidelines ask the composer to estimate fragmentation and warn before a
message needs several frames. Neither app does yet.

**Recommendation:** leave it out of batch 2 and design it once for both apps,
since the estimate comes from the shared core. The long-draft board shows
where it would appear.

### Floating conversation bubbles

**Recommendation:** no Android Bubbles (floating chat heads) in the first
release. The notifications carry the shortcut and metadata Bubbles need, so
they can be added later without redesign.

### Channel routing on the conversation page

iOS edits a channel's region and hop limit on the channel page, under Local
Details, beside its alias. The conversation page has neither.

**Recommendation:** a Routing section on the channel conversation page, right
after Notifications, because it governs what this phone sends there. This is
the only place routing is edited: the channel page in batch 4 holds the
channel's details, alias, sharing and leaving, and no routing. iOS adds the
section to its conversation page as well. The section waits on
[several regions on a channel](#several-regions-on-a-channel).

Regions are input chips plus an **Add region** chip that opens a dialog. The
dialog takes the same text as iOS and the repeater settings: a short code, an
agreed name, or a raw `0x` code. The hop limit is an exposed dropdown with
Default and 1 to 15. On public and EMERGENCY, where the protocol fixes it, the
limit is a plain value.

### Region suggestions for a channel

Repeater settings can propose regions from a position. A channel could do the
same from the phone's location.

**Recommendation:** not in v1. A channel's regions describe how far its
messages should reach, which is the members' agreement, not where this phone
happens to be.

## Onboarding and identity

### No preset or completion step

The plan lists five onboarding steps: welcome, identity, radio, preset, and
ready. They come from `ios/product-structure.md`, which also describes a
Learn How It Works page, a restore choice, and a host takeover sheet. The iOS
app as built has two steps. Welcome names the identity, which already exists,
and asks for a name. Connect a Radio pairs one radio or is skipped. Then the
app opens on Conversations. The radio's preset belongs to the radio and is set
in device setup and Radio Detail (batch 5).

**Recommendation:** match the built app. A preset step would ask a new user a
regulatory and PHY question before they have sent anything, for a radio that
usually arrives configured. A completion screen adds a tap and has nothing to
decide. The iOS chapter is corrected to match (item 11 under "Reconciling the
shared chapters").

### No identity restore

**Recommendation:** onboarding offers no restore and no recovered identity.
Android has nothing like iOS's Keychain, which keeps the key after the app is
deleted, and the identity export format has no implementation yet. A restore
choice appears once identity export exists, before the public release.

### An in-app radio list with board photos

iOS's AccessorySetupKit picker shows each radio's board photo, chosen by the
model identifier the radio advertises in pairing mode. Android's
CompanionDeviceManager picker cannot show one. Its only icon setter,
`setDeviceIcon` (API 36.1), is a 24 dp icon for self-managed associations,
not a photo in the discovery list.

**Recommendation:** Connect a radio scans for itself and lists radios in
pairing mode, each with its board photo from the shared board list
(`docs/hardware/boards.json`, the same photos iOS bundles). An unknown model
gets the radio glyph. Tapping a row hands that one radio to
CompanionDeviceManager as a single-device request, which asks the user to
confirm it and keeps device presence and background wake-up working. The
model identifier is recorded at pairing, so Radio Detail and the saved-radio
picker (batch 5) can show the same photo once the radio has left pairing
mode and stopped advertising it.

**Cost:** the app needs `BLUETOOTH_SCAN`, declared with `neverForLocation`.
It is in the same Nearby devices group as `BLUETOOTH_CONNECT`, so the user
sees one prompt either way. This changes the plan's statement that
CompanionDeviceManager does discovery and that no scan permission is needed.

### Nearby devices when Connect a radio opens

**Recommendation:** opening the step asks for Nearby devices, because the
list cannot fill without it. Then it raises the Bluetooth request if
Bluetooth is off. If either is refused, the page shows the reason and one
button (Allow or Turn on) in place of the list. Android's own wording
explains the request; the page behind it already says what it is for.

### A re-imagined Your identity page

iOS's identity page is one long list: the QR code and printed link, the name
field and an Advertise button, the schedules, the default hop limits, location,
storage, and both erasures, each section with a footer.

**Recommendation:** Android draws a new page, and iOS later follows it.
- **The top says who this phone is:** avatar, name, and address (tap to
  copy). Under it are four actions, as on a contact card: QR code, Share,
  Advertise, and Edit name. The QR code opens a sheet with a large code;
  the link is never printed. QR code uses `qr_code`, leaving
  `qr_code_scanner` to Scan; Advertise uses `wifi_tethering`, the broadcast
  glyph every Discover and Announce action shares.
- **Announcements:** what nearby nodes learn. Discoverable, the beacon and
  identity schedules, and location sharing with its precision. Each row
  states its current value, so the page needs no footers.
- **Key:** the key protection and Erase identity.
- **Moved out, because neither is about this identity:**
  - Reach, the default hop limits, moves to routing settings.
  - Start over moves to Settings › Storage.

  Both are drawn in batch 5. Start over also stays on the manage-space screen.

### Key protection on the identity page

**Recommendation:** the Key section names what Android reported when the
wrapping key was created: Security chip (StrongBox), Secure area (TEE), or
Software only. It has no caption. A caption would have to say how the key is
held, which is mechanism, or that it is never exported and is lost with the
app, which identity export will change.

### Copy that identity export would make untrue

Several iOS lines state today's limits as if they were permanent:
- Welcome says the key "never leaves the device".
- The Storage caption says the key is "never displayed or exported".
- Start over's second ask says "Nothing is backed up".
- Connect a Radio says nothing is sent or received without a radio, which IP
  multicast would change.

**Recommendation:** Android leaves these out and says only what an action
does. iOS drops them too.

### Precise location

The plan asks only for approximate location. But location sharing offers
areas down to centimeters, and setting a repeater to this phone's position
needs a real fix. Android's approximate location is only good to a few
kilometers.

**Recommendation:** ask for precise location, which Android always offers
with approximate as a choice. Ask when Share location is turned on, or when a
device is set to this phone's position. With approximate only, the
precision choices stop at about 9.8 km, and a line offers to allow precise.
Whether background location is needed depends on how announcements run
without the app on screen, which is decided with the foreground service in
Phase 2.

### Failures that won't fix themselves

Saving the name is a local write, so if it fails, storage itself is in
trouble. Asking the user to try again doesn't help.

**Recommendation:** a failure that won't clear on its own opens a dialog. It
says what happened, then the reason Android gave, and has Copy details and
OK. Whatever the user typed stays in place. The same dialog serves every
failure of this kind across the app.

### When the identity can't be opened

Android's keystore can fail in two ways: for a while (not ready, or an error
it may not repeat), or for good (the key invalidated or missing, or the
stored file failing its check). Making a new identity over one that still
exists would lose it for nothing.

**Recommendation:** each replaces the whole app on Storage unavailable's
layout.
- **Identity unavailable** offers nothing and tries again the next time the
  app comes to the foreground. A failure Android does not classify counts as
  this state.
- **Identity can't be opened** shows Android's error with Copy details, and
  **Erase identity** behind the usual confirmation. Erasing makes this phone a
  new node and opens Welcome; messages and peers stay in the store.

The app never erases or replaces an identity on its own.

### Welcome copy and Learn more

**Recommendation:** Welcome says "This phone has its own identity, separate
from the radio—let's get it set up!" Under it, Learn more about UMSH opens
umsh.dev in a Custom Tab. That is the only explanation onboarding offers; the
site can change without an app update.

### Manage space

**Recommendation:** the manage-space screen offers Erase identity and Start
over with the same confirmations they have in the app. It shows what uses the
space, so the person who came to free storage sees what each choice removes.
Afterwards it closes back to the system page. Unlike erasing from inside the
app, it makes no new identity: the next launch starts from Welcome, as it
would after Clear storage.

## Peers and channels

### Sort and filter as chips

Batch 1's Peers board said sort and filter would belong to the search bar. iOS
keeps them in a toolbar menu, where the current sort and filter are hidden
until the menu is opened.

**Recommendation:** a row of chips under the top app bar on the Peers root,
kept on the search screen. The first chip opens the sort menu and names the
current sort; the others are single-choice role filters. The filter names are
shortened from iOS: **People** for "People & text" and **Repeaters** for
"Repeaters & bridges". What each matches is unchanged. The row scrolls
sideways on narrow phones.

### Long press instead of swipe actions on peer rows

iOS rows swipe one way to favorite or save and the other way to remove.

**Recommendation:** a long-press menu with Favorite (or Save for an unsaved
node), Share, and Remove peer. Two-way swipe actions are an iOS idiom. On
Android a swipe usually dismisses, and removing a peer always asks first.
Batch 2's conversation swipe is unchanged; it is a dismissal.

### Renaming a peer

iOS edits the peer's name in place, in the header.

**Recommendation:** tapping the name, which carries an edit mark, opens a
**Rename** dialog. The line under the field is what the node calls itself,
using batch 2's "Calls itself" wording. An empty name falls back to it.
Android has no editable large title, and an always-editable header invites
accidental edits.

### No snackbar for copies on Android 13 and later

**Recommendation:** copying an address or link shows nothing of the app's own
on Android 13 and later, where the system shows its own copy confirmation. On
Android 12 and earlier it shows a snackbar: "Address copied" or "Link copied".

### Full-screen dialogs keep the radio control

The manual path editor and channel creation are full-screen dialogs. Material
puts the confirming action, such as Save, at the end of the top app bar, which
is where the radio control always sits.

**Recommendation:** the confirming action comes just before the radio
control, as screen actions do everywhere else. The radio control never moves,
and the dialog hides only the navigation bar.

### Add peer and Discover are pages

iOS presents Add Peer and Discover Peers as sheets. The exchange is pushed
inside the Add Peer sheet.

**Recommendation:** both are pages in the Peers stack.
- Their rows open peer pages, and the exchange pushes onto Add peer, so Back
  and predictive back work through them.
- A completed exchange replaces Add peer and the exchange with the new peer's
  page, so Back leads to the Peers list.
- Being asked to exchange stays a sheet, over Add peer.

### More ways into the scanner

Batch 1 placed **Scan** on the Conversations and Peers roots.

**Recommendation:** the Add peer and Join channel fields also get a scan
button, opening the same scanner. What a code opens, and where, does not
change. These are the two places where the person is already holding
something to scan. The Global actions table in the product structure lists
them.

### The channel page and Conversation info

iOS has one channel page, holding the routing and the membership. Batch 2
approved Conversation info with Routing and a header row that "leads to the
channel itself".

**Recommendation:** keep two pages.
- **Conversation info** is about what this phone sends and keeps. It holds
  Notifications, Routing, and the message history.
- **The channel page** is the channel itself: its details, alias, Share, and
  Leave channel. It is reached from that header row and from Settings ›
  Channels.

There is no member list, so the header row's caption in Conversation info
reads "Alias, sharing, and leaving the channel".

### The radio's own channels are left out

iOS lists the channels the radio's own identity has joined and lets each
channel page switch membership for the phone and the radio separately.

**Recommendation:** the channel screens cover only this phone's channels. They
show no radio-only list, no "Joined by" switches, and no phone or radio scope
on rows. The radio's channels will be managed separately, later.

### A name already in use is a suggestion

**Recommendation:** joining a channel whose name matches a different channel
shows a note, not a warning. It says the two are different channels and
suggests another name. Join works as it is, and the alias stays optional.

### Creating a channel opens it

iOS closes the sheet after creating a channel and shows no invitation.

**Recommendation:** Create opens the new channel's page, so Share is one tap
away. The invitation sheet puts its warning before the code, which is the
disclosure the [sharing chapter](../import-discovery-sharing.md) asks for
before an invitation is shared.

### iOS copy shortened

**Recommendation:** these iOS lines are cut to what the reader needs:
- the private-channel disclosure before Create;
- the footer for channels only the radio holds;
- the public and private notes in the join preview;
- Discover's footers.

The cuts drop mechanism and keep every security consequence. Strings that
iOS words the same way everywhere, such as dialogs and errors, are kept word
for word.

## Map, radio, and management

### The node list is a sheet, and filters are chips

iOS draws its own card over the map with three heights, and keeps the filters
in a toolbar menu.

**Recommendation:** a standard bottom sheet with the same three heights on
phones, which never covers the navigation bar, and a side sheet in the list
pane's place on expanded widths. The filters are three chips over the map, as
on Peers: Show, Heard, and Capabilities. A chip that differs from the default
is filled, so the header no longer needs to name the filters, though it still
does for TalkBack.

### No node card on the map

iOS's UX chapters describe a summary card for the selected node with a **View
node** button. The built app has none: selecting a node moves its row to the
top of the list.

**Recommendation:** follow the built app. Tapping a pin or a row selects the
node; tapping the selected row opens its peer page, and a row's long press
has **Details**. A card would repeat the row it sits above.

### Open in maps app

iOS offers **Show in Maps…**, which opens Apple Maps.

**Recommendation:** **Open in maps app** hands a `geo:` link to whatever map
app the phone has, or asks which one when there are several.

### Radio Detail follows the iOS spec

The built iOS screen starts with a Connection list and a long caption for each
link state. It shows no battery, board photo, or model, and its many buttons
sit in one list.

**Recommendation:** Android draws the screen the
[iOS spec](../ios/product-structure.md) describes, and iOS follows later:
- **The top:** the board photo, name, model, state, and battery with its age.
- **Two buttons:** Disconnect and Forget, as on Android's own Bluetooth device
  page.
- **Sections:** Manage device, then Mesh radio, Connection, Offline assistance
  (iOS's Host provisioning), Radio identity, and Maintenance.

The state captions are left out; the state and the problem banner say enough.

### Setting up the radio

The plan listed a host takeover screen, and the built iOS app still shows a
radio's host, with **Set Up for This Phone** and **Replace Existing Host…**
when the radio holds no host or another one.

**Recommendation:** the app sets up whichever radio it connects to for this
phone, every time, without asking. Radio Detail shows no host row, no host
state, and no takeover control, and Manage device is never locked for it. A
radio that cannot be set up is a failed connection like any other: its reason
and **Reconnect**. iOS drops the same controls.

### Forgetting a radio

iOS words its Forget confirmation for the accessory picker and for Bluetooth
Settings, neither of which Android has.

**Recommendation:** "Forget this companion radio?" with "The app stops
reconnecting to this radio and releases it. The radio keeps its own pairing
until you pair it again." Forgetting also removes the radio's association. As
on iOS, the radio's host key is cleared first.

### Device setup on Android

**Recommendation:** iOS's flow and form, with three changes:
- It is a full-screen flow over the shell, not a sheet.
- Each new device gets its own one-device association before pairing, as
  agreed in batch 3, using the same scan list with board photos.
- The result replaces the form instead of covering it. iOS's "Congrats,
  you've successfully set up your repeater!" becomes **Repeater set up**.

### Management screens keep iOS's behavior and lose its footers

iOS's categories carry long footers that explain each setting.

**Recommendation:** keep iOS's behavior: values edit in place; **Refresh**
becomes **Apply**; leaving with changes asks first; and over the mesh nothing
is read until Refresh. Keep every confirmation and error word for word. Drop
the explanatory footers: what a footer warns about is either confirmed before
it happens or follows from the value. Each screen keeps one line saying how
fresh its values are.

The top app bar's subtitle names the device, since Manage device can be open
for several devices in different stacks.

### The Settings overview follows the iOS spec

The built iOS Settings tab has Identity, Radio, Devices, and Region database.

**Recommendation:** the spec's order, under four headers: Identity (Your
identity, Channels), Radios (Companion radio, Set up a device), Mesh (Routing,
Region database), and This app (Notifications, Storage, Diagnostics, About
UMSH). Region database is a row of information, as on iOS, with no page.

### Notifications in Settings

**Recommendation:** one row per Android notification channel (Direct
messages, Channels, EMERGENCY, Radio connection, and Problems), each opening
the system page for its channel, where sound and importance are set. The page
also holds **Hide contents on the lock screen** (batch 2) and a link to all of
UMSH's notification settings. With notifications off for the app, a card at
the top says so, with **Turn on**.

### Diagnostics and About are new

The iOS spec asks for diagnostics with a redaction preview and an About page.
iOS has neither.

**Recommendation:**
- **Diagnostics:** versions; the radio's capabilities, by name; a radio log;
  and **Share diagnostics…**. Its preview leaves out addresses, locations, and
  message text until each is turned on, and never includes keys.
- **About UMSH:** the version, umsh.dev, and the open-source licenses.

iOS adds both. The radio log and the shared file need the core change below.

### iOS copy shortened

**Recommendation:** these iOS lines are cut to what the reader needs:
- the place sources' details in region suggestion;
- the setup goals' details;
- the empty states on the map;
- Radio Detail's state captions;
- the management footers (see above);
- the Wi-Fi password footer.

Dialogs and errors keep iOS's words. The one exception is the Reach warning,
titled "More than 10 hops?" instead of "Warning".

## Protocol and core changes

Batch 4 adds no protocol or core changes. Batch 5 adds no protocol changes,
and one core change:

### A diagnostics log

Diagnostics needs a bounded log of radio and session events and a way to export
it with chosen kinds of detail left out. Neither app keeps one today.

1. **Mobile core:** keep a fixed-size ring of recent events: link state
   changes, ULCP errors, and frame accounting. Store each event's addresses,
   locations, and message text as separate fields, so an export can leave each
   kind out.
2. **Mobile core:** export the ring and the versions as one file, given the
   kinds of detail to include. Keys are never in the ring.
3. **Both apps:** the Diagnostics page and its share preview.

### Several regions on a channel

A channel today holds at most one region, and in practice none reaches the
air: a channel's region is stored, but the core's channel registration carries
only the hop limit, so no channel send is tagged. Supporting any number of
regions, including none, is decided and deferred (2026-11-21). It gates the
Routing section of the channel conversation page on both apps; until it
lands, Android builds that page without the section.

It is a protocol change and gets its own review when picked up:

- **Region Code (option 11) carries a list.** Its value becomes one or more
  2-byte region codes (n × 2 bytes), and a sender puts all its regions in one
  option. The first region costs 3 bytes (option header and code), each
  further one 2.
- **To settle then:** whether a receiver still accepts repeated option-11
  entries (receiver tolerance suggests reading every entry, from one option or
  several); an odd-length value (dropped with accounting); a sender's maximum
  count; and the repeater rules, which stay as they are (never rewrite an
  existing code; never add one to a packet that has any).
- **Affected:** `packet-options.md`, the routing chapters where they speak of
  several options, the MAC's encoder and every region matcher (repeaters
  included), the Wireshark dissector, and the firmware.

Then, in order:

1. **The spec change** above.
2. **MAC send options** (`umsh-mac` `SendOptions`): `region_code` becomes a
   list, written into one Region Code option, with the matchers to read it.
3. **Mobile core:** a channel's registration carries its region list beside
   its hop limit, and every send in the channel applies both.
4. **Store:** a channel's regions become a list, a step on the store's
   migration ladder. A stored single region becomes a one-item list.
5. **Channel URIs** (`uri-formats.md`): one `r` parameter whose regions are
   separated by `:`. A `:` inside a region name needs an escape that survives
   percent-decoding (for example a doubled `::`, since a region name is never
   empty), settled when the work starts.
6. **Both apps:** the Routing section's chip editor described above.

**Recommendation:** no fixed limit on the number of regions beyond the
sender maximum the spec sets. The fragmentation estimate, when it is designed,
counts these bytes like any other.

## Reconciling the shared chapters

The shared chapters still describe three destinations, with a map inside
**Network**, and a PFS ring on peer avatars. Both apps have four destinations,
and PFS shows as a bubble color. These edits bring the chapters in line; they
are not made yet.

1. **`mobile-guidelines.md`, "Stable information architecture":** replace "The
   compact mobile interface has three top-level destinations:" and its table
   with:

   > The compact mobile interface has four top-level destinations, in this
   > order:
   >
   > | Destination | Contains | Does not contain |
   > |---|---|---|
   > | **Conversations** | Direct messages, multicast channels, chat rooms, drafts, unread state | Node administration and raw packet logs |
   > | **Peers** | Known nodes, contacts, repeaters, sensors, rooms, discovery | A second copy of active conversations |
   > | **Map** | Nodes with usable location, with their reported precision and age | Nodes without a location |
   > | **Settings** | User identity and its channels, radios, regions and radio presets, notifications, storage, diagnostics | Frequently used send or discovery actions |

2. **Same section:** replace "Network is broader than Contacts." with "Peers
   is broader than Contacts.", and replace the paragraph beginning "Map is a
   presentation of Network" with:

   > Map shows the same nodes as Peers, placed where they report themselves.
   > It is always present; with no located nodes it says so and offers
   > discovery. A map must show the precision and age of reported positions
   > and must not turn a coarse location cell into a misleading exact pin.

3. **`mobile-guidelines.md`, "Reveal trust at the decision point":** "across
   Conversations, Network, maps, details, and notifications" becomes "across
   Conversations, Peers, Map, details, and notifications".
4. **`mobile-guidelines.md`, "Global actions":** "reachable from both
   Conversations and Network" becomes "reachable from both Conversations and
   Peers".
5. **`mobile-guidelines.md`, "Radio status always includes power state":**
   after "immediately below the top toolbar and above the screen title or
   content", add:

   > Where the platform's navigation is a side rail and the screen has one
   > toolbar per pane, the slot spans the content area beside the rail, above
   > every pane.

6. **`ios/product-structure.md`, "App-wide shell":** replace the three-item
   tab list with four: Conversations (`bubble.left.and.bubble.right`; badge is
   unread conversations, not raw packets), Peers
   (`point.3.connected.trianglepath.dotted`; no badge for routine discovery),
   Map (`map`; no badge), Settings (`gearshape`; a badge only for an actionable
   radio, identity, or migration problem). "The companion status is not a
   fourth tab" becomes "The companion status is not a tab".
7. **`ios/product-structure.md`, "Peers map":** move the section out of the
   Peers tab into its own "Map tab" section, and drop the List/Map choice in
   the Peers toolbar, which the app no longer has.
8. **`ios/mockups.md`, "Review legend":** the note on the tab strip should say
   the shipping tab bar is **Conversations · Peers · Map · Settings**, not
   Conversations · Peers · Channels · Settings.
9. **`peer-identity-and-sessions.md`, "Avatar shape":** "Anything drawn around
   the avatar, such as a state ring or a map marker's border" becomes
   "Anything drawn around the avatar, such as a map marker's border".
10. **`peer-identity-and-sessions.md`, "PFS status on peer avatars":** retitle
    it "PFS status" and replace the paragraph, table, and the paragraph after
    it with:

    > PFS belongs only to a direct relationship with a peer. It never changes
    > the peer's avatar, which looks the same with or without a session. A
    > message sent under a PFS session is drawn in the forward-secrecy bubble
    > color, distinct from ordinary encrypted messages and from open channels,
    > and its message details may record it. No header, badge, or page
    > states whether a session is held; text names PFS only where a choice
    > depends on it, such as resending a message first sent under one.

11. **`ios/product-structure.md`, "First launch and onboarding":** replace
    the four steps with what the app does. Welcome shows the identity
    already created, named by its hint, and asks for an optional name.
    Connect a Radio pairs a radio or is skipped with Set Up Later. Then the
    app opens on Conversations, with `public` and `EMERGENCY` joined and
    muted. Replace the Learn How It Works action with a Learn more about UMSH
    link to umsh.dev. Remove the restore choice until
    identity export is implemented, the host takeover sheet, and step 4
    ("Radio preset and readiness"). The radio's preset is set in device setup
    and Radio Detail.
