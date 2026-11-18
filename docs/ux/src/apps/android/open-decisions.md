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
scanner, which hands a recognized code to the import preview as a bottom sheet
over the screen the scan started from. When iOS gets an in-app scanner it takes
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
the communicator's amber in both schemes. Under dynamic color it is harmonized
toward the wallpaper, not replaced, so it stays amber.

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

### Storage-unavailable wording

The iOS screen tells the user that reinstalling the previous version restores
everything. On Android that is not possible without uninstalling first, which
erases the database and, unlike iOS, the identity with it.

**Recommendation:** the Android copy says not to uninstall or clear storage,
that doing so also erases the identity, and that an update fixing the error
restores everything. **Clear storage** in system settings leads to the app's
manage-space screen (batch 3), not a wipe.

## Conversations

### The blocked composer keeps the field

When sending is impossible, iOS replaces the text field with the reason and a
button, so the draft is hidden until the radio returns. The guidelines ask
that a draft stay and that Send look blocked and explain itself.

**Recommendation:** Android keeps the field and the draft editable. Send is
drawn blocked, and a line above the field gives the reason and the way out
(Connect radio, Radio settings); tapping Send explains in an alert. iOS
adopts the same so a long draft never disappears under a banner.

### The thread header carries no subtitle

Batch 1's thread placeholder had a subtitle ("Chat · heard 2 min ago"). iOS
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
after Notifications, because it governs what this phone sends there. The
channel page in batch 4 shows the same two settings, since there is one record
per channel. Notifications already appears on both pages this way. iOS adds
the section to its conversation page as well.

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

## Protocol and core changes

### Several regions on a channel

A channel today holds at most one region, and in practice none reaches the
air: iOS saves a channel's region, but the core's channel registration carries
only the hop limit, so no channel send is tagged. Supporting any number of
regions, including none, takes these changes. None changes the wire format,
because the Region Code option (11) already repeats, and a repeater forwards
when any listed region matches.

1. **Channel URIs** (`uri-formats.md`): `r` may repeat, one parameter per
   region. Repetition is used instead of a list separator because a region
   name may contain any character.
2. **MAC send options** (`umsh-mac` `SendOptions`): `region_code` becomes a
   list, written as one Region Code option per entry. A repeater's own region
   insertion stays single, as the spec requires.
3. **Mobile core:** a channel's registration carries its region list beside
   its hop limit, and every send in the channel applies both.
4. **iOS:** the channel's `regionCode` becomes a list. Its Region text field
   becomes the chip editor described above. A stored single region becomes a
   one-item list.

**Cost:** each region adds 3 bytes to every message sent in the channel: one
byte of option header and the 2-byte code. **Recommendation:** no fixed limit
on the number of regions. The fragmentation estimate, when it is designed,
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
