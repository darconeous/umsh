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
permission, host decision) use the warning container; failures (connection
failed, transmission rejected, data load failed) use the error container. The
icon and the wording carry the difference, never the tint alone.

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
    > and its message details may record it.
    >
    > The direct-conversation header and Peer Detail state the session in
    > text: **Establishing PFS…**, **PFS active · expires in 24 min** or
    > **PFS active · until restart**, **Ending PFS…**, or a specific failure
    > or **Session ended after restart**. Peer Detail shows **Standard
    > encryption** when there is no session.
