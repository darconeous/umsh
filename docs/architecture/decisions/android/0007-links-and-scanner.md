# ADR 0007: `umsh:` links, one task, and an in-app QR scanner

- Status: Accepted; emulator-verified on API 31 and 36, Pixel unverified
- Phase: 3

iOS routes links in `onOpenURL` and has no in-app scanner; it relies on the
system Camera. Android routes links the same way and leads with a scanner of
its own (product-structure, "QR scanner" and "Deep links").

## Decision

### One route for every link

`MainActivity` takes `umsh:` links through one intent filter: `VIEW`,
`DEFAULT` and `BROWSABLE`, with the scheme only. The app sorts the link,
not the manifest. Notification taps carry their own `umsh-notification`
scheme, which the filter does not match, and `takeRequest` branches on the
scheme before anything else, so a notification never reaches the link route.

`LinkRoute` sorts a link with the core's rules, so the channel prefixes and
the forms a node link takes live in one place (`classify_umsh_link`,
`inspect_peer_identity`):

- **Channel** (`gs:`, `gk:`, and the deprecated `cs:`, `ck:`): Settings ›
  Channels is selected and Join channel opens over it with the link's
  preview. Close returns to Channels. Each opening is a new page, so the
  same link opened again starts over and is looked up again.
- **This phone's own identity:** Settings at Your identity.
- **Any other node:** the core records it unsaved (`record_link_peer`; a
  stored row is left as it is), and its peer page opens above the shell with
  Close. An opened node link is not previewed.
- **Anything else:** the import sheet, holding the link with what is wrong
  with it.

Links in a message take the same route through the same request queue, with
their origin marked as in the app.

`OpenRequests` keeps at most one waiting link and one waiting notification
tap, in arrival order, a newer one of a kind replacing the older. Requests
compare by value: one equal to a request already waiting or being opened is
that request, so a double tap opens once. A link that
arrives before the store is loaded or during onboarding waits in the
activity's saved state, so a rotation or process death keeps it. A taken
link is marked on the intent (`umsh.linkTaken`), because clearing the data
would change the intent's identity.

An intent that carries a link, or that a browser sent (`CATEGORY_BROWSABLE`),
never opens what the app's own extras ask for (a conversation, a node, Radio
Detail, or the debug staging switch), since a web page can put any extras on
a link it opens.

### One instance, one task

`MainActivity` is `singleTask`. A link from another app comes to the running
instance instead of starting a second activity over the same core inside the
other app's task.

Close and Back on a peer page that another app's link opened pop the page and
move the task to the back, so the user is back in the app that opened the
link. A page opened from a link in a message pops back to the thread. Once
the user leaves UMSH any other way (Home, Recents, another app, the screen
turning off, a share target), the link's flow is over and Close returns to
the shell. Beside the other app (split screen, a desktop window) that app is
already in view, so Close and Back return to the shell and the task keeps
its place, rather than moving UMSH out of its split slot (decided
2026-11-24; G-258 still to run).

**The cost:** a link that arrives finishes whatever system activity sits
above the app in its task: a permission dialog, the share chooser, or the
radio pairing confirmation. To make that safe, every permission ask reads an
empty result (a dialog closed under the app) as dismissed, never as refused,
and an interrupted pairing is redone by pairing again. The one automatic
ask, for notifications, closed that way counts as not asked: it comes back
the next time the app is resumed with a radio attached, after it has been
left, not over the link's page (decided 2026-11-24; G-259 still to run).

### The scanner

The scanner is an app-level page above the shell, reached from Scan on the
Conversations and Peers roots and from the scan buttons in the Add peer and
Join channel fields. The scanned code is handed back to where the scan began
through state saved with the back stacks.

- **Libraries:** CameraX 1.6.2 (core, Camera2, lifecycle, the Compose
  viewfinder) and ZXing core 3.5.4, which the app already used to draw codes.
  No native code and no Play services; ML Kit is out for that reason.
  zxing-cpp is the fallback if real decoding is too weak.
- **Pipeline:** a preview and an `ImageAnalysis` at 1280 × 720 with
  `STRATEGY_KEEP_ONLY_LATEST` on its own thread. The Y plane is copied with
  its row stride, every frame is closed, and ZXing's `QRCodeReader` decodes
  with `TRY_HARDER`. Frames are not rotated first; QR finder patterns read in
  any orientation. The use cases are bound to the page's lifecycle and
  unbound when it leaves.
- **What is accepted:** a node code the core reads as a node, or a channel
  code the core reads as a channel. The first accepted code is latched once.
  Anything else, bare addresses and keys included, is "Not a UMSH code", a
  pill that clears after 10 frames in a row without a code, while scanning
  continues.
- **Results:** a code is handled where the scan began, as the same text
  typed there would be. An unsaved node's code opens the import preview
  over that screen; a saved node or the companion radio opens its page, and
  this phone's own code opens Your identity. A channel code opens the
  channel preview over that screen, or, from the Join channel field, fills
  the field and previews inline. Unlike an opened link, an unsaved node's
  code is previewed, because the user has not yet seen what it holds.
- **Keys stay out of saved state:** text holding a private channel key is
  replaced by a process-only handle on its way into any saved state the app
  writes: navigation keys, a waiting scan, a waiting link, and every field
  that can hold an invitation. After process death, an invitation waiting to
  be delivered, or one in a field, is gone. An invitation that arrives as
  another app's link is also the launching intent, which Android itself
  keeps (and a task started from it keeps as its root intent); the app
  cannot seal that copy.

### Camera permission and states

- `CAMERA` is asked the first time the scanner opens, never at launch,
  through the shared permission asker and its "blocked after refusal" rule.
  The grant is checked again on every start, since one-time grants lapse.
- The camera features are declared `required="false"`. With no camera, Scan
  and the fields' scan buttons are not offered.
- A refused permission, or camera access turned off (quick settings, or
  disabled by policy: `ERROR_CAMERA_DISABLED`), shows "Camera access is off
  for UMSH" with Allow camera, which asks again or binds again.
- Any other critical camera error, or no camera to bind, shows the same
  layout with "Camera unavailable" and Try again, which binds again. Allow
  camera would be untrue there: access is not what is wrong.
- The camera in use elsewhere (`ERROR_CAMERA_IN_USE`,
  `ERROR_MAX_CAMERAS_IN_USE`) keeps the camera bound and the viewfinder dark
  until CameraX reopens it. Held for more than about 2 s, "Camera in use by
  another app" shows in the pill's place. The wait is latched: CameraX's
  retries pass through opening, which neither restarts it nor hides the
  line; only the camera opening or failing ends it. The latch is saved, so a
  rotation keeps a line already shown. A camera freed within the grace
  period (the Camera app just closed) says nothing. Other recoverable errors
  are part of opening.
- The torch is offered only when the camera has a flash, and its request is
  applied again each time the camera opens.

## Verification

On the arm64 AVDs `umsh-api31` and `umsh-api36`:

- Links: cold, warm and from another app's task (the Settings app; the AVDs
  have no browser and AOSP Messaging does not linkify `umsh:`), with
  `am start -a VIEW` and no component, so the manifest filter is what
  matches. One activity record throughout; Close and Back return to the app
  the link came from; a page reopened from the launcher closes to the shell.
- A link during onboarding, across a recreation and across a real process
  kill (api36), opens after onboarding. A link that arrives while the camera
  permission dialog is up leaves the ask dismissed, not refused (both
  levels). A browsable intent with the app's extras opens only the link. A
  notification intent never reaches the link route.
- Channel links: a private invitation opened with `am start` on API 31 joined
  a channel created on API 36, and a message went both ways over
  `umsh-bridge` with the LAN group off.
- Scanner: through an injected frame source on both levels (one preview per
  code, the pill, every origin, camera unavailable, no camera); the camera
  permission dialog through UiAutomator on both levels; the real CameraX
  pipeline on API 36 against the emulator's virtual scene with a `umsh:` code
  as its wall poster, decoded in 6–7 s including opening the camera.

Not verified: real cameras, focus and torches; links from Chrome or any app
that linkifies custom schemes; a link arriving during radio pairing; live
TalkBack. These are below.

## Consequences

- A link finishes a system dialog that is up when it arrives; see the cost
  above.
- The scanner adds CameraX to the APK and nothing native.
- A private invitation in transit does not survive process death.
- iOS has no in-app scanner; if it gets one, it takes the same place and the
  same rules.

## Unverified

The Pixel checklist items for links, sharing and the scanner, from the Phase
3 plan (G-136 to G-152) and its build reports, deduplicated: an item that
absorbed others lists them in brackets. The rest of Phase 3's items are in
[ADR 0006](0006-background.md) "Unverified". None has been run on hardware.

| # | Guess | Do | Expect | If wrong |
|---|---|---|---|---|
| G-136 [G-214] | CameraX binds the back camera and ZXing decodes a `umsh:` code from another phone's screen and from paper within about 1 s at arm's length, with autofocus | Scan an iPhone's identity code, a printed code, a code on a laptop | Preview within about a second | A higher analysis resolution, or zxing-cpp |
| G-137 [G-215, G-217, G-227] | The torch is offered (`hasFlashUnit`), follows the button and reads "Flashlight, Off/On"; it goes off when the scanner closes; turned on, then Home and back, it is lit again and still says On; the camera and its privacy indicator are released on Close, Back or backgrounding | Toggle; leave; return; open the Camera app | As described | Fix the binding or the torch effect |
| G-138 [G-231] | A `umsh:` link opened from an app that linkifies it, or from a QR in the Camera app, opens UMSH's page once, in UMSH's own task; Close returns to that app. Many apps (Gmail, SMS) do not linkify a custom scheme, which is not an app bug | Tap links in Chrome and any app that linkifies; check Recents | One UMSH task; Close returns | Adjust launch mode or task affinity |
| G-151 [G-218, G-230] | With quick settings' camera access off, the scanner shows "Camera access is off for UMSH" if CameraX reports a critical error, and Allow camera brings Android's unblock dialog. A Pixel may instead deliver black frames with no error | Toggle access off; open Scan | Board 3, or record the black frames | Treat a long run of black frames as unavailable |
| G-152 [G-232] | Close on a page opened from another app's link returns to that app; a link arriving during the radio pairing confirmation dismisses it, and pairing again works | Open a link from Chrome, Close; open one mid-pairing | As described | Revisit D7 |
| G-216 | Status and navigation bar icons are light over the scanner and restored after it, in both themes and both navigation modes | Open and close Scan | As described | Fix the bar appearance |
| G-219 | On a cutout phone, Close and the title clear the cutout and the torch clears the gesture bar, in portrait and landscape | Rotate with the scanner open | Nothing covered | Adjust the insets |
| G-220 | A rotation while scanning rebinds the camera without a lasting black frame, and an accepted code is never delivered twice | Rotate while scanning, and just after a code is accepted | One preview | Fix the latch or the binding |
| G-221 | After "Only this time" lapses, the scanner shows the camera-off page and Allow camera asks again | Grant once, leave the app a while, return to Scan | As described | Fix the re-check on start |
| G-222 | The peer Sharesheet offers real targets (Messages, Quick Share); on 13+ only the system confirms a copy, on 12 "Link copied" shows | Share and copy a peer | As described | — |
| G-223 | A peer's shared code scanned by another phone's UMSH previews that peer; an iPhone's Camera offers to open UMSH | Scan from both | As described | — |
| G-224 | On a device whose only camera faces front, the front camera is used and still decodes | A tablet with one camera | Decodes | Prefer any camera |
| G-225 | Live TalkBack on the scanner reads the viewfinder's description, the pill once and politely, Close, and the torch with its state | TalkBack on the Pixel | As described | Fix semantics |
| G-226 | The pill does not flicker with real camera blur at the 10-frame hysteresis | Move a non-UMSH code in and out of focus | Steady | Lengthen the hysteresis |
| G-228 [G-229] | With another app holding the camera (just closed Camera app, or split screen), the viewfinder waits dark without the camera-off page and comes up by itself once the camera is free; just after closing the Camera app, no "Camera in use by another app" line flashes | Open Scan beside a camera app; open Scan right after closing Camera | Recovers by itself | Lengthen the grace period |
| G-233 | A link arriving while the Sharesheet or a notification-permission dialog is up closes it; the notification ask reads as dismissed and is asked again later | Open a link with each up | As described | Adjust the asker |
| G-234 | Live TalkBack offers a bubble's `umsh:` link in the links menu, and opening it lands on the page with focus on Close | TalkBack on a thread with a link | As described | Fix the link annotation |
| G-235 | The predictive back gesture on a page another app's link opened shows the shell beneath, then the other app, with no lingering flash | Swipe back slowly and fully | As described | Disable the preview on that page |
| G-236 | A link opened while the system kills the app during onboarding comes back after onboarding from Recents | Open a link, let the system reclaim the app, return | The page opens after onboarding | Fix the saved link |
| G-239 | A channel invitation opened from another app opens Join channel over Settings › Channels with the key hidden until the eye is tapped | Tap an invitation in a message app | As described | — |
| G-241 | Scanning a printed channel code opens the channel sheet | Scan one | The sheet | — |
| G-249 | From a page opened by a Chrome link, Share and a dismissed chooser: Close still goes back to Chrome, or, if the chooser stopped the activity, to the shell (accepted, record which) | Do it | Either, recorded | — |
| G-250 | From a page opened by a Chrome link, Home, then reopening from the launcher and from Recents: Close returns to the shell, not out of the app | Do both | Shell | Fix the left-since-link flag |
| G-251 | A web page's `intent:` link with `scheme=umsh` and the app's extras (a stored node, Radio Detail) opens only the link's page, confirming Chrome adds `CATEGORY_BROWSABLE` | Open such a link in Chrome | Only the page | Ignore extras on every `VIEW` intent |
| G-252 | On a link's page the radio control opens Radio Detail with a radio held, Choose a radio otherwise; Close then still behaves as above | Tap the control on a link page | As described | — |
| G-253 | A cold start from a link keeps the node's page open, with no flash of it closing | Open a link with the app not running | Page stays | Fix the page-closing collector |
| G-254 | A private invitation link, then the process killed in the background: Join channel comes back with an empty field and no key anywhere; a rotation before that keeps the invitation | "Don't keep activities", or let the system reclaim | As described | Fix the key handle |
| G-257 | The scanner in a signed release (R8) build: a node code and a channel code are read, the torch toggles, and backgrounding and returning rebinds the camera (the CameraX and ZXing paths under R8; G-210 covers navigation keys and `platforms.json`) | Install a release build signed for testing; scan | All work | Add keep rules |
| G-258 | In split screen and in a desktop window beside Chrome, Close and Back on a page a Chrome link opened return to UMSH's shell, and UMSH keeps its place beside Chrome | Open a link from Chrome side by side; Close; again with Back | Shell, split kept | Revisit the multi-window rule |
| G-259 | On API 33+, a link arriving while the first notification ask is up closes it; the ask does not come back over the link's page, and comes back the next time the app is resumed with a radio attached | Attach a radio on a fresh install; open a link from Chrome while the dialog is up; leave and return | As described | Adjust the deferred ask |
| G-260 | A cold start from a link makes a task whose root is that link: Back at the Conversations root finishes the activity, and Recents then reopens the shell without opening the link again, with the radio service unaffected | Open a link with the app not running; Back at the root; reopen from Recents | Shell, no replay | Fix the launched-from-history path |
| G-262 | A camera held for a long time (a picture-in-picture video call) shows "Camera in use by another app" under the dark frame after about 2 s, steadily through CameraX's retries; ending the call brings the viewfinder up and the line goes | Start a video call, put it in picture-in-picture, open Scan; end the call | As described | Check the error codes the Pixel reports (logged as `camera error`) |
| G-263 | A critical camera error other than camera access off (Do Not Disturb's camera block on some devices, a camera fault) shows "Camera unavailable" with Try again, never "Camera access is off for UMSH" | Hard to force; record any such code seen in the log | As described | Map that code |
