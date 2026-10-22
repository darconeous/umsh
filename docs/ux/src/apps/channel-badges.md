# Channel Badges and Titles

A channel is shown as a badge beside its title. Everyone holding a channel's
key sees the same badge, derived from the key and the name, with nothing agreed
or transmitted. The badge must be reproducible across conforming applications
and devices.

## Shape

A channel badge is a rounded square, which tells it at a glance from a peer's
avatar (see [Avatar shape](peer-identity-and-sessions.md#avatar-shape)).

## Color

The color is derived from the key: the channel-identifier derivation run one
byte longer, `HKDF-SHA256(channel_key, salt="UMSH-CHAN-ID", info="", L=3)`, so
its first two bytes are the identifier itself.

A derived color can land anywhere, including the middle of the brightness
range where neither black nor white text reads well. The badge keeps the
derived hue and moves only brightness and saturation, into whichever of a light
or dark band it is already nearer. Each band clears 4.5:1 against its text
color: white on the dark band, black on the light one.

Two channels are recognized on sight rather than read: `public` is a white
**P** on blue, `EMERGENCY` a white **E** on red.

## Lettering

Lettering is made of whole grapheme clusters, never parts of one.

1. A name that starts with an emoji is lettered with that emoji alone. An emoji
   here is a first grapheme cluster drawn as an emoji, whether or not the
   surface has art for it.
2. Any other name is lettered with the first grapheme cluster of each word,
   uppercased, up to four. Words are split at whitespace, hyphens, and
   underscores. Up to two initials share a line; three and four go two over
   two, so they stay as large as two rather than shrinking.
3. A private channel that was never named has nothing to letter and shows its
   identifier instead.

## Title

Wherever a channel's badge sits to the left of its name on one row or
widget, such as a list row, a search result, a lock-screen card, a
notification, an invitation, or the conversation's header, the name is shown
as the channel's title. The title is the name without what the badge already
shows:

1. A name that starts with an emoji drops that emoji, and any whitespace after
   it. Only the first emoji is dropped; any after it stay in the title.
2. A name that is that emoji alone is titled with the emoji's CLDR short name,
   its first letter capitalized and the rest as CLDR writes it. A skin-toned
   emoji takes its base's name. A flag is titled with its region code, such as
   `FR` or `GB-SCT`. An emoji the surface has no name for keeps the name as
   written.
3. Any other name is its own title.

Anywhere else, such as an editable field or text that quotes the name, the
name is shown as written. Search matches both the name and the title, so
`fire` finds a channel named `🔥`.

Two channels may share a title, as they may share a name. The badge and the
channel's details tell them apart.

## Examples

| Name | Badge | Title |
|---|---|---|
| `Hot Topic` | `HT` | Hot Topic |
| `hike-club` | `HC` | hike-club |
| `one two 👍🏽 four five` | `OT` / `👍🏽F` | one two 👍🏽 four five |
| `🔥 Hot Topic` | `🔥` | Hot Topic |
| `🔥Hot` | `🔥` | Hot |
| `🔥🎉 Party` | `🔥` | 🎉 Party |
| `🔥` | `🔥` | Fire |
| `👌` | `👌` | OK hand |
| `🇫🇷` | `🇫🇷` | FR |
