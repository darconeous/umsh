# Localizing the iOS app

The app's text lives in string catalogs: `UMSH/Localizable.xcstrings` for the
app, `UMSH/InfoPlist.xcstrings` for the permission prompts, and
`UMSHLanRadio/Localizable.xcstrings` for the extension. English is the source
language. Xcode fills the catalogs from the code on every build; nobody edits
the English entries by hand.

## Handing strings to translators

```sh
scripts/ios/export-localizations.sh target/ios-localizations en de fr
```

Each language comes out as an `.xcloc` holding an XLIFF with every string,
its comment, and whatever translation the catalog already has. Bring a
finished one back with:

```sh
xcodebuild -importLocalizations -project apps/ios/UMSH.xcodeproj \
    -localizationPath target/ios-localizations/de.xcloc
```

CI runs the English export on every build, so a string that fails to extract
fails there instead of in a translator's hands.

## Rules for new and changed code

New screens follow these from the start. Older screens are converted as they
are touched; the peer page, Ping, and Route screens are the reference.

1. **Every user-visible string is a literal key.** `Text("…")`,
   `Label("…", systemImage:)`, `String(localized: "…", comment: "…")`, or
   `LocalizedStringResource("…", comment: "…")` when the text has to travel as
   a value. A helper that produces display text returns
   `LocalizedStringResource`, `Text`, or a `String` made by
   `String(localized:)`. Never a bare `String` literal, which the catalog
   never sees.
2. **Never assemble sentences.** No `+`, no `joined`, no inserting a fragment
   ("the repeater") into a sentence. Write the whole sentence once, with
   placeholders: `String(localized: "Heard \(time)")`. Lists of names use
   `.formatted(.list(type: .and))`. Pairs shown with a middle dot are one
   format string, `"\(first) · \(second)"`, so a translator can reorder them.
3. **Plurals live in the catalog.** Write `String(localized: "\(count) hops")`
   and give the entry plural variants. Never `hop\(n == 1 ? "" : "s")`.
4. **Numbers and units go through Foundation.** `Measurement` for distance
   and altitude (it picks miles or kilometers), `Duration` for times,
   `.formatted()` for counts. dBm and dB have no Foundation unit, so they
   live in one place, `SignalPresentation`, as localized format strings around
   a locale-formatted number.
5. **Dates use formatters.** `Text(date, format: .relative(…))` or
   `.formatted(…)`. A word around a date ("Heard \(date)") is its own
   localized string.
6. **The Rust core never supplies display text.** It sends codes, bit sets,
   and enums; Swift names them. Role names are `PeerRole.label`, capability
   names `MeshNodeCapabilities.named`.
7. **Identifiers are never translated.** Addresses, hints, hex, and `umsh:`
   links render with `Text(verbatim:)`.
8. **Comment anything a translator could misread.** A single word is the
   usual case: "Route" is a noun, "Ping" is a verb on a button and a noun as
   a title, "Flood" is a routing mode, not water.
9. **Layouts take long and right-to-left text.**
   - Give no text a fixed width; tiles wrap to two lines before shrinking.
   - Use leading and trailing, never left and right.
   - SF Symbols chevrons mirror by themselves. Anything that points at
     the world, like the bearing arrow, must not: rotate it from a symbol
     that does not mirror, and check it under right-to-left.
10. **Tests find elements by accessibility identifier,** never by their
    English text.

## Checking a screen

Run the scheme with **Double-Length Pseudolanguage** and then **Right-to-Left
Pseudolanguage** (Edit Scheme › Run › Options › App Language). Nothing should
truncate, and everything except the bearing arrow should mirror.
