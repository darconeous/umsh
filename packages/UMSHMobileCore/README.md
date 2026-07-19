# UMSHMobileCore

This local Swift package is the only application-facing entry point to the
generated UniFFI binding. Feature targets should depend on `UMSHMobileCore`,
not on `UMSHMobileCoreFFI` or generated symbols directly.

From the repository root, build the Rust device/simulator slices, regenerate
Swift, and assemble the XCFramework:

```sh
scripts/ios/build-mobile-core.sh
```

Run the executable host-language boundary check:

```sh
scripts/ios/verify-mobile-core-swift.sh
```

The generated Swift source is committed. The compiled XCFramework under
`Artifacts/` is reproducible local/CI output and is ignored by Git.
