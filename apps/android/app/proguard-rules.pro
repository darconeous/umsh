# JNA and the core's bindings are kept by `:core`'s consumer rules.
# kotlinx.serialization (serializers of `@Serializable` classes) and
# Preferences DataStore (its protobuf messages) ship their own.

# Navigation keys are saved through their serializers and found by class
# when a back stack is restored after process death.
-keep class * implements androidx.navigation3.runtime.NavKey { *; }
