# JNA finds its natives and the bindings' callback interfaces by reflection.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class com.voria.umsh.core.** { *; }
-dontwarn java.awt.**
