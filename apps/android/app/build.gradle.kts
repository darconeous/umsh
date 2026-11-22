plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.voria.umsh"
    compileSdk = libs.versions.compileSdk.get().toInt()
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        applicationId = "com.voria.umsh"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1"
        // Installs `TestUmshApplication`, so instrumented tests never touch
        // the app's own files or identity.
        testInstrumentationRunner = "com.voria.umsh.app.UmshTestRunner"
        // Only the ABIs `:core` builds the core for. JNA's AAR carries
        // `libjnidispatch.so` for several more, which would otherwise ship
        // as ABI directories with no core in them.
        ndk { abiFilters += providers.gradleProperty("umsh.androidAbis").get().split(",") }
    }

    buildTypes {
        debug {
            // en-XA and ar-XB, for layout checks under long and RTL text.
            isPseudoLocalesEnabled = true
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    androidResources {
        // Per-app language settings list the locales `res/` carries.
        generateLocaleConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
        // Every visible string is a resource: in XML, and in Compose code
        // through `:lint-rules`. Fatal, so `assembleRelease` (lintVital)
        // fails on one too, not only the `lint` task.
        fatal += listOf("HardcodedText", "ComposeLiteralText")
    }
}

kotlin {
    jvmToolchain(17)
}

// The JVM unit tests drive the real core through JNA, from the host build
// `:core` makes, and read the parity stores and avatar goldens from the
// repository. Each is a declared input, so a changed golden or a rebuilt
// core reruns the tests rather than leaving them up to date.
val repoDir: File = rootDir.resolve("../..").canonicalFile
val hostLibraryDir: File = repoDir.resolve("target/android-mobile-core/host/release")
tasks.withType<Test>().configureEach {
    dependsOn(":core:cargoHost")
    systemProperty("jna.library.path", hostLibraryDir.path)
    systemProperty("umsh.repoDir", repoDir.path)
    inputs.file(repoDir.resolve("docs/ux/src/apps/avatar-goldens.tsv"))
        .withPropertyName("avatarGoldens")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir(repoDir.resolve("crates/umsh-mobile-core/src/app_core/parity"))
        .withPropertyName("parityStores")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(fileTree(hostLibraryDir) { include("libumsh_mobile_core.dylib", "libumsh_mobile_core.so") })
        .withPropertyName("hostCore")
        .withPathSensitivity(PathSensitivity.NAME_ONLY)
}

dependencies {
    implementation(project(":core"))
    lintChecks(project(":lint-rules"))

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material3.adaptive)
    implementation(libs.androidx.compose.material3.adaptive.navigation.suite)
    implementation(libs.androidx.compose.material3.adaptive.navigation3)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.viewmodel.navigation3)
    implementation(libs.androidx.navigation3.runtime)
    implementation(libs.androidx.navigation3.ui)
    implementation(libs.kotlinx.serialization.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.browser)
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.zxing.core)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    // The JAR carries the host's `libjnidispatch`.
    testImplementation(libs.jna)

    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
