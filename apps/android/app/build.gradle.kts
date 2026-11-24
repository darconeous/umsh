import groovy.json.JsonSlurper

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

/**
 * Stages the board list and photos the app shows for a radio's model
 * (`BoardCatalog`): `docs/hardware/boards.json` as an asset, and each
 * board's iOS photo (the 3x PNG of its `board-*.imageset`) as a `nodpi`
 * drawable named after it. Plain copies, generated and never committed,
 * so the two apps and the spec read the same list.
 */
abstract class StageBoards : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val boardsJson: RegularFileProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val imageSets: ConfigurableFileCollection

    @get:OutputDirectory abstract val assets: DirectoryProperty

    @get:OutputDirectory abstract val res: DirectoryProperty

    @TaskAction
    fun stage() {
        val assetsDir = assets.get().asFile.apply { deleteRecursively(); mkdirs() }
        val resDir = res.get().asFile.apply { deleteRecursively() }
        val source = boardsJson.get().asFile
        source.copyTo(assetsDir.resolve("boards.json"))
        val drawables = resDir.resolve("drawable-nodpi").apply { mkdirs() }
        val sets = imageSets.files.associateBy { it.name.removeSuffix(".imageset") }

        @Suppress("UNCHECKED_CAST")
        val boards = (JsonSlurper().parse(source) as Map<String, Any>)["boards"] as List<Map<String, Any>>
        for (board in boards) {
            val photo = board["photo"] as String
            val set = sets[photo] ?: throw GradleException("boards.json names $photo, which has no imageset")
            @Suppress("UNCHECKED_CAST")
            val images = (JsonSlurper().parse(set.resolve("Contents.json")) as Map<String, Any>)["images"]
                as List<Map<String, Any>>
            val file = images.firstOrNull { it["scale"] == "3x" }?.get("filename") as String?
                ?: throw GradleException("$photo has no 3x image")
            set.resolve(file).copyTo(drawables.resolve(photo.replace('-', '_') + ".png"))
        }
        // Looked up by name, so the resource shrinker is told to keep them.
        resDir.resolve("raw").apply { mkdirs() }.resolve("keep_boards.xml").writeText(
            """<?xml version="1.0" encoding="utf-8"?>
            |<resources xmlns:tools="http://schemas.android.com/tools" tools:keep="@drawable/board_*" />
            |""".trimMargin(),
        )
    }
}

/**
 * Stages the host platforms Nearby names and draws (`PlatformCatalog`):
 * `docs/hardware/platforms.json` as an asset. A plain copy, generated and
 * never committed, so the two apps read the same list.
 */
abstract class StagePlatforms : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val platformsJson: RegularFileProperty

    @get:OutputDirectory abstract val assets: DirectoryProperty

    @TaskAction
    fun stage() {
        val assetsDir = assets.get().asFile.apply { deleteRecursively(); mkdirs() }
        platformsJson.get().asFile.copyTo(assetsDir.resolve("platforms.json"))
    }
}

androidComponents {
    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar { it.uppercase() }
        val boards = tasks.register<StageBoards>("stage${suffix}Boards") {
            boardsJson.set(repoDir.resolve("docs/hardware/boards.json"))
            imageSets.from(
                fileTree(repoDir.resolve("apps/ios/UMSH/Assets.xcassets")) { include("board-*.imageset/**") }
                    .files.map { it.parentFile }.distinct(),
            )
        }
        variant.sources.assets?.addGeneratedSourceDirectory(boards, StageBoards::assets)
        variant.sources.res?.addGeneratedSourceDirectory(boards, StageBoards::res)
        val platforms = tasks.register<StagePlatforms>("stage${suffix}Platforms") {
            platformsJson.set(repoDir.resolve("docs/hardware/platforms.json"))
        }
        variant.sources.assets?.addGeneratedSourceDirectory(platforms, StagePlatforms::assets)
    }
}

dependencies {
    implementation(project(":core"))
    lintChecks(project(":lint-rules"))

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material3.adaptive)
    implementation(libs.androidx.compose.material3.adaptive.navigation.suite)
    implementation(libs.androidx.compose.material3.adaptive.navigation3)
    implementation(libs.androidx.core)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.viewmodel.navigation3)
    implementation(libs.androidx.navigation3.runtime)
    implementation(libs.androidx.navigation3.ui)
    implementation(libs.kotlinx.serialization.core)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.browser)
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.zxing.core)
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.compose)

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
    androidTestImplementation(libs.androidx.test.uiautomator)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
