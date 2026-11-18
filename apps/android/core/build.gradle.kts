import javax.inject.Inject

plugins {
    alias(libs.plugins.android.library)
}

// `umsh-mobile-core` is built by cargo from the repository's own workspace.
// Its Kotlin bindings are generated from the built library on every build
// and never committed, so they cannot go stale.
val repoDir: File = rootDir.resolve("../..").canonicalFile
val cargoTargetDir: File = repoDir.resolve("target/android-mobile-core")
val hostLibraryDir: File = cargoTargetDir.resolve("host/release")
val androidAbis = providers.gradleProperty("umsh.androidAbis").get().split(",")
val minSdkLevel = libs.versions.minSdk.get().toInt()

android {
    namespace = "com.voria.umsh.core"
    compileSdk = libs.versions.compileSdk.get().toInt()
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        minSdk = minSdkLevel
        // JNA's AAR carries `libjnidispatch.so` for ABIs the core is not
        // built for; keep them out of the test APK.
        ndk { abiFilters += androidAbis }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // One smoke suite, run on the host JVM against a host build of the core
    // and on a device or emulator against the cross-built one.
    sourceSets {
        getByName("test").kotlin.directories += "src/sharedTest/kotlin"
        getByName("androidTest").kotlin.directories += "src/sharedTest/kotlin"
    }
}

kotlin {
    jvmToolchain(17)
}

/** Cross-builds `umsh-mobile-core` for each ABI, laid out as `jniLibs`. */
abstract class CargoNdk : DefaultTask() {
    @get:Input abstract val abis: ListProperty<String>
    @get:Input abstract val platform: Property<Int>
    @get:Internal abstract val repoRoot: DirectoryProperty
    @get:Internal abstract val cargoTarget: DirectoryProperty
    @get:Internal abstract val ndk: DirectoryProperty
    @get:OutputDirectory abstract val jniLibs: DirectoryProperty
    @get:Inject abstract val exec: ExecOperations

    init {
        // Cargo tracks the crate graph's inputs itself.
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun build() {
        val out = jniLibs.get().asFile
        out.deleteRecursively()
        exec.exec {
            workingDir = repoRoot.get().asFile
            environment("CARGO_TARGET_DIR", cargoTarget.get().asFile.resolve("ndk").path)
            environment("ANDROID_NDK_HOME", ndk.get().asFile.path)
            commandLine(
                buildList {
                    addAll(listOf("cargo", "ndk", "--platform", platform.get().toString()))
                    abis.get().forEach { addAll(listOf("-t", it)) }
                    addAll(listOf("-o", out.path))
                    addAll(listOf("build", "--release", "-p", "umsh-mobile-core"))
                },
            )
        }
    }
}

/** Generates the Kotlin bindings from a built library's UniFFI metadata. */
abstract class UniffiKotlin : DefaultTask() {
    @get:InputFile abstract val library: RegularFileProperty
    @get:Internal abstract val repoRoot: DirectoryProperty
    @get:OutputDirectory abstract val sources: DirectoryProperty
    @get:Inject abstract val exec: ExecOperations

    @TaskAction
    fun generate() {
        val out = sources.get().asFile
        out.deleteRecursively()
        exec.exec {
            workingDir = repoRoot.get().asFile
            commandLine(
                "cargo", "run", "-q", "-p", "umsh-uniffi-bindgen", "--",
                "generate", "--library", library.get().asFile.path,
                "--language", "kotlin", "--no-format", "--out-dir", out.path,
            )
        }
    }
}

/** Builds `umsh-mobile-core` for the host, for the JVM unit tests. */
abstract class CargoHost : DefaultTask() {
    @get:Internal abstract val repoRoot: DirectoryProperty
    @get:Internal abstract val cargoTarget: DirectoryProperty

    @get:Inject abstract val exec: ExecOperations

    init {
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun build() {
        exec.exec {
            workingDir = repoRoot.get().asFile
            environment("CARGO_TARGET_DIR", cargoTarget.get().asFile.resolve("host").path)
            commandLine("cargo", "build", "--release", "-p", "umsh-mobile-core")
        }
    }
}

androidComponents {
    val ndkDirectory = sdkComponents.ndkDirectory
    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar { it.uppercase() }
        val cargoNdk = tasks.register<CargoNdk>("cargoNdk$suffix") {
            abis.set(androidAbis)
            platform.set(minSdkLevel)
            repoRoot.set(repoDir)
            cargoTarget.set(cargoTargetDir)
            ndk.set(ndkDirectory)
        }
        val bindings = tasks.register<UniffiKotlin>("uniffiKotlin$suffix") {
            library.set(cargoNdk.flatMap { it.jniLibs.file("arm64-v8a/libumsh_mobile_core.so") })
            repoRoot.set(repoDir)
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoNdk, CargoNdk::jniLibs)
        // Registered as generated, so lint skips them: the bindings name
        // `java.lang.ref.Cleaner` (API 33) behind a runtime check.
        variant.sources.kotlin?.addGeneratedSourceDirectory(bindings, UniffiKotlin::sources)
    }
}

val cargoHost = tasks.register<CargoHost>("cargoHost") {
    repoRoot.set(repoDir)
    cargoTarget.set(cargoTargetDir)
}

tasks.withType<Test>().configureEach {
    dependsOn(cargoHost)
    systemProperty("jna.library.path", hostLibraryDir.path)
}

dependencies {
    // The AAR carries `libjnidispatch.so` for each Android ABI.
    implementation("${libs.jna.get()}@aar")
    implementation(libs.kotlinx.coroutines.core)

    // The JAR carries the host's `libjnidispatch` for the JVM unit tests.
    testImplementation(libs.jna)
    testImplementation(libs.junit)

    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
