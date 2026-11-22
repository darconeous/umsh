// Custom lint checks, loaded by `:app` through `lintChecks`.
plugins {
    `java-library`
    // On the classpath already through the root build script, so unversioned.
    id("org.jetbrains.kotlin.jvm")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    compileOnly(libs.lint.api)

    testImplementation(libs.lint.api)
    testImplementation(libs.lint.tests)
    testImplementation(libs.junit)
}
