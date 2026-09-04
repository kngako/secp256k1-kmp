import org.gradle.kotlin.dsl.register
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    `maven-publish`
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()
val bash = if (currentOs.isWindows) "bash.exe" else "bash"

// build.sh compiles jni/c/src against the checked-in JNI headers and links the static library
// produced by :native. Declaring only build.sh let a JNI-glue edit or a submodule bump leave a
// stale libsecp256k1-jni.so in place, which surfaces at test time as UnsatisfiedLinkError on the
// newly added natives rather than as a rebuild.
val jniCSources = fileTree(rootProject.file("jni/c")) {
    include("src/**", "headers/**")
}

val buildNativeHost = tasks.register<Exec>("buildNativeHost") {
    group = "build"
    dependsOn(":jni:generateHeaders")
    dependsOn(":native:buildSecp256k1Host")

    val target = when {
        currentOs.isLinux -> "linux"
        currentOs.isMacOsX -> "darwin"
        currentOs.isWindows -> "mingw"
        else -> error("Unsupported OS $currentOs")
    }

    inputs.files(projectDir.resolve("build.sh"), jniCSources).withPropertyName("jniSources")
    inputs.files(rootProject.file("native/build/$target")).withPropertyName("secp256k1StaticLib")
    outputs.dir(layout.buildDirectory.dir(target))

    workingDir = projectDir
    environment("TARGET", target)
    commandLine(bash, "build.sh")
}

val buildNativeLinuxArm64 = tasks.register<Exec>("buildNativeLinuxArm64") {
    onlyIf { org.gradle.internal.os.OperatingSystem.current().isLinux }
    group = "build"
    dependsOn(":jni:generateHeaders")
    dependsOn(":native:buildSecp256k1LinuxArm64")

    val target = "linuxArm64"

    inputs.files(projectDir.resolve("build.sh"), jniCSources).withPropertyName("jniSources")
    inputs.files(rootProject.file("native/build/$target")).withPropertyName("secp256k1StaticLib")
    outputs.dir(layout.buildDirectory.dir(target))

    workingDir = projectDir
    environment("TARGET", target)
    commandLine(bash, "build.sh")
}

dependencies {
    api(project(":jni"))
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        // See https://jakewharton.com/kotlins-jdk-release-compatibility-flag/ and https://youtrack.jetbrains.com/issue/KT-49746/
        freeCompilerArgs.add("-Xjdk-release=1.8")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-jvm-extract"
            from(components["java"])
            val sourcesJar = tasks.register<Jar>("sourcesJar") {
                archiveClassifier.set("sources")
            }
            artifact(sourcesJar)
        }
    }
}

afterEvaluate {
    tasks["clean"].doLast {
        delete(layout.buildDirectory.dir("build/cmake"))
    }
}
