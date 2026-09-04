import org.gradle.kotlin.dsl.register
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    `maven-publish`
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        // See https://jakewharton.com/kotlins-jdk-release-compatibility-flag/ and https://youtrack.jetbrains.com/issue/KT-49746/
        freeCompilerArgs.add("-Xjdk-release=1.8")
    }
}

dependencies {
    api(project(":"))
}

val generateHeaders = tasks.register<JavaCompile>("generateHeaders") {
    group = "build"
    classpath = sourceSets["main"].compileClasspath
    destinationDirectory.set(layout.buildDirectory.dir("generated/jni"))
    source = sourceSets["main"].java
    options.compilerArgs = listOf(
        "-h", layout.buildDirectory.dir("generated/jni").get().asFile.absolutePath,
        "-d", layout.buildDirectory.dir("generated/jni-tmp").get().asFile.absolutePath
    )
    doLast {
        // javac needs a -d for the class files it emits alongside the headers, and those are
        // throwaway. File.delete() only removes an empty directory, so it silently did nothing.
        layout.buildDirectory.dir("generated/jni-tmp").get().asFile.deleteRecursively()
    }
}

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-common"
            from(components["java"])
            val sourcesJar = tasks.register<Jar>("sourcesJar") {
                archiveClassifier.set("sources")
                from(sourceSets["main"].allSource)
            }
            artifact(sourcesJar)
        }
    }
}
