pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.namespace == "com.android") {
                useModule("com.android.tools.build:gradle:9.4.0")
            }
        }
    }
}
rootProject.name = "secp256k1-kmp"

// We use a property defined in `local.properties` to know whether we should build the android application or not.
// For example, iOS developers may want to skip that most of the time.
val skipAndroid = File("$rootDir/local.properties").takeIf { it.exists() }
    ?.inputStream()?.use { java.util.Properties().apply { load(it) } }
    ?.run { getProperty("skip.android", "false")?.toBoolean() }
    ?: false

// Use system properties to inject the property in other gradle build files.
System.setProperty("includeAndroid", (!skipAndroid).toString())

include(
    ":native",
    ":jni",
    ":jni:jvm",
    ":jni:jvm:darwin",
    ":jni:jvm:linux",
    ":jni:jvm:mingw",
    ":jni:jvm:all",
    ":tests"
)

if (!skipAndroid) {
    println("building android library")
    include(":jni:android")
} else {
    println("skipping android build")
}
