[![Kotlin](https://img.shields.io/badge/Kotlin-2.1.10-blue.svg?style=flat&logo=kotlin)](http://kotlinlang.org)
[![Maven Central](https://img.shields.io/maven-central/v/fr.acinq.secp256k1/secp256k1-kmp)](https://search.maven.org/search?q=g:fr.acinq.secp256k1%20a:secp256k1-kmp*)
![Github Actions](https://github.com/ACINQ/secp256k1-kmp/actions/workflows/test.yml/badge.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ACINQ/secp256k1-kmp/blob/master/LICENSE)

# Secp256k1 for Kotlin/Multiplatform

Kotlin/Multiplatform wrapper for Bitcoin Core's secp256k1 library. Targets: JVM, Android, iOS & Linux.

## Installation

secp256k1-kmp is available on [maven central](https://search.maven.org/search?q=g:fr.acinq.secp256k1%20a:secp256k1-kmp*)

Then, the actual dependency depends on your targeted platform(s):

### Multiplatform

Add the `secp256k1` dependency to the common sourceSet, and the JNI dependencies to JVM and Android sourcesets:

```kotlin
// build.gradle.kts

kotlin {
    jvm()
    android()
    linuxX64("linux")
    ios()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(kotlin("stdlib-common"))
                implementation("fr.acinq.secp256k1:secp256k1-kmp:$secp256k1_version")
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(kotlin("stdlib"))
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:$secp256k1_version")
            }
        }
        val androidMain by getting {
            dependencies {
                implementation(kotlin("stdlib"))
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:$secp256k1_version")
            }
        }
    }
}
```

### Native targets (iOS, linux64)

Native targets include libsecp256k1, called through KMP's c-interop, simply add the `fr.acinq.secp256k1:secp256k1` dependency.

### JVM targets & Android

The JVM library uses JNI bindings for libsecp256k1, which is much faster than BouncyCastle. It will extract and load native bindings for your operating system in a temporary directory.

JNI libraries are included for:
- Linux 64 bits (x86_64 and arm64)
- Windows 64 bits (x86_64)
- Macos 64 bits (x86_64 and arm64)

Along this library, you **must** specify which JNI native library to use in your dependency manager:

* **For desktop or server JVMs**, you must add the dependency:
  * Either the `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm` dependency which imports all supported platforms.
  * Or the platform specific dependencies (note that you can add multiple as they do not conflict):
    * `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-linux` for Linux
    * `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-darwin` for Mac OS X
    * `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-mingw` for Windows
* **For Android**, you must add the `fr.acinq.secp256k1:secp256k1-kmp-jni-android` dependency

If you are using the JVM on an OS for which we don't provide JNI bindings (32 bits OS for example), you can use your own library native library by
adding the `fr.acinq.secp256k1:secp256k1-kmp-jni-jvm` dependency and specifying its path with `-Dfr.acinq.secp256k1.lib.path` and optionally its name with `-Dfr.acinq.secp256k1.lib.name`
(if unspecified bitcoink use the standard name for your OS i.e. libsecp256k1.so on Linux, secp256k1.dll on Windows, ...).

To compile your own JNI bindings, have a look add the `native/build.sh` and `jni/build.sh` scripts.

You can also specify the temporary directory where the library will be extracted with `-Djava.io.tmpdir` or `-Dfr.acinq.secp256k1.tmpdir`
(if you want to use a different directory from `-Djava.io.tmpdir`).

## Usage

Please have a look at unit tests, more samples will be added soon.

### FROST enrollment and repair

FROST enrollment grows a `(t, n)` group to `(t, n+1)` without changing its threshold public key or rerunning key generation. The same operation at an existing participant identifier repairs that participant's lost share without changing `n` or its public-share table. Two explicitly separated protocols are available:

- The original `frostEnrollment...` functions implement full enrollment (version 1).
- The `frostEnrollmentReduced...` functions implement reduced enrollment (version 2), recommended for new integrations. Reduced enrollment uses a triangular share matrix, a session-bound parameters hash and mandatory target-side verification. Full and reduced messages must not be mixed within a run.

A reduced enrollment or repair run follows this sequence:

1. The target creates a fresh 32-byte `sessionId32`. Every helper authorizes the exact session, group, participant count, threshold, target and helper set out of band.
2. Each helper calls `frostEnrollmentReducedSharesGen` with fresh 32-byte randomness. It retains its own entry and sends entries only to helpers with larger participant identifiers, together with its parameters hash.
3. Each helper calls `frostEnrollmentReducedShareAgg` over its triangular matrix column and sends the resulting sigma and parameters hash to the target.
4. The expected public share is derived with `frostEnrollmentPubshareDerive`, or with `frostEnrollmentPubshareDeriveFromCommitments` when authenticated aggregate VSS commitments are available.
5. The target calls `frostEnrollmentReducedSecshareGen` with one sigma and parameters hash from every helper and the mandatory expected public share.

After enrollment, every participant must append the same derived public share, update `n` to `n+1`, validate the extended table with `frostThresholdInfoValidate`, and persist the transition atomically before signing. Repair leaves the group metadata unchanged. Transport, message deduplication, authorization, consensus and persistent state remain application responsibilities.

Deltas and sigmas are additive shares of real secret shares and must use confidential, authenticated channels. The threshold public key and public shares or VSS commitments must be authenticated independently of helper messages. Commitment entries are 33-byte compressed points in ascending coefficient order; 33 zero bytes encode infinity for a zero nonconstant coefficient. The bindings wipe native scratch copies of consumed randomness, but do not wipe caller-provided Kotlin arrays.

**Warning:** the underlying enrollment module is experimental and must not be used in production. In particular, the generalized reduced protocol with more helpers than the threshold requires independent review. See the [protocol notes](https://code.sigidli.com/frost/secp256k1-zkp/src/commit/a04dc1edd71783990e1fcde648fa42ac5d03eefa/src/modules/frost_enrollment/frost_enrollment.md), [API contract](https://code.sigidli.com/frost/secp256k1-zkp/src/commit/a04dc1edd71783990e1fcde648fa42ac5d03eefa/include/secp256k1_frost_enrollment.h), and [upstream example](https://code.sigidli.com/frost/secp256k1-zkp/src/commit/a04dc1edd71783990e1fcde648fa42ac5d03eefa/examples/frost_enrollment.c) for the complete security contract. `FrostReducedEnrollmentTest` demonstrates the corresponding Kotlin call sequence.

### Confederation

The `confederation...` functions expose nested threshold key generation and signing, descriptor and transition validation, entity-overlap analysis, share rebinding, and recovery packages through the same JVM/JNI and Kotlin/Native APIs.

**Warning:** confederation is experimental research code under active design and review. It is not audited or stable and must not be used in production or to protect value. The initial DKG, signing, and lifecycle implementations require independent implementation review; full masking as changed has no independent review. See the pinned [public API](https://code.sigidli.com/frost/secp256k1-zkp/src/commit/e18a8e8e5cba0e10860b7f3e6a8464f257ed9e61/include/secp256k1_confederation.h), [protocol candidate](https://code.sigidli.com/frost/secp256k1-zkp/src/commit/e18a8e8e5cba0e10860b7f3e6a8464f257ed9e61/doc/confederation-protocol.md), and [security limitations](https://code.sigidli.com/frost/secp256k1-zkp/src/commit/e18a8e8e5cba0e10860b7f3e6a8464f257ed9e61/src/modules/confederation/security.md).

Canonical descriptor, transition, and recovery encodings may be persisted or transported. The larger objects returned by parse and DKG calls are build-specific opaque native values: do not inspect, persist, or exchange them between library versions or ABIs. Serialize them before storage. Opaque shares and recovery data are secret.

A typical initial sequence is:

1. Parse and validate a canonical RPD, then call `confederationDkg` with a fresh session seed and one freshly generated host secret, dealer seed, and recovery nonce per flattened RPD role.
2. Validate the genesis transition against the returned KSD. Persist accepted `(config_seq, RPD hash, KSD hash)` state, canonical transitions, shares, and recovery data atomically. Certificates do not provide consensus: check successors and quarantine conflicting certificates.
3. Sign with a fresh signing session ID, full-role share and host-secret arrays, and canonically ordered group/admin selections. Four zero bytes encode no tweaks. Secret nonces are consumed by each attempt and must never be reused across attempts.
4. Serialize recovery packages with `confederationRecoverySerialize`. Later, parse them with the corresponding host secret, open them against the current RPD/KSD, and validate the recovered share.

#### The DKG one role at a time

`confederationDkg` runs every role in one process, which is a test harness, not a ceremony. The `confederationDkg...` step functions run it the way it happens: each role on its own device, the coordinator relaying bytes between them. Every step is a deterministic function of what it is given, so a role that restarts recomputes a step from what it stored.

1. Every role: `confederationDkgParticipantStep1` gives a dealer record and a ciphertext vector. Store both and send them to the coordinator, then erase the dealer seed.
2. Coordinator: `confederationDkgCoordinatorStep1` checks every record and writes the broadcast.
3. Every role: `confederationDkgParticipantStep2` runs every check, derives the KSD itself (it never accepts one) and signs an authorization of the genesis transition.
4. Coordinator: `confederationDkgEvidenceListWrite` collects the authorizations.
5. Every role: durably store the RPD, the KSD, the broadcast, its own record and its recovery nonce, then `confederationDkgParticipantAcknowledge`. The acknowledgment says the role can never lose its share.
6. Coordinator: collect the acknowledgments, derive its own KSD with `confederationDkgDeriveKsd`, and certify the genesis with `confederationDkgCoordinatorFinalize`.
7. Every role: `confederationDkgParticipantFinalize` checks the certified transition and recomputes its share and recovery package.

A step that judges another party's message returns a `ConfederationStep.Faulted` carrying a `ConfederationFault`: a code and the flattened RPD index of the implicated role, or null. A fault is an answer, not an error. `Secp256k1Exception` is kept for this caller's own malformed input. `ROLE_OR_COORDINATOR` from step 3 means the role's share did not decrypt; `confederationDkgInvestigationResponse` and `confederationDkgInvestigate` decide whether the dealer or the coordinator is at fault. `ConfederationDistributedDkgTest` runs the whole ceremony against upstream's vectors.

The library is stateless. Transport, sender authentication, real-world entity attestation, authorization, durable attempt and abandonment records, timeout handling, consensus, and atomic state transitions remain application responsibilities. Unique host keys do not establish independent people or entities. RecoveryPackage encryption is a non-standard candidate; compromising a host key exposes that role's shares in every epoch where the key was registered.

The bindings cleanse native scratch copies where practical, but cannot wipe caller-provided Kotlin arrays or returned secret objects. Upstream's enrollment, refresh, masking, and resharing round steps are internal at the pinned revision and are not exposed as public lifecycle orchestration here. `ConfederationTest`, `ConfederationVectorsTest` and `ConfederationDistributedDkgTest` demonstrate the supported call sequences.

### FROST share refresh

`frostRefresh*` gives every recipient of a ChillDKG group a new share of the same threshold key, on a new polynomial, so that shares from before the refresh no longer combine with shares after it. Enrollment cannot do this: it evaluates the existing polynomial. The session parameters cross the binding as their serialization, from `frostRefreshParamsSerialize`, and every other function takes them:

1. Every recipient (at least t, each a dealer) calls `frostRefreshParticipantStep1` with fresh randomness and sends the result to the coordinator.
2. The coordinator calls `frostRefreshCoordinatorStep1` and broadcasts cmsg1.
3. Every recipient calls `frostRefreshParticipantStep2`, stores the new share and public-share table durably, and only then sends its CertEq signature.
4. `frostRefreshCoordinatorFinalize` makes the certificate; `frostRefreshParticipantFinalize` verifies it and yields recovery data. Only then does the group move to the new generation.

A participant left out of the recipients is withheld: its public share moves, but it is dealt nothing, and a reduced-enrollment repair at its identifier is how it is brought back. Recovery data rebuilds a recipient's new share from its host secret key and previous share (`frostRefreshParticipantRecover`), and anyone's view of the new table (`frostRefreshPublicRecover`).

**Warning:** the underlying refresh module is experimental, has no BIP and no independent review, and must not be used in production. A refresh is only as good as the deletion of the old shares, and does not survive a leaked host secret key. `FrostRefreshTest` demonstrates the call sequence.

## Building

**secp256k1-kmp** is a [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) wrapper for Bitcoin Core's [secp256k1 library](https://github.com/bitcoin-core/secp256k1).

To build the library you need the following:
- Window 64 bits, Linux 64 bits, or MacOs 64 Bits
- OpenJDK11 (we recommend using packages provided by https://adoptopenjdk.net/ but there are other options)
- (optional) Android SDK

On Linux X64 you need to install a cross-compiler, which is used to cross-build for Linux Arm64.
On Ubuntu, this is done with:

```sh
sudo apt install g++-aarch64-linux-gnu binutils-aarch64-linux-gnu

```

It may work with other Operating Systems and JDKs, but then you're on your own (in particular we don't plan to support 32 bits Operating Systems).
To build the library and publish compiled artefacts locally (so they can be used by other projects):

```sh
./gradlew :build
./gradlew :publishToMavenLocal
```

To run all tests on all platforms:

```sh
./gradlew allTests
```

To run tests on a single platform, for example the JVM:

```sh
./gradlew jvmTest
```

If you want to skip building Android artefacts create a `local.properties` file in the project's root directory and add the following line:

```
skip.android=true
```

## Contributing to and extending the library

secp256k1-kmp follows 2 simples rules:
- copy as literally as possible what the original [secp256k1 library](https://github.com/bitcoin-core/secp256k1) does: use the same function names, parameters, options, ... 
- follow JNI best practices (memory allocation, error handling, ...)
 
"Porting" C/C++ code that uses [secp256k1](https://github.com/bitcoin-core/secp256k1) should be a no-brainer and we should not have to document secp256k1-kmp


To extend this library and support methods that have been added to specific versions of [secp256k1](https://github.com/bitcoin-core/secp256k1) you have to:
- add new methods to the Secp256k1 interface src/commonMain/kotlin/fr/acinq/secp256k1/Secp256k1.kt (please follow rule #1 above and try and match secp256k1's interface as much as possible)
- implement these new methods in jni/src/main/kotlin/fr/acinq/secp256k1/Secp256k1Jni.kt (JNI implementation) and src/nativeMain/kotlin/fr/acinq/secp256k1/Secp256k1Native.kt (native linux/ios/... implementation)
- update the JNI interface src/main/java/fr/acinq/secp256k1/Secp256k1CFunctions.java (NativeSecp256k1 calls Secp256k1CFunctions)
- generate a new JNI header file jni/c/headers/java/fr_acinq_secp256k1_Secp256k1CFunctions.h with `javac -h jni/c/headers/java jni/src/main/java/fr/acinq/secp256k1/Secp256k1CFunctions.java`
- implement the new methods in jni/c/src/fr_acinq_secp256k1_Secp256k1CFunctions.c

You may also need to modify build files if you need to compile [secp256k1](https://github.com/bitcoin-core/secp256k1) with custom options

We use [secp256k1](https://github.com/bitcoin-core/secp256k1) through git submodules so you may also need to change what they point to
