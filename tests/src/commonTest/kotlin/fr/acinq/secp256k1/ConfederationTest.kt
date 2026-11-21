package fr.acinq.secp256k1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalUnsignedTypes::class)
class ConfederationTest {
    private fun dealerSeed(role: Int): ByteArray = ByteArray(32).also {
        it[0] = 0xd0.toByte()
        it[31] = (role + 1).toByte()
    }

    private fun recoveryNonce(role: Int): ByteArray = ByteArray(32).also {
        it[0] = 0x42
        it[31] = (role + 1).toByte()
    }

    private fun hostSecrets(): Array<ByteArray> = Array(9) { confederationHostSecret(it) }

    private fun runDkg(sessionSeed: ByteArray): Pair<ByteArray, ConfederationDkgResult> {
        val rpd = Secp256k1.confederationRpdParse(confederationVectors().confederationHex("rpd"))
        val result = Secp256k1.confederationDkg(
            rpd,
            sessionSeed,
            hostSecrets(),
            Array(9) { dealerSeed(it) },
            Array(9) { recoveryNonce(it) },
        )
        return Pair(rpd, result)
    }

    @Test
    fun deterministicDkgRecoveryAndSigning() {
        val vectors = confederationVectors()
        val (rpd, result) = runDkg(vectors.confederationHex("dkg_session_seed"))
        assertTrue(Secp256k1.confederationDkgWorkSize(rpd) > 0)
        assertEquals(9, result.roleCount)
        assertEquals(9, result.recoveries.size)
        assertTrue(Secp256k1.confederationKsdValidate(result.ksd, rpd))
        assertTrue(Secp256k1.confederationTransitionValidate(result.transition, null, null, rpd, result.ksd))
        assertContentEquals(vectors.confederationHex("dkg_fixed_ksd"), Secp256k1.confederationKsdSerialize(result.ksd, rpd))
        assertContentEquals(vectors.confederationHex("dkg_fixed_transition"), Secp256k1.confederationTransitionSerialize(result.transition, null, null, rpd, result.ksd))
        assertContentEquals(vectors.confederationHex("dkg_fixed_transition_hash"), Secp256k1.confederationTransitionHash(result.transition))
        assertContentEquals(vectors.confederationHex("dkg_fixed_recovery"), Secp256k1.confederationRecoverySerialize(result.recoveries[0]))

        result.shares.forEach { assertTrue(Secp256k1.confederationShareValidate(it, result.ksd, rpd)) }
        val recovered = Secp256k1.confederationRecoveryOpen(result.recoveries[0], confederationHostSecret(0), result.ksd, rpd)
        assertTrue(Secp256k1.confederationShareValidate(recovered, result.ksd, rpd))

        val session = ByteArray(32).also { it[0] = 0xb1.toByte() }
        val message = ByteArray(32).also { it[0] = 0xb2.toByte() }
        val signature = Secp256k1.confederationSign(
            rpd,
            result.ksd,
            result.shares,
            hostSecrets(),
            session,
            uintArrayOf(0u, 1u),
            intArrayOf(2, 2),
            uintArrayOf(0u, 1u, 0u, 1u),
            ByteArray(4),
            message,
        )
        assertTrue(Secp256k1.verifySchnorr(signature, message, Secp256k1.confederationKsdPubkeyGet(result.ksd, rpd)))
    }

    @Test
    fun tweakedSigningVectorVerifies() {
        val vectors = confederationVectors()
        val rpd = Secp256k1.confederationRpdParse(vectors.confederationHex("rpd"))
        val ksd = Secp256k1.confederationKsdParse(vectors.confederationHex("ksd"), rpd)
        val encodedShares = vectors.confederationHexMap("shares")
        val shares = Array(9) { role ->
            val group = role / 3
            val admin = role % 3
            Secp256k1.confederationShareWrap(group.toUInt(), admin.toUInt(), encodedShares.getValue("($group, $admin)"), ksd, rpd)
        }
        val signature = Secp256k1.confederationSign(
            rpd,
            ksd,
            shares,
            hostSecrets(),
            vectors.confederationHex("signing_session_id"),
            uintArrayOf(0u, 1u),
            intArrayOf(2, 2),
            uintArrayOf(0u, 1u, 0u, 2u),
            vectors.confederationHex("signing_tweak_sequence"),
            vectors.confederationHex("message"),
        )
        assertEquals(64, signature.size)
        val tweakedPubkey = vectors.confederationHex("tweaked_Q").copyOfRange(1, 33)
        assertTrue(Secp256k1.verifySchnorr(signature, vectors.confederationHex("message"), tweakedPubkey))
        val basePubkey = vectors.confederationHex("X").copyOfRange(1, 33)
        assertContentEquals(basePubkey, Secp256k1.confederationKsdPubkeyGet(ksd, rpd))
    }

    @Test
    fun conflictingGenesisCertificatesAreDetected() {
        val vectors = confederationVectors()
        val firstSeed = vectors.confederationHex("dkg_session_seed")
        val (rpd, first) = runDkg(firstSeed)
        val secondSeed = firstSeed.copyOf().also { it[31] = (it[31].toInt() xor 1).toByte() }
        val (_, second) = runDkg(secondSeed)
        assertTrue(Secp256k1.confederationTransitionValidate(second.transition, null, null, rpd, second.ksd))
        assertFalse(Secp256k1.confederationTransitionConflicts(first.transition, first.transition))
        assertTrue(Secp256k1.confederationTransitionConflicts(first.transition, second.transition))
    }

    @Test
    fun invalidCoalitionsAndRoleArraysAreRejected() {
        val vectors = confederationVectors()
        val (rpd, result) = runDkg(vectors.confederationHex("dkg_session_seed"))
        val message = ByteArray(32).also { it[0] = 0xb2.toByte() }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationSign(
                rpd, result.ksd, result.shares, hostSecrets(), ByteArray(32).also { it[0] = 0xb3.toByte() },
                uintArrayOf(0u), intArrayOf(2), uintArrayOf(0u, 1u), ByteArray(4), message,
            )
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationSign(
                rpd, result.ksd, result.shares, hostSecrets(), ByteArray(32).also { it[0] = 0xb4.toByte() },
                uintArrayOf(0u, 1u), intArrayOf(1, 1), uintArrayOf(0u, 0u), ByteArray(4), message,
            )
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationSign(
                rpd, result.ksd, result.shares.dropLast(1).toTypedArray(), hostSecrets(), ByteArray(32).also { it[0] = 0xb5.toByte() },
                uintArrayOf(0u, 1u), intArrayOf(2, 2), uintArrayOf(0u, 1u, 0u, 1u), ByteArray(4), message,
            )
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationDkg(rpd, vectors.confederationHex("dkg_session_seed"), hostSecrets().dropLast(1).toTypedArray(), Array(9) { dealerSeed(it) }, Array(9) { recoveryNonce(it) })
        }
        assertEquals(0, Secp256k1.confederationDkgWorkSize(ByteArray(Secp256k1.CONFEDERATION_RPD_SIZE)))
    }
}
