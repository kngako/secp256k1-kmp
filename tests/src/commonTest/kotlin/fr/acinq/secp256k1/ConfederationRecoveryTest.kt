package fr.acinq.secp256k1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ConfederationRecoveryTest {
    private fun descriptors(): Triple<ByteArray, ByteArray, ByteArray> {
        val vectors = confederationVectors()
        val rpd = Secp256k1.confederationRpdParse(vectors.confederationHex("rpd"))
        val ksd = Secp256k1.confederationKsdParse(vectors.confederationHex("ksd"), rpd)
        val share = Secp256k1.confederationShareWrap(0u, 0u, vectors.confederationHexMap("shares").getValue("(0, 0)"), ksd, rpd)
        return Triple(rpd, ksd, share)
    }

    @Test
    fun shareWrapValidateAndRebind() {
        val vectors = confederationVectors()
        val (rpd, ksd, share) = descriptors()
        assertEquals(Secp256k1.CONFEDERATION_SHARE_SIZE, share.size)
        assertTrue(Secp256k1.confederationShareValidate(share, ksd, rpd))
        val rebound = Secp256k1.confederationShareRebind(share, confederationHostSecret(0), ksd, rpd)
        assertTrue(Secp256k1.confederationShareValidate(rebound, ksd, rpd))
        assertTrue(Secp256k1.confederationShareValidate(share, ksd, rpd))
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationShareRebind(share, confederationHostSecret(1), ksd, rpd)
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationShareWrap(0u, 1u, vectors.confederationHexMap("shares").getValue("(0, 0)"), ksd, rpd)
        }
        val badScalar = vectors.confederationHexMap("shares").getValue("(0, 0)").also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationShareWrap(0u, 0u, badScalar, ksd, rpd) }
        assertFalse(Secp256k1.confederationShareValidate(ByteArray(Secp256k1.CONFEDERATION_SHARE_SIZE), ksd, rpd))
    }

    @Test
    fun recoveryReferenceVectorAndRoundTrip() {
        val vectors = confederationVectors()
        val (rpd, ksd, share) = descriptors()
        val recovery = Secp256k1.confederationRecoveryIssue(
            share,
            confederationHostSecret(0),
            ksd,
            rpd,
            0,
            vectors.confederationHex("transition_hash"),
            vectors.confederationHex("recovery_nonce"),
        )
        val expected = vectors.confederationHex("recovery_package")
        assertEquals(Secp256k1.CONFEDERATION_RECOVERY_OPAQUE_SIZE, recovery.size)
        assertEquals(Secp256k1.CONFEDERATION_RECOVERY_SIZE, Secp256k1.confederationRecoverySerializedSize(recovery))
        assertContentEquals(expected, Secp256k1.confederationRecoverySerialize(recovery))

        val parsed = Secp256k1.confederationRecoveryParse(expected, confederationHostSecret(0))
        assertContentEquals(expected, Secp256k1.confederationRecoverySerialize(parsed))
        val recovered = Secp256k1.confederationRecoveryOpen(parsed, confederationHostSecret(0), ksd, rpd)
        assertTrue(Secp256k1.confederationShareValidate(recovered, ksd, rpd))
    }

    @Test
    fun recoveryRejectsWrongKeysTamperingAndInvalidOperations() {
        val vectors = confederationVectors()
        val (rpd, ksd, share) = descriptors()
        val encoded = vectors.confederationHex("recovery_package")
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationRecoveryParse(encoded, confederationHostSecret(1))
        }
        val tampered = encoded.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationRecoveryParse(tampered, confederationHostSecret(0))
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationRecoveryParse(encoded + 0, confederationHostSecret(0))
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationRecoveryIssue(share, confederationHostSecret(0), ksd, rpd, 8, vectors.confederationHex("transition_hash"), vectors.confederationHex("recovery_nonce"))
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationRecoveryIssue(share, confederationHostSecret(0), ksd, rpd, 0, ByteArray(32), vectors.confederationHex("recovery_nonce"))
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationRecoveryIssue(share, confederationHostSecret(1), ksd, rpd, 0, vectors.confederationHex("transition_hash"), vectors.confederationHex("recovery_nonce"))
        }

        val zero = ByteArray(Secp256k1.CONFEDERATION_RECOVERY_OPAQUE_SIZE)
        assertEquals(0, Secp256k1.confederationRecoverySerializedSize(zero))
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationRecoverySerialize(zero) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationRecoveryOpen(zero, confederationHostSecret(0), ksd, rpd) }
    }
}
