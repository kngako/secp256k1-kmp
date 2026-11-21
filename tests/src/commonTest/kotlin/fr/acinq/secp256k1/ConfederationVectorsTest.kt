package fr.acinq.secp256k1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ConfederationVectorsTest {
    @Test
    fun descriptorVectors() {
        val vectors = confederationVectors()
        val encodedRpd = vectors.confederationHex("rpd")
        val rpd = Secp256k1.confederationRpdParse(encodedRpd)
        assertEquals(Secp256k1.CONFEDERATION_RPD_SIZE, rpd.size)
        assertTrue(Secp256k1.confederationRpdValidate(rpd))
        assertEquals(encodedRpd.size, Secp256k1.confederationRpdSerializedSize(rpd))
        assertContentEquals(encodedRpd, Secp256k1.confederationRpdSerialize(rpd))
        assertContentEquals(vectors.confederationHex("rpd_hash"), Secp256k1.confederationRpdHash(rpd))

        val encodedKsd = vectors.confederationHex("ksd")
        val ksd = Secp256k1.confederationKsdParse(encodedKsd, rpd)
        assertEquals(Secp256k1.CONFEDERATION_KSD_SIZE, ksd.size)
        assertTrue(Secp256k1.confederationKsdValidate(ksd, rpd))
        assertEquals(encodedKsd.size, Secp256k1.confederationKsdSerializedSize(ksd, rpd))
        assertContentEquals(encodedKsd, Secp256k1.confederationKsdSerialize(ksd, rpd))
        assertContentEquals(vectors.confederationHex("ksd_hash"), Secp256k1.confederationKsdHash(ksd, rpd))
    }

    @Test
    fun accessAnalysisAccountsForEntityOverlap() {
        val vectors = confederationVectors()
        val encodedRpd = vectors.confederationHex("rpd")
        val rpd = Secp256k1.confederationRpdParse(encodedRpd)
        assertEquals(ConfederationAccess(4, 4), Secp256k1.confederationAccessAnalyze(rpd))

        val overlap = confederationShareEntity(encodedRpd, 3, 0)
        assertEquals(ConfederationAccess(3, 3), Secp256k1.confederationAccessAnalyze(Secp256k1.confederationRpdParse(overlap)))

        val moreOverlap = confederationShareEntity(overlap, 4, 1)
        assertEquals(ConfederationAccess(2, 2), Secp256k1.confederationAccessAnalyze(Secp256k1.confederationRpdParse(moreOverlap)))
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationKsdParse(vectors.confederationHex("ksd"), Secp256k1.confederationRpdParse(overlap))
        }
    }

    @Test
    fun malformedDescriptorsAreRejected() {
        val vectors = confederationVectors()
        val encodedRpd = vectors.confederationHex("rpd")
        val rpd = Secp256k1.confederationRpdParse(encodedRpd)
        listOf(
            encodedRpd.copyOf(3),
            encodedRpd.copyOf(encodedRpd.size - 1),
            encodedRpd + 0,
            encodedRpd.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() },
            encodedRpd.copyOf().also { it.confederationWriteU32(4, 2) },
        ).forEach { candidate ->
            assertFailsWith<Secp256k1Exception> { Secp256k1.confederationRpdParse(candidate) }
        }

        val encodedKsd = vectors.confederationHex("ksd")
        listOf(
            encodedKsd.copyOf(encodedKsd.size - 1),
            encodedKsd + 0,
            encodedKsd.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() },
            encodedKsd.copyOf().also { it.confederationWriteU32(4, 2) },
        ).forEach { candidate ->
            assertFailsWith<Secp256k1Exception> { Secp256k1.confederationKsdParse(candidate, rpd) }
        }

        val zeroRpd = ByteArray(Secp256k1.CONFEDERATION_RPD_SIZE)
        val zeroKsd = ByteArray(Secp256k1.CONFEDERATION_KSD_SIZE)
        assertFalse(Secp256k1.confederationRpdValidate(zeroRpd))
        assertEquals(0, Secp256k1.confederationRpdSerializedSize(zeroRpd))
        assertFalse(Secp256k1.confederationKsdValidate(zeroKsd, rpd))
        assertEquals(0, Secp256k1.confederationKsdSerializedSize(zeroKsd, rpd))
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationRpdSerialize(zeroRpd) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationKsdSerialize(zeroKsd, rpd) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationRpdHash(zeroRpd) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationKsdHash(zeroKsd, rpd) }
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationAccessAnalyze(zeroRpd) }
    }
}
