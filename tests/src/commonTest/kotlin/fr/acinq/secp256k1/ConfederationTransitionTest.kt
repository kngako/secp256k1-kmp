package fr.acinq.secp256k1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ConfederationTransitionTest {
    @Test
    fun genesisTransitionVector() {
        val vectors = confederationVectors()
        val rpd = Secp256k1.confederationRpdParse(vectors.confederationHex("rpd"))
        val ksd = Secp256k1.confederationKsdParse(vectors.confederationHex("ksd"), rpd)
        val encoded = vectors.confederationHex("genesis_transition")
        val transition = Secp256k1.confederationTransitionParse(encoded, null, null, rpd, ksd)

        assertEquals(Secp256k1.CONFEDERATION_TRANSITION_SIZE, transition.size)
        assertTrue(Secp256k1.confederationTransitionValidate(transition, null, null, rpd, ksd))
        assertEquals(encoded.size, Secp256k1.confederationTransitionSerializedSize(transition, null, null, rpd, ksd))
        assertContentEquals(encoded, Secp256k1.confederationTransitionSerialize(transition, null, null, rpd, ksd))
        assertContentEquals(vectors.confederationHex("transition_hash"), Secp256k1.confederationTransitionHash(transition))
        assertFalse(Secp256k1.confederationTransitionConflicts(transition, transition))
        assertFalse(Secp256k1.confederationTransitionCheckSuccessor(transition, rpd, ksd))
    }

    @Test
    fun malformedTransitionsAreRejected() {
        val vectors = confederationVectors()
        val rpd = Secp256k1.confederationRpdParse(vectors.confederationHex("rpd"))
        val ksd = Secp256k1.confederationKsdParse(vectors.confederationHex("ksd"), rpd)
        val encoded = vectors.confederationHex("genesis_transition")
        listOf(
            encoded.copyOf(encoded.size - 1),
            encoded + 0,
            encoded.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
        ).forEach { candidate ->
            assertFailsWith<Secp256k1Exception> {
                Secp256k1.confederationTransitionParse(candidate, null, null, rpd, ksd)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationTransitionParse(encoded, rpd, null, rpd, ksd)
        }

        val zero = ByteArray(Secp256k1.CONFEDERATION_TRANSITION_SIZE)
        assertFalse(Secp256k1.confederationTransitionConflicts(zero, zero))
        assertFalse(Secp256k1.confederationTransitionValidate(zero, null, null, rpd, ksd))
        assertEquals(0, Secp256k1.confederationTransitionSerializedSize(zero, null, null, rpd, ksd))
        assertFailsWith<Secp256k1Exception> { Secp256k1.confederationTransitionHash(zero) }
    }
}
