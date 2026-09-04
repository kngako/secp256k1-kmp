package fr.acinq.secp256k1

import kotlin.test.*

/**
 * FROST enrollment: turning a (t, n) group into a (t, n+1) one, and repairing a lost share, without
 * re-running key generation and without any helper revealing its secret share.
 *
 * The protocol is driven end to end rather than checked against fixed vectors, because what these
 * bindings can get wrong is the marshalling of the two u-entry arrays whose own-slot conventions are
 * deliberately opposite, and the transposition between rounds 1.1 and 1.2. A vector would pin the C
 * module's arithmetic, which its own test suite already covers; driving the rounds pins the wiring.
 *
 * Runs on the JVM and on every native target: the two binding layers marshal these arguments
 * completely differently.
 */
@OptIn(ExperimentalUnsignedTypes::class)
class FrostEnrollmentTest {
    private val thresholdSeckey = Hex.decode("44a2825e4626fa53f52c2e6a407afcb9b7e87d63306b0d69ae3d0d29eb6ca608")

    private class Group(
        val threshPk: ByteArray,
        val secshares: Array<ByteArray>,
        val pubshares: Array<ByteArray>,
        val n: Int,
        val t: Int,
    )

    private fun deal(n: Int, t: Int): Group {
        val (threshPk, secshares, pubshares) = Secp256k1.frostTrustedDealerKeygen(thresholdSeckey, n, t)
        return Group(threshPk, secshares, pubshares, n, t)
    }

    /** Fresh-looking but deterministic per-helper randomness, so a failure reproduces. */
    private fun secrand(helper: Int): ByteArray = ByteArray(32) { (it + 1 + 31 * helper).toByte() }

    private class Enrollment(
        val newSecshare: ByteArray,
        val newPubshare: ByteArray,
        val paramsHash: ByteArray,
        val sigmas: Array<ByteArray>,
    )

    /**
     * Run all three rounds. [helperIds] are the u helpers; [newId] is the target, equal to n to enroll
     * and smaller than n to repair.
     */
    private fun runEnrollment(g: Group, helperIds: UIntArray, newId: UInt): Enrollment {
        val u = helperIds.size

        // Round 1.1: each helper splits its Lagrange-scaled contribution into u additive shares. Entry j of
        // helper i's output is destined for the helper sitting at position j of helperIds.
        val round1 = helperIds.mapIndexed { i, myId ->
            Secp256k1.frostEnrollmentSharesGen(secrand(i), g.secshares[myId.toInt()], g.threshPk, helperIds, myId, newId, g.n, g.t)
        }

        // Every helper must have computed the same parameters hash.
        round1.forEach { assertContentEquals(round1[0].second, it.second) }

        // Round 1.2: transpose. Helper j collects entry j from every helper, and the parameters hash of every
        // helper but itself - its own slot is never read and is left zero on purpose.
        val sigmas = helperIds.mapIndexed { j, myId ->
            val allShares = Array(u) { i -> round1[i].first[j] }
            val hashes = Array(u) { i -> if (i == j) ByteArray(32) else round1[i].second }
            val res = Secp256k1.frostEnrollmentShareAgg(allShares, hashes, g.threshPk, helperIds, myId, newId, g.n, g.t)
            assertTrue(res.isOk, "share aggregation faulted on helper ${res.mismatchId}")
            assertNull(res.mismatchId)
            res.sigma!!
        }.toTypedArray()

        // Round 2: the target sums the values and verifies against the public share it derives itself.
        val helperPubshares = helperIds.map { g.pubshares[it.toInt()] }.toTypedArray()
        val newPubshare = Secp256k1.frostEnrollmentPubshareDerive(helperPubshares, helperIds, newId, g.n, g.t)
        val newSecshare = Secp256k1.frostEnrollmentSecshareGen(sigmas, g.threshPk, helperIds, newId, g.n, g.t, round1[0].second, newPubshare)
        return Enrollment(newSecshare, newPubshare, round1[0].second, sigmas)
    }

    @Test
    fun enrollNewParticipant() {
        // Every helper-set size from t to n, since u is what fixes the alignment of both u-entry arrays.
        for (n in 3..5) {
            for (t in 2..n) {
                for (u in t..n) {
                    val g = deal(n, t)
                    val helperIds = UIntArray(u) { it.toUInt() }
                    val e = runEnrollment(g, helperIds, n.toUInt())
                    // The share the protocol produced is the discrete log of the public share derived
                    // independently from the helpers' public shares.
                    assertContentEquals(e.newPubshare, Secp256k1.pubkeyCreate(e.newSecshare), "n=$n t=$t u=$u")
                    // And the extended table is consistent with the same threshold public key.
                    val extended = g.pubshares + e.newPubshare
                    assertTrue(Secp256k1.frostThresholdInfoValidate(g.threshPk, extended, t), "n=$n t=$t u=$u")
                }
            }
        }
    }

    @Test
    fun repairReproducesTheExistingShare() {
        val g = deal(5, 3)
        // Repair participant 4 using three helpers that exclude it. The result must be that participant's
        // actual share, byte for byte - this is what makes the mode a repair rather than a new share.
        val helperIds = uintArrayOf(0u, 1u, 2u)
        val e = runEnrollment(g, helperIds, 4u)
        assertContentEquals(g.secshares[4], e.newSecshare)
        assertContentEquals(g.pubshares[4], e.newPubshare)
    }

    @Test
    fun paramsHashIdentifiesTheGroup() {
        val g = deal(4, 2)
        val ids = uintArrayOf(0u, 1u)
        val base = Secp256k1.frostEnrollmentParamsHash(g.threshPk, ids, 4u, 4, 2)
        assertEquals(32, base.size)
        // Sorting makes the hash independent of the order the caller lists the helpers in.
        assertContentEquals(base, Secp256k1.frostEnrollmentParamsHash(g.threshPk, uintArrayOf(1u, 0u), 4u, 4, 2))
        // The hash is what every party recomputes, so it must agree with what round 1.1 returns.
        val fromRound1 = Secp256k1.frostEnrollmentSharesGen(secrand(0), g.secshares[0], g.threshPk, ids, 0u, 4u, 4, 2).second
        assertContentEquals(base, fromRound1)
        // Binding the threshold public key is what makes it identify a group rather than a tuple of numbers.
        val other = Secp256k1.frostTrustedDealerKeygen(ByteArray(32) { 0x11 }, 4, 2).first
        assertFalse(base.contentEquals(Secp256k1.frostEnrollmentParamsHash(other, ids, 4u, 4, 2)))
        // Every other component is bound too.
        assertFalse(base.contentEquals(Secp256k1.frostEnrollmentParamsHash(g.threshPk, uintArrayOf(0u, 2u), 4u, 4, 2)))
        assertFalse(base.contentEquals(Secp256k1.frostEnrollmentParamsHash(g.threshPk, ids, 3u, 4, 2)))
    }

    @Test
    fun shareAggAttributesAParameterDisagreement() {
        val g = deal(4, 2)
        val helperIds = uintArrayOf(0u, 1u, 2u)
        val round1 = helperIds.mapIndexed { i, myId ->
            Secp256k1.frostEnrollmentSharesGen(secrand(i), g.secshares[myId.toInt()], g.threshPk, helperIds, myId, 4u, 4, 2)
        }
        // Helper 0 aggregates, but helper 2's hash is the one it would have produced for a different target.
        val wrongHash = Secp256k1.frostEnrollmentParamsHash(g.threshPk, helperIds, 3u, 4, 2)
        val allShares = Array(3) { i -> round1[i].first[0] }
        val hashes = arrayOf(ByteArray(32), round1[1].second, wrongHash)
        val res = Secp256k1.frostEnrollmentShareAgg(allShares, hashes, g.threshPk, helperIds, 0u, 4u, 4, 2)
        assertFalse(res.isOk)
        assertNull(res.sigma)
        // The identifier of the helper at fault, not its index - here they coincide, so the next case
        // uses a helper set where they do not.
        assertEquals(2u, res.mismatchId)
    }

    @Test
    fun shareAggReportsIdentifiersNotIndices() {
        val g = deal(5, 2)
        // Helper ids that are not 0..u-1, so an implementation returning the index would be caught.
        val helperIds = uintArrayOf(1u, 3u, 4u)
        val round1 = helperIds.mapIndexed { i, myId ->
            Secp256k1.frostEnrollmentSharesGen(secrand(i), g.secshares[myId.toInt()], g.threshPk, helperIds, myId, 5u, 5, 2)
        }
        val wrongHash = Secp256k1.frostEnrollmentParamsHash(g.threshPk, helperIds, 2u, 5, 2)
        val allShares = Array(3) { i -> round1[i].first[0] }
        // Position 1 in the array is the helper whose identifier is 3.
        val hashes = arrayOf(ByteArray(32), wrongHash, round1[2].second)
        val res = Secp256k1.frostEnrollmentShareAgg(allShares, hashes, g.threshPk, helperIds, 1u, 5u, 5, 2)
        assertFalse(res.isOk)
        assertEquals(3u, res.mismatchId)
    }

    @Test
    fun shareAggAttributesACorruptShare() {
        val g = deal(4, 2)
        val helperIds = uintArrayOf(0u, 1u, 2u)
        val round1 = helperIds.mapIndexed { i, myId ->
            Secp256k1.frostEnrollmentSharesGen(secrand(i), g.secshares[myId.toInt()], g.threshPk, helperIds, myId, 4u, 4, 2)
        }
        val allShares = Array(3) { i -> round1[i].first[0] }
        // Not a valid scalar: larger than the group order.
        allShares[1] = ByteArray(32) { 0xff.toByte() }
        val hashes = arrayOf(ByteArray(32), round1[1].second, round1[2].second)
        val res = Secp256k1.frostEnrollmentShareAgg(allShares, hashes, g.threshPk, helperIds, 0u, 4u, 4, 2)
        assertFalse(res.isOk)
        assertEquals(1u, res.mismatchId)
    }

    @Test
    fun secshareGenChecksAreLoadBearing() {
        val g = deal(4, 2)
        val helperIds = uintArrayOf(0u, 1u, 2u)
        val e = runEnrollment(g, helperIds, 4u)

        // The expected public share is the only check that the helpers contributed correct values.
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentSecshareGen(e.sigmas, g.threshPk, helperIds, 4u, 4, 2, e.paramsHash, g.pubshares[0])
        }
        // So is the parameters hash, which catches helpers agreeing among themselves on parameters the
        // target does not expect.
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentSecshareGen(e.sigmas, g.threshPk, helperIds, 4u, 4, 2, ByteArray(32), e.newPubshare)
        }
        // Both are optional, and skipping them yields the same share - not recommended, but supported.
        val unchecked = Secp256k1.frostEnrollmentSecshareGen(e.sigmas, g.threshPk, helperIds, 4u, 4, 2, null, null)
        assertContentEquals(e.newSecshare, unchecked)
    }

    @Test
    fun sessionRandomnessIsNotWipedForTheCaller() {
        val g = deal(4, 2)
        val helperIds = uintArrayOf(0u, 1u)
        val secrand = secrand(0)
        val copy = secrand.copyOf()
        Secp256k1.frostEnrollmentSharesGen(secrand, g.secshares[0], g.threshPk, helperIds, 0u, 4u, 4, 2)
        // libsecp256k1 wipes session_secrand32, but neither binding writes the wipe back: single use is the
        // caller's responsibility, exactly as for frostSign's secnonce. Asserted so the behaviour is pinned
        // rather than mistaken for an oversight.
        assertContentEquals(copy, secrand)
    }

    @Test
    fun argumentValidation() {
        val g = deal(4, 2)
        val ids = uintArrayOf(0u, 1u)
        // Threshold below 2 is rejected by the module itself, not just by these bindings.
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentParamsHash(g.threshPk, ids, 4u, 4, 1) }
        // The target must not be one of the helpers.
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentParamsHash(g.threshPk, ids, 1u, 4, 2) }
        // Helper ids must be unique and smaller than n.
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentParamsHash(g.threshPk, uintArrayOf(0u, 0u), 4u, 4, 2) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentParamsHash(g.threshPk, uintArrayOf(0u, 9u), 4u, 4, 2) }
        // The helper count must be between t and n.
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentParamsHash(g.threshPk, uintArrayOf(0u), 4u, 4, 2) }
        // The target may not exceed n.
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentParamsHash(g.threshPk, ids, 5u, 4, 2) }
        // Sizes are checked on every byte array crossing the boundary.
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentParamsHash(ByteArray(32), ids, 4u, 4, 2) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentSharesGen(ByteArray(31), g.secshares[0], g.threshPk, ids, 0u, 4u, 4, 2) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentSharesGen(secrand(0), ByteArray(31), g.threshPk, ids, 0u, 4u, 4, 2) }
        // The caller's own id must appear in the helper set.
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentSharesGen(secrand(0), g.secshares[0], g.threshPk, ids, 2u, 4u, 4, 2) }
        // Array counts must match the helper count.
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.frostEnrollmentShareAgg(arrayOf(ByteArray(32)), arrayOf(ByteArray(32), ByteArray(32)), g.threshPk, ids, 0u, 4u, 4, 2)
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.frostEnrollmentPubshareDerive(arrayOf(g.pubshares[0]), ids, 4u, 4, 2)
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.frostEnrollmentSecshareGen(arrayOf(ByteArray(32)), g.threshPk, ids, 4u, 4, 2, null, null)
        }
    }
}
