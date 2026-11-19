package fr.acinq.secp256k1

import kotlin.test.*

@OptIn(ExperimentalUnsignedTypes::class)
class FrostReducedEnrollmentTest {
    private val thresholdSeckey = Hex.decode("44a2825e4626fa53f52c2e6a407afcb9b7e87d63306b0d69ae3d0d29eb6ca608")

    private class Group(
        val threshPk: ByteArray,
        val secshares: Array<ByteArray>,
        val pubshares: Array<ByteArray>,
        val n: Int,
        val t: Int,
    )

    private class HelperRound(
        val id: UInt,
        val ids: UIntArray,
        val shares: Array<ByteArray>,
        val paramsHash: ByteArray,
    )

    private class Enrollment(
        val rounds: List<HelperRound>,
        val sigmas: Array<ByteArray>,
        val paramsHashes: Array<ByteArray>,
        val newSecshare: ByteArray,
        val newPubshare: ByteArray,
    )

    private fun deal(n: Int, t: Int): Group {
        val (threshPk, secshares, pubshares) = Secp256k1.frostTrustedDealerKeygen(thresholdSeckey, n, t)
        return Group(threshPk, secshares, pubshares, n, t)
    }

    private fun secrand(helper: Int): ByteArray = ByteArray(32) { (it + 1 + 31 * helper).toByte() }

    private fun sessionId(run: Int): ByteArray = ByteArray(32) { (0xa0 + run).toByte() }

    private fun orderedIds(ids: UIntArray, offset: Int, permute: Boolean): UIntArray {
        if (!permute) return ids
        val out = UIntArray(ids.size) { ids[(it + offset) % ids.size] }
        if (offset % 2 == 1) out.reverse()
        return out
    }

    private fun generateRows(g: Group, helperIds: UIntArray, newId: UInt, sessionId: ByteArray, permute: Boolean = false): List<HelperRound> =
        helperIds.mapIndexed { i, myId ->
            val ids = orderedIds(helperIds, i, permute)
            val out = Secp256k1.frostEnrollmentReducedSharesGen(secrand(i), g.secshares[myId.toInt()], g.threshPk, ids, myId, newId, g.n, g.t, sessionId)
            HelperRound(myId, ids, out.first, out.second)
        }

    private fun collectColumn(rounds: List<HelperRound>, recipientIds: UIntArray, myId: UInt): Pair<Array<ByteArray>, Array<ByteArray>> {
        val shares = Array(recipientIds.size) { ByteArray(32) }
        val hashes = Array(recipientIds.size) { ByteArray(32) }
        rounds.forEach { source ->
            val sourcePos = source.ids.indexOf(myId)
            val destPos = recipientIds.indexOf(source.id)
            require(sourcePos >= 0 && destPos >= 0)
            shares[destPos] = source.shares[sourcePos]
            if (source.id < myId) hashes[destPos] = source.paramsHash
        }
        return Pair(shares, hashes)
    }

    private fun runReduced(g: Group, helperIds: UIntArray, newId: UInt, sessionId: ByteArray, permute: Boolean = false): Enrollment {
        val rounds = generateRows(g, helperIds, newId, sessionId, permute)
        rounds.forEach { assertContentEquals(rounds[0].paramsHash, it.paramsHash) }
        val sigmasById = helperIds.associateWith { myId ->
            val recipientIds = orderedIds(helperIds, helperIds.indexOf(myId) + 1, permute)
            val (shares, hashes) = collectColumn(rounds, recipientIds, myId)
            val result = Secp256k1.frostEnrollmentReducedShareAgg(shares, hashes, g.threshPk, recipientIds, myId, newId, g.n, g.t, sessionId)
            assertTrue(result.isOk, "aggregation faulted on helper ${result.mismatchId}")
            assertNull(result.mismatchId)
            result.sigma!!
        }
        val sigmas = helperIds.map { sigmasById.getValue(it) }.toTypedArray()
        val paramsHashes = helperIds.map { id -> rounds.first { it.id == id }.paramsHash }.toTypedArray()
        val helperPubshares = helperIds.map { g.pubshares[it.toInt()] }.toTypedArray()
        val newPubshare = Secp256k1.frostEnrollmentPubshareDerive(helperPubshares, helperIds, newId, g.n, g.t)
        val newSecshare = Secp256k1.frostEnrollmentReducedSecshareGen(sigmas, paramsHashes, g.threshPk, helperIds, newId, g.n, g.t, sessionId, newPubshare)
        return Enrollment(rounds, sigmas, paramsHashes, newSecshare, newPubshare)
    }

    private fun signAndVerify(g: Group, signerIds: UIntArray) {
        val msg = ByteArray(32) { 0x42 }
        val tweakCache = Secp256k1.frostTweakCacheInit(g.threshPk)
        val tweakedPubkey = Secp256k1.frostTweakedPubkeyGet(tweakCache)
        val signerPubshares = signerIds.map { g.pubshares[it.toInt()] }.toTypedArray()
        val nonces = signerIds.mapIndexed { i, id ->
            Secp256k1.frostNonceGen(ByteArray(32) { (0x70 + i).toByte() }, g.secshares[id.toInt()], g.pubshares[id.toInt()], tweakedPubkey, msg, null)
        }
        val secnonces = nonces.map { it.copyOfRange(0, Secp256k1.FROST_SECRET_NONCE_SIZE) }
        val pubnonces = nonces.map { it.copyOfRange(Secp256k1.FROST_SECRET_NONCE_SIZE, it.size) }
        val aggnonce = Secp256k1.frostNonceAgg(pubnonces.toTypedArray())
        val session = Secp256k1.frostSessionInit(aggnonce, signerIds, signerPubshares, g.n, g.t, tweakCache, msg)
        val psigs = signerIds.mapIndexed { i, id ->
            Secp256k1.frostSign(secnonces[i], g.secshares[id.toInt()], session, signerIds, signerPubshares, id)
        }
        psigs.forEachIndexed { i, psig ->
            assertEquals(1, Secp256k1.frostPartialSigVerify(psig, pubnonces[i], signerPubshares[i], session, signerIds, i))
        }
        val sig = Secp256k1.frostPartialSigAgg(session, psigs.toTypedArray())
        assertTrue(Secp256k1.verifySchnorr(sig, msg, tweakedPubkey))
    }

    @Test
    fun sequentialEnrollmentAndSigning() {
        val initial = deal(3, 2)
        val first = runReduced(initial, uintArrayOf(0u, 1u, 2u), 3u, sessionId(0))
        assertContentEquals(Secp256k1.pubkeyCreate(first.newSecshare), first.newPubshare)
        val firstPubshares = initial.pubshares + first.newPubshare
        assertTrue(Secp256k1.frostThresholdInfoValidate(initial.threshPk, firstPubshares, 2))

        val grown = Group(initial.threshPk, initial.secshares + first.newSecshare, firstPubshares, 4, 2)
        val second = runReduced(grown, uintArrayOf(1u, 3u), 4u, sessionId(1))
        val secondPubshares = grown.pubshares + second.newPubshare
        assertTrue(Secp256k1.frostThresholdInfoValidate(grown.threshPk, secondPubshares, 2))
        val finalGroup = Group(grown.threshPk, grown.secshares + second.newSecshare, secondPubshares, 5, 2)
        assertContentEquals(initial.threshPk, finalGroup.threshPk)
        signAndVerify(finalGroup, uintArrayOf(3u, 4u))
    }

    @Test
    fun repairAfterEnrollmentReproducesOriginalShare() {
        val initial = deal(3, 2)
        val enrolled = runReduced(initial, uintArrayOf(0u, 1u, 2u), 3u, sessionId(2))
        val grown = Group(initial.threshPk, initial.secshares + enrolled.newSecshare, initial.pubshares + enrolled.newPubshare, 4, 2)
        val repaired = runReduced(grown, uintArrayOf(0u, 2u, 3u), 1u, sessionId(3))
        assertContentEquals(initial.secshares[1], repaired.newSecshare)
        assertContentEquals(initial.pubshares[1], repaired.newPubshare)
        assertEquals(4, grown.n)
        assertEquals(4, grown.pubshares.size)
    }

    @Test
    fun unsortedIdsAndIndependentPermutations() {
        val g = deal(5, 3)
        val helperIds = uintArrayOf(4u, 0u, 3u)
        val e = runReduced(g, helperIds, 2u, sessionId(4), permute = true)
        assertContentEquals(g.secshares[2], e.newSecshare)
        assertContentEquals(g.pubshares[2], e.newPubshare)
        e.rounds.forEach { source ->
            source.ids.forEachIndexed { j, recipient ->
                if (recipient < source.id) assertContentEquals(ByteArray(32), source.shares[j])
            }
        }
    }

    @Test
    fun fullAndReducedProduceTheSameShare() {
        val g = deal(3, 2)
        val helperIds = uintArrayOf(0u, 1u, 2u)
        val reduced = runReduced(g, helperIds, 3u, sessionId(5))

        val fullRound = helperIds.mapIndexed { i, myId ->
            Secp256k1.frostEnrollmentSharesGen(secrand(i), g.secshares[myId.toInt()], g.threshPk, helperIds, myId, 3u, g.n, g.t)
        }
        val fullSigmas = helperIds.mapIndexed { j, myId ->
            val shares = Array(helperIds.size) { i -> fullRound[i].first[j] }
            val hashes = Array(helperIds.size) { i -> if (i == j) ByteArray(32) else fullRound[i].second }
            val result = Secp256k1.frostEnrollmentShareAgg(shares, hashes, g.threshPk, helperIds, myId, 3u, g.n, g.t)
            assertTrue(result.isOk)
            result.sigma!!
        }.toTypedArray()
        val fullSecshare = Secp256k1.frostEnrollmentSecshareGen(fullSigmas, g.threshPk, helperIds, 3u, g.n, g.t, fullRound[0].second, reduced.newPubshare)
        assertContentEquals(fullSecshare, reduced.newSecshare)
        assertFalse(fullRound[0].second.contentEquals(reduced.paramsHashes[0]))
    }

    @Test
    fun targetRejectsTamperingAndMixedProtocols() {
        val g = deal(3, 2)
        val helperIds = uintArrayOf(0u, 1u, 2u)
        val session = sessionId(6)
        val e = runReduced(g, helperIds, 3u, session)

        helperIds.indices.forEach { i ->
            val hashes = e.paramsHashes.copyOf()
            hashes[i] = hashes[i].copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            assertFailsWith<Secp256k1Exception> {
                Secp256k1.frostEnrollmentReducedSecshareGen(e.sigmas, hashes, g.threshPk, helperIds, 3u, g.n, g.t, session, e.newPubshare)
            }
            val sigmas = e.sigmas.copyOf()
            sigmas[i] = sigmas[i].copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            assertFailsWith<Secp256k1Exception> {
                Secp256k1.frostEnrollmentReducedSecshareGen(sigmas, e.paramsHashes, g.threshPk, helperIds, 3u, g.n, g.t, session, e.newPubshare)
            }
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentReducedSecshareGen(e.sigmas, e.paramsHashes, g.threshPk, helperIds, 3u, g.n, g.t, sessionId(7), e.newPubshare)
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentReducedSecshareGen(e.sigmas, e.paramsHashes, g.threshPk, helperIds, 3u, g.n, g.t, session, g.pubshares[0])
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentReducedSecshareGen(Array(helperIds.size) { ByteArray(32) }, e.paramsHashes, g.threshPk, helperIds, 3u, g.n, g.t, session, e.newPubshare)
        }
        val fullHash = Secp256k1.frostEnrollmentParamsHash(g.threshPk, helperIds, 3u, g.n, g.t)
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentReducedSecshareGen(e.sigmas, Array(helperIds.size) { fullHash }, g.threshPk, helperIds, 3u, g.n, g.t, session, e.newPubshare)
        }
    }

    @Test
    fun shareAggChecksStructureAndAttributesFaultsByIdentifier() {
        val g = deal(5, 2)
        val helperIds = uintArrayOf(1u, 3u, 4u)
        val session = sessionId(8)
        val rounds = generateRows(g, helperIds, 5u, session)

        val smallest = collectColumn(rounds, helperIds, 1u)
        smallest.second.forEach { it.fill(0xa5.toByte()) }
        assertTrue(Secp256k1.frostEnrollmentReducedShareAgg(smallest.first, smallest.second, g.threshPk, helperIds, 1u, 5u, g.n, g.t, session).isOk)

        val omitted = collectColumn(rounds, helperIds, 1u)
        val omittedPos = helperIds.indexOf(3u)
        omitted.first[omittedPos] = omitted.first[omittedPos].copyOf().also { it[31] = 1 }
        val omittedResult = Secp256k1.frostEnrollmentReducedShareAgg(omitted.first, omitted.second, g.threshPk, helperIds, 1u, 5u, g.n, g.t, session)
        assertFalse(omittedResult.isOk)
        assertEquals(3u, omittedResult.mismatchId)

        val wrongHash = collectColumn(rounds, helperIds, 3u)
        val sourcePos = helperIds.indexOf(1u)
        wrongHash.second[sourcePos] = wrongHash.second[sourcePos].copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val hashResult = Secp256k1.frostEnrollmentReducedShareAgg(wrongHash.first, wrongHash.second, g.threshPk, helperIds, 3u, 5u, g.n, g.t, session)
        assertFalse(hashResult.isOk)
        assertEquals(1u, hashResult.mismatchId)

        val invalidScalar = collectColumn(rounds, helperIds, 3u)
        invalidScalar.first[sourcePos] = ByteArray(32) { 0xff.toByte() }
        val scalarResult = Secp256k1.frostEnrollmentReducedShareAgg(invalidScalar.first, invalidScalar.second, g.threshPk, helperIds, 3u, 5u, g.n, g.t, session)
        assertFalse(scalarResult.isOk)
        assertEquals(1u, scalarResult.mismatchId)
    }

    @Test
    fun commitmentDerivationVerifiesReducedRound2() {
        val g = deal(4, 2)
        val helperIds = uintArrayOf(0u, 1u, 2u)
        val session = sessionId(9)
        val e = runReduced(g, helperIds, 4u, session)
        val c0 = Secp256k1.pubKeyCompress(g.threshPk)
        val c1 = Secp256k1.pubKeyCompress(Secp256k1.pubKeyCombine(arrayOf(g.pubshares[0], Secp256k1.pubKeyNegate(g.threshPk))))
        val commitments = arrayOf(c0, c1)

        val derived = Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, commitments, 4u, g.n)
        assertContentEquals(e.newPubshare, derived)
        assertContentEquals(e.newSecshare, Secp256k1.frostEnrollmentReducedSecshareGen(e.sigmas, e.paramsHashes, g.threshPk, helperIds, 4u, g.n, g.t, session, derived))
        assertContentEquals(g.pubshares[2], Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, commitments, 2u, g.n))

        val zeroCoefficient = Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(c0, ByteArray(33)), 4u, g.n)
        assertContentEquals(Secp256k1.pubkeyParse(c0), zeroCoefficient)

        val changedC1 = c1.copyOf().also { it[0] = if (it[0] == 2.toByte()) 3 else 2 }
        val changed = Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(c0, changedC1), 4u, g.n)
        assertFalse(changed.contentEquals(e.newPubshare))
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentReducedSecshareGen(e.sigmas, e.paramsHashes, g.threshPk, helperIds, 4u, g.n, g.t, session, changed)
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(Secp256k1.pubKeyCompress(g.pubshares[0]), c1), 4u, g.n)
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(ByteArray(33), c1), 4u, g.n)
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(c0, ByteArray(33) { 0x7f }), 4u, g.n)
        }
        val negatedC0 = Secp256k1.pubKeyCompress(Secp256k1.pubKeyNegate(c0))
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(c0, negatedC0), 0u, g.n)
        }
    }

    @Test
    fun argumentValidationAndRandomnessContract() {
        val g = deal(4, 2)
        val ids = uintArrayOf(0u, 1u)
        val session = sessionId(10)
        val seed = secrand(0)
        val originalSeed = seed.copyOf()
        val first = Secp256k1.frostEnrollmentReducedSharesGen(seed, g.secshares[0], g.threshPk, ids, 0u, 4u, g.n, g.t, session)
        val second = Secp256k1.frostEnrollmentReducedSharesGen(seed, g.secshares[0], g.threshPk, ids, 0u, 4u, g.n, g.t, sessionId(11))
        assertContentEquals(originalSeed, seed)
        assertFalse(first.second.contentEquals(second.second))
        assertFalse(first.first.contentDeepEquals(second.first))

        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentReducedParamsHash(g.threshPk, ids, 4u, g.n, g.t, ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentReducedParamsHash(g.threshPk, ids, 4u, g.n, 1, session) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentReducedSharesGen(ByteArray(31), g.secshares[0], g.threshPk, ids, 0u, 4u, g.n, g.t, session) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentReducedSharesGen(seed, ByteArray(31), g.threshPk, ids, 0u, 4u, g.n, g.t, session) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentReducedSharesGen(seed, g.secshares[0], g.threshPk, ids, 2u, 4u, g.n, g.t, session) }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.frostEnrollmentReducedShareAgg(arrayOf(ByteArray(32)), arrayOf(ByteArray(32), ByteArray(32)), g.threshPk, ids, 0u, 4u, g.n, g.t, session)
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.frostEnrollmentReducedSecshareGen(arrayOf(ByteArray(32)), arrayOf(ByteArray(32), ByteArray(32)), g.threshPk, ids, 4u, g.n, g.t, session, g.pubshares[0])
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.frostEnrollmentReducedSecshareGen(arrayOf(ByteArray(32), ByteArray(32)), arrayOf(ByteArray(32), ByteArray(32)), g.threshPk, ids, 4u, g.n, g.t, session, ByteArray(32))
        }

        val c0 = Secp256k1.pubKeyCompress(g.threshPk)
        val c1 = Secp256k1.pubKeyCompress(g.pubshares[0])
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(ByteArray(32), arrayOf(c0, c1), 4u, g.n) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(c0), 4u, g.n) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, Array(5) { c0 }, 4u, g.n) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(c0, c1), 5u, g.n) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(c0, c1), 128u, 128) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostEnrollmentPubshareDeriveFromCommitments(g.threshPk, arrayOf(c0, ByteArray(32)), 4u, g.n) }
    }
}
