package fr.acinq.secp256k1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Option A signing driven one signer at a time, through the step functions, against upstream's vectors: the key
 * state and shares of the vector DKG, its selection and its tweak sequence. Every message crosses as bytes.
 */
@OptIn(ExperimentalUnsignedTypes::class)
class ConfederationDistributedSigningTest {
    private val groupIds = uintArrayOf(0u, 1u)
    private val innerCounts = intArrayOf(2, 2)
    private val adminIds = uintArrayOf(0u, 1u, 0u, 2u)
    private val roleOf = intArrayOf(0, 1, 3, 5)

    private class Keys(val rpd: ByteArray, val ksd: ByteArray, val shares: Array<ByteArray>, val tweaks: ByteArray, val tweakedKey: ByteArray)

    private fun keys(): Keys {
        val vectors = confederationVectors()
        val rpd = Secp256k1.confederationRpdParse(vectors.confederationHex("rpd"))
        val ksd = Secp256k1.confederationKsdParse(vectors.confederationHex("ksd"), rpd)
        val encodedShares = vectors.confederationHexMap("shares")
        val shares = Array(9) { role ->
            Secp256k1.confederationShareWrap((role / 3).toUInt(), (role % 3).toUInt(), encodedShares.getValue("(${role / 3}, ${role % 3})"), ksd, rpd)
        }
        return Keys(rpd, ksd, shares, vectors.confederationHex("signing_tweak_sequence"), vectors.confederationHex("tweaked_Q").copyOfRange(1, 33))
    }

    private var secrandCounter = 0
    private fun secrand(): ByteArray = ByteArray(32).also {
        it[0] = 0x5e
        it[1] = (++secrandCounter).toByte()
        it[31] = 0x01
    }

    private class Round(val session: ConfederationSignSession, val signers: List<ByteArray>, val transcript: ByteArray)

    /** Steps 1 to 3: every signer builds the session, checks D_sign, and draws a nonce; the coordinator writes the transcript. */
    private fun nonces(keys: Keys, sessionId: ByteArray): Round {
        val session = Secp256k1.confederationSignSessionInit(keys.rpd, keys.ksd, sessionId, groupIds, innerCounts, adminIds, keys.tweaks)
        val signers = roleOf.map { ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE) }
        val pubnonces = roleOf.mapIndexed { i, role ->
            val own = Secp256k1.confederationSignSessionInit(keys.rpd, keys.ksd, sessionId, groupIds, innerCounts, adminIds, keys.tweaks)
            assertTrue(Secp256k1.confederationSignSessionCheck(own.session, keys.rpd, keys.ksd, session.dSign))
            Secp256k1.confederationSignerNonceGen(signers[i], own.session, keys.rpd, keys.ksd, keys.shares[role], session.dSign, secrand())
        }
        return Round(session, signers, Secp256k1.confederationNonceTranscriptWrite(session.session, pubnonces.toTypedArray()))
    }

    @Test
    fun everySignerRunsItsOwnStepsToASignatureUnderTheTweakedKey() {
        val vectors = confederationVectors()
        val keys = keys()
        val message = vectors.confederationHex("message")
        val sessionId = vectors.confederationHex("signing_session_id")
        val round = nonces(keys, sessionId)
        val session = round.session.session
        val dSign = round.session.dSign
        assertContentEquals(vectors.confederationHex("d_sign"), dSign)
        val sizes = Secp256k1.confederationSignMessageSizes(session)
        assertEquals(ConfederationSignMessageSizes(dSign.size, 12 + 74 * 4, 44 + 72 * 4), sizes)
        assertEquals(sizes.nonceTranscript, round.transcript.size)

        // 4. Every signer confirms; 5. the coordinator's certificate, which anyone can check.
        val confirmations = roleOf.mapIndexed { i, role ->
            Secp256k1.confederationSignerConfirm(round.signers[i], session, keys.rpd, keys.ksd, dSign, round.transcript, message, confederationHostSecret(role))
        }
        val certificate = Secp256k1.confederationConfirmationCertificateWrite(session, dSign, round.transcript, message, confirmations.toTypedArray())
        assertEquals(sizes.certificate, certificate.size)
        assertTrue(Secp256k1.confederationConfirmationVerify(session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate))

        // 6. Every signer's partial; the state is spent.
        val partials = roleOf.mapIndexed { i, role ->
            val partial = Secp256k1.confederationSignerPartial(round.signers[i], session, keys.rpd, keys.ksd, keys.shares[role], dSign, round.transcript, message, certificate)
            assertContentEquals(ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE), round.signers[i])
            assertTrue(Secp256k1.confederationMemberPartialVerify(partial, session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, i))
            partial
        }
        assertFalse(Secp256k1.confederationMemberPartialVerify(partials[0], session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, 1))

        // 7. Each group coordinator; 8. the outer coordinator.
        val groupPartials = (0 until 2).map { g ->
            val groupPartial = Secp256k1.confederationGroupPartialAggregate(session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, g, arrayOf(partials[2 * g], partials[2 * g + 1]))
            assertEquals(g, groupPartial.confederationReadU32(0))
            assertTrue(Secp256k1.confederationGroupPartialVerify(groupPartial, session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, g))
            groupPartial
        }
        assertFalse(Secp256k1.confederationGroupPartialVerify(groupPartials[0], session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, 1))
        val signature = Secp256k1.confederationOuterAggregate(session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, groupPartials.toTypedArray())
        assertTrue(Secp256k1.verifySchnorr(signature, message, keys.tweakedKey))
    }

    @Test
    fun aSignerRefusesAnotherSelectionsDSign() {
        val vectors = confederationVectors()
        val keys = keys()
        val sessionId = vectors.confederationHex("signing_session_id")
        val own = Secp256k1.confederationSignSessionInit(keys.rpd, keys.ksd, sessionId, groupIds, innerCounts, adminIds, keys.tweaks)
        val other = Secp256k1.confederationSignSessionInit(keys.rpd, keys.ksd, sessionId, groupIds, innerCounts, uintArrayOf(0u, 1u, 0u, 1u), keys.tweaks)
        assertFalse(Secp256k1.confederationSignSessionCheck(own.session, keys.rpd, keys.ksd, other.dSign))
        // A signer never draws a nonce against a D_sign its own session does not encode.
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationSignerNonceGen(ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE), own.session, keys.rpd, keys.ksd, keys.shares[0], other.dSign, secrand())
        }
    }

    @Test
    fun theRandomnessIsWipedAndTheStateConfirmsOnce() {
        val keys = keys()
        val message = ByteArray(32).also { it[0] = 0xc2.toByte() }
        val other = ByteArray(32).also { it[0] = 0xc3.toByte() }
        val session = Secp256k1.confederationSignSessionInit(keys.rpd, keys.ksd, ByteArray(32).also { it[0] = 0xc4.toByte() }, groupIds, innerCounts, adminIds, keys.tweaks)
        val randomness = secrand()
        val signer = ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE)
        Secp256k1.confederationSignerNonceGen(signer, session.session, keys.rpd, keys.ksd, keys.shares[0], session.dSign, randomness)
        assertContentEquals(ByteArray(32), randomness)

        val signers = listOf(signer) + (1 until 4).map { ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE) }
        val pubnonces = signers.mapIndexed { i, state ->
            if (i == 0) null else Secp256k1.confederationSignerNonceGen(state, session.session, keys.rpd, keys.ksd, keys.shares[roleOf[i]], session.dSign, secrand())
        }
        // Signer 0's nonce is needed for the transcript: draw it again into a fresh state, as a restart would.
        val restarted = ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE)
        val restartedNonce = Secp256k1.confederationSignerNonceGen(restarted, session.session, keys.rpd, keys.ksd, keys.shares[0], session.dSign, secrand())
        val transcript = Secp256k1.confederationNonceTranscriptWrite(session.session, arrayOf(restartedNonce, pubnonces[1]!!, pubnonces[2]!!, pubnonces[3]!!))

        // The first state's nonce is not in the transcript: refused, and the refusal wiped it.
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationSignerConfirm(signer, session.session, keys.rpd, keys.ksd, session.dSign, transcript, message, confederationHostSecret(0))
        }
        assertContentEquals(ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE), signer)

        // A partial before confirmation is refused, and costs the state.
        val early = signers[1].copyOf()
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationSignerPartial(early, session.session, keys.rpd, keys.ksd, keys.shares[roleOf[1]], session.dSign, transcript, message, ByteArray(0))
        }
        assertContentEquals(ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE), early)

        // Confirmed once; a second confirmation, for another message, is refused.
        val beforeConfirm = signers[1].copyOf()
        Secp256k1.confederationSignerConfirm(signers[1], session.session, keys.rpd, keys.ksd, session.dSign, transcript, message, confederationHostSecret(roleOf[1]))
        assertFalse(beforeConfirm.contentEquals(signers[1]))
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationSignerConfirm(signers[1], session.session, keys.rpd, keys.ksd, session.dSign, transcript, other, confederationHostSecret(roleOf[1]))
        }
        assertContentEquals(ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE), signers[1])

        Secp256k1.confederationSignerAbort(signers[2])
        assertContentEquals(ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE), signers[2])
        Secp256k1.confederationSignerAbort(restarted)
        Secp256k1.confederationSignerAbort(signers[3])
    }

    @Test
    fun aPartialUnderACertificateForAnotherMessageIsRefused() {
        val keys = keys()
        val message = ByteArray(32).also { it[0] = 0xc2.toByte() }
        val other = ByteArray(32).also { it[0] = 0xc3.toByte() }
        val round = nonces(keys, ByteArray(32).also { it[0] = 0xc6.toByte() })
        val session = round.session.session
        val dSign = round.session.dSign
        val confirmations = roleOf.mapIndexed { i, role ->
            Secp256k1.confederationSignerConfirm(round.signers[i], session, keys.rpd, keys.ksd, dSign, round.transcript, message, confederationHostSecret(role))
        }
        val certificate = Secp256k1.confederationConfirmationCertificateWrite(session, dSign, round.transcript, message, confirmations.toTypedArray())
        assertFalse(Secp256k1.confederationConfirmationVerify(session, keys.rpd, keys.ksd, dSign, round.transcript, other, certificate))
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationSignerPartial(round.signers[2], session, keys.rpd, keys.ksd, keys.shares[roleOf[2]], dSign, round.transcript, other, certificate)
        }
        assertContentEquals(ByteArray(Secp256k1.CONFEDERATION_SIGNER_SIZE), round.signers[2])
        round.signers.forEach { Secp256k1.confederationSignerAbort(it) }
    }

    @Test
    fun shortArraysFailInsteadOfReadingPastThem() {
        val keys = keys()
        val message = ByteArray(32).also { it[0] = 0xc2.toByte() }
        val round = nonces(keys, ByteArray(32).also { it[0] = 0xc7.toByte() })
        val session = round.session.session
        val dSign = round.session.dSign
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationNonceTranscriptWrite(session, arrayOf(ByteArray(66)))
        }
        val confirmations = roleOf.mapIndexed { i, role ->
            Secp256k1.confederationSignerConfirm(round.signers[i], session, keys.rpd, keys.ksd, dSign, round.transcript, message, confederationHostSecret(role))
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationConfirmationCertificateWrite(session, dSign, round.transcript, message, confirmations.take(3).toTypedArray())
        }
        val certificate = Secp256k1.confederationConfirmationCertificateWrite(session, dSign, round.transcript, message, confirmations.toTypedArray())
        val partials = roleOf.mapIndexed { i, role ->
            Secp256k1.confederationSignerPartial(round.signers[i], session, keys.rpd, keys.ksd, keys.shares[role], dSign, round.transcript, message, certificate)
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationGroupPartialAggregate(session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, 0, arrayOf(partials[0]))
        }
        val first = Secp256k1.confederationGroupPartialAggregate(session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, 0, arrayOf(partials[0], partials[1]))
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationOuterAggregate(session, keys.rpd, keys.ksd, dSign, round.transcript, message, certificate, arrayOf(first))
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationSignerNonceGen(ByteArray(10), session, keys.rpd, keys.ksd, keys.shares[0], dSign, secrand())
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationSignMessageSizes(ByteArray(10))
        }
    }

    @Test
    fun theOneProcessPathTakesCallerRandomnessAndWipesIt() {
        val vectors = confederationVectors()
        val keys = keys()
        val message = vectors.confederationHex("message")
        val secrands = Array(4) { secrand() }
        val signature = Secp256k1.confederationSign(
            keys.rpd, keys.ksd, keys.shares, Array(9) { confederationHostSecret(it) }, ByteArray(32).also { it[0] = 0xc5.toByte() },
            groupIds, innerCounts, adminIds, keys.tweaks, message, secrands,
        )
        assertTrue(Secp256k1.verifySchnorr(signature, message, keys.tweakedKey))
        secrands.forEach { assertContentEquals(ByteArray(32), it) }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationSign(
                keys.rpd, keys.ksd, keys.shares, Array(9) { confederationHostSecret(it) }, ByteArray(32).also { it[0] = 0xc8.toByte() },
                groupIds, innerCounts, adminIds, keys.tweaks, message, Array(3) { secrand() },
            )
        }
    }
}
