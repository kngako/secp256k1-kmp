package fr.acinq.secp256k1

import kotlin.test.*

class FrostTest {
    private val thresholdSeckey = Hex.decode("EEC1CB7D1B7254C5CAB0D9C61AB02E643D464A59FE6C96A7EFE871F07C5AEF54")
    private val msg = ByteArray(32) { 0x42 }

    private fun keygen(n: Int, t: Int): Triple<ByteArray, Array<ByteArray>, Array<ByteArray>> = Secp256k1.frostTrustedDealerKeygen(thresholdSeckey, n, t)

    @Test
    fun trustedDealerKeygenAndValidate() {
        val (thresholdPubkey, secshares, pubshares) = keygen(3, 2)
        assertEquals(65, thresholdPubkey.size)
        assertEquals(3, secshares.size)
        assertEquals(3, pubshares.size)
        // each public share is the public key of the corresponding secret share
        secshares.forEachIndexed { i, secshare ->
            assertContentEquals(Secp256k1.pubkeyCreate(secshare), pubshares[i])
        }
        // key material is consistent
        assertTrue(Secp256k1.frostThresholdInfoValidate(thresholdPubkey, pubshares, 2))
        // tampered public share is rejected
        val badPubshares = pubshares.copyOf()
        badPubshares[1] = Secp256k1.pubkeyCreate(ByteArray(32) { 0x11 })
        assertFalse(Secp256k1.frostThresholdInfoValidate(thresholdPubkey, badPubshares, 2))
        // wrong threshold public key is rejected
        val badThresholdPubkey = Secp256k1.pubkeyCreate(ByteArray(32) { 0x22 })
        assertFalse(Secp256k1.frostThresholdInfoValidate(badThresholdPubkey, pubshares, 2))
    }

    /** Run a complete 2-of-3 signing session with the given (possibly tweaked) tweak cache. */
    private fun runSigningSession(tweakCache: ByteArray, tweakedPubkey: ByteArray, secshares: Array<ByteArray>, pubshares: Array<ByteArray>, ids: UIntArray) {
        val n = 3
        val t = 2
        // 1. every signer generates a nonce and sends the public nonce to the coordinator
        val nonces = ids.mapIndexed { i, id ->
            Secp256k1.frostNonceGen(ByteArray(32) { (0xA0 + i).toByte() }, secshares[id.toInt()], pubshares[id.toInt()], tweakedPubkey, msg, null)
        }
        val secnonces = nonces.map { it.copyOfRange(0, Secp256k1.FROST_SECRET_NONCE_SIZE) }
        val pubnonces = nonces.map { it.copyOfRange(Secp256k1.FROST_SECRET_NONCE_SIZE, Secp256k1.FROST_SECRET_NONCE_SIZE + Secp256k1.FROST_PUBLIC_NONCE_SIZE) }
        // 2. the coordinator aggregates the public nonces
        val aggnonce = Secp256k1.frostNonceAgg(pubnonces.toTypedArray())
        assertEquals(Secp256k1.FROST_PUBLIC_NONCE_SIZE, aggnonce.size)
        // 3. everyone initializes the session with the same parameters
        val signerPubshares = ids.map { pubshares[it.toInt()] }.toTypedArray()
        val session = Secp256k1.frostSessionInit(aggnonce, ids, signerPubshares, n, t, tweakCache, msg)
        assertEquals(Secp256k1.FROST_SESSION_SIZE, session.size)
        // 4. every signer produces a partial signature
        val psigs = ids.mapIndexed { i, id -> Secp256k1.frostSign(secnonces[i], secshares[id.toInt()], session, ids, signerPubshares, id) }
        // 5. the coordinator verifies and aggregates the partial signatures
        psigs.forEachIndexed { i, psig ->
            assertEquals(1, Secp256k1.frostPartialSigVerify(psig, pubnonces[i], signerPubshares[i], session, ids, i))
        }
        val sig = Secp256k1.frostPartialSigAgg(session, psigs.toTypedArray())
        assertEquals(64, sig.size)
        assertTrue(Secp256k1.verifySchnorr(sig, msg, tweakedPubkey))
        // a partial signature from signer 0 must not verify as signer 1's
        assertEquals(0, Secp256k1.frostPartialSigVerify(psigs[0], pubnonces[1], signerPubshares[1], session, ids, 1))
    }

    @Test
    fun signingSession() {
        val (thresholdPubkey, secshares, pubshares) = keygen(3, 2)
        val tweakCache = Secp256k1.frostTweakCacheInit(thresholdPubkey)
        assertEquals(Secp256k1.FROST_TWEAK_CACHE_SIZE, tweakCache.size)
        // without tweaks, the tweaked public key is the x-only threshold public key
        val tweakedPubkey = Secp256k1.frostTweakedPubkeyGet(tweakCache)
        assertEquals(32, tweakedPubkey.size)
        assertContentEquals(Secp256k1.pubKeyCompress(thresholdPubkey).copyOfRange(1, 33), tweakedPubkey)
        // sign with participants 0 and 2 (non-contiguous ids)
        runSigningSession(tweakCache, tweakedPubkey, secshares, pubshares, uintArrayOf(0u, 2u))
    }

    @Test
    fun tweakedSigningSession() {
        val (thresholdPubkey, secshares, pubshares) = keygen(3, 2)
        val tweakCache = Secp256k1.frostTweakCacheInit(thresholdPubkey)
        val tweak32 = ByteArray(32) { 0x33 }
        val tweakedPubkey = Secp256k1.frostPubkeyXonlyTweakAdd(tweakCache, tweak32)
        assertContentEquals(tweakedPubkey, Secp256k1.frostTweakedPubkeyGet(tweakCache))
        runSigningSession(tweakCache, tweakedPubkey, secshares, pubshares, uintArrayOf(0u, 1u))
    }

    @Test
    fun deterministicSign() {
        val (thresholdPubkey, secshares, pubshares) = keygen(3, 2)
        val tweakCache = Secp256k1.frostTweakCacheInit(thresholdPubkey)
        val tweakedPubkey = Secp256k1.frostTweakedPubkeyGet(tweakCache)
        val ids = uintArrayOf(0u, 1u)
        val signerPubshares = ids.map { pubshares[it.toInt()] }.toTypedArray()

        // signer 0 uses a regular random nonce, signer 1 signs deterministically against signer 0's nonce
        val nonce0 = Secp256k1.frostNonceGen(ByteArray(32) { 0x77 }, secshares[0], pubshares[0], tweakedPubkey, msg, null)
        val secnonce0 = nonce0.copyOfRange(0, Secp256k1.FROST_SECRET_NONCE_SIZE)
        val pubnonce0 = nonce0.copyOfRange(Secp256k1.FROST_SECRET_NONCE_SIZE, Secp256k1.FROST_SECRET_NONCE_SIZE + Secp256k1.FROST_PUBLIC_NONCE_SIZE)
        val aggOtherNonce1 = Secp256k1.frostNonceAgg(arrayOf(pubnonce0))
        val (psig1, pubnonce1) = Secp256k1.frostDeterministicSign(secshares[1], 1u, aggOtherNonce1, ids, signerPubshares, 3, 2, tweakCache, msg, null)

        val aggnonce = Secp256k1.frostNonceAgg(arrayOf(pubnonce0, pubnonce1))
        val session = Secp256k1.frostSessionInit(aggnonce, ids, signerPubshares, 3, 2, tweakCache, msg)
        val psig0 = Secp256k1.frostSign(secnonce0, secshares[0], session, ids, signerPubshares, 0u)
        assertEquals(1, Secp256k1.frostPartialSigVerify(psig0, pubnonce0, pubshares[0], session, ids, 0))
        assertEquals(1, Secp256k1.frostPartialSigVerify(psig1, pubnonce1, pubshares[1], session, ids, 1))
        val sig = Secp256k1.frostPartialSigAgg(session, arrayOf(psig0, psig1))
        assertTrue(Secp256k1.verifySchnorr(sig, msg, tweakedPubkey))
    }

    @Test
    fun deterministicSignSoleSigner() {
        val (thresholdPubkey, secshares, pubshares) = keygen(1, 1)
        val tweakCache = Secp256k1.frostTweakCacheInit(thresholdPubkey)
        val tweakedPubkey = Secp256k1.frostTweakedPubkeyGet(tweakCache)
        val ids = uintArrayOf(0u)
        // a sole signer needs no other nonces
        val (psig, pubnonce) = Secp256k1.frostDeterministicSign(secshares[0], 0u, null, ids, pubshares, 1, 1, tweakCache, msg, null)
        val aggnonce = Secp256k1.frostNonceAgg(arrayOf(pubnonce))
        val session = Secp256k1.frostSessionInit(aggnonce, ids, pubshares, 1, 1, tweakCache, msg)
        assertEquals(1, Secp256k1.frostPartialSigVerify(psig, pubnonce, pubshares[0], session, ids, 0))
        val sig = Secp256k1.frostPartialSigAgg(session, arrayOf(psig))
        assertTrue(Secp256k1.verifySchnorr(sig, msg, tweakedPubkey))
    }

    /**
     * The tweak cache, session and secret nonce are opaque blobs that libsecp256k1 tags with a magic prefix
     * and validates with ARG_CHECK, whose default handler aborts the process. Passing a blob that has the right
     * size but does not hold a frost object must raise an exception instead of killing the process: if any of
     * these cases regresses, this test does not fail, it takes the whole test run down with SIGABRT.
     */
    @Test
    fun rejectMalformedOpaqueBlobs() {
        val (thresholdPubkey, secshares, pubshares) = keygen(3, 2)
        val tweakCache = Secp256k1.frostTweakCacheInit(thresholdPubkey)
        val tweakedPubkey = Secp256k1.frostTweakedPubkeyGet(tweakCache)
        val tweak32 = ByteArray(32) { 0x33 }
        val ids = uintArrayOf(0u, 1u)

        // A genuine signing session, so that exactly one blob is malformed in each case below.
        val nonce = Secp256k1.frostNonceGen(ByteArray(32) { 0x44 }, secshares[0], pubshares[0], tweakedPubkey, msg, null)
        val secnonce = nonce.copyOfRange(0, Secp256k1.FROST_SECRET_NONCE_SIZE)
        val pubnonce = nonce.copyOfRange(Secp256k1.FROST_SECRET_NONCE_SIZE, Secp256k1.FROST_SECRET_NONCE_SIZE + Secp256k1.FROST_PUBLIC_NONCE_SIZE)
        val aggnonce = Secp256k1.frostNonceAgg(arrayOf(pubnonce, pubnonce))
        val session = Secp256k1.frostSessionInit(aggnonce, ids, arrayOf(pubshares[0], pubshares[1]), 3, 2, tweakCache, msg)
        val psig = Secp256k1.frostSign(secnonce, secshares[0], session, ids, arrayOf(pubshares[0], pubshares[1]), 0u)

        // Sanity check: the valid blobs are still accepted, so the checks above are not rejecting everything.
        assertEquals(1, Secp256k1.frostPartialSigVerify(psig, pubnonce, pubshares[0], session, ids, 0))

        // Right size, wrong content.
        val badCache = ByteArray(Secp256k1.FROST_TWEAK_CACHE_SIZE)
        val badSession = ByteArray(Secp256k1.FROST_SESSION_SIZE)
        val badSecnonce = ByteArray(Secp256k1.FROST_SECRET_NONCE_SIZE)

        assertFails { Secp256k1.frostTweakedPubkeyGet(badCache) }
        assertFails { Secp256k1.frostPubkeyXonlyTweakAdd(badCache, tweak32) }
        assertFails { Secp256k1.frostPubkeyEcTweakAdd(badCache, tweak32) }
        assertFails { Secp256k1.frostSessionInit(aggnonce, ids, null, 3, 2, badCache, msg) }
        assertFails { Secp256k1.frostSign(badSecnonce, secshares[0], session, ids, null, 0u) }
        assertFails { Secp256k1.frostSign(secnonce, secshares[0], badSession, ids, null, 0u) }
        assertFails { Secp256k1.frostPartialSigVerify(psig, pubnonce, pubshares[0], badSession, ids, 0) }
        assertFails { Secp256k1.frostPartialSigAgg(badSession, arrayOf(psig)) }
        assertFails { Secp256k1.frostDeterministicSign(secshares[0], 0u, null, ids, null, 3, 2, badCache, msg, null) }
    }
}
