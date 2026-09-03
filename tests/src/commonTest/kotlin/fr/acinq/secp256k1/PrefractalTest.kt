package fr.acinq.secp256k1

import kotlin.test.*

/**
 * Nested FROST+MuSig2: a FROST t-of-n group occupying one participant slot of an ordinary musig2
 * session, alongside one stock musig2 cosigner.
 *
 * The port of the C module's round trip. Runs on the JVM and on every native target, which is the
 * point: the two binding layers marshal these arguments completely differently, and the nonce
 * generation below passes msg = null, exactly the empty-vs-absent hazard class that the native
 * FROST bindings needed a fix for once already.
 */
@OptIn(ExperimentalUnsignedTypes::class)
class PrefractalTest {
    // Two FIXED threshold secret keys, one of each Y parity of the resulting threshold public key.
    // The nested equation carries no g_frost factor, and NOT because the tweak cache is the
    // identity: stock frost's key-side factor is -1 for every odd-Y threshold key. A binding that
    // dropped or added that negation would pass for even-Y groups and fail for odd-Y ones, so both
    // are pinned rather than left to a random draw.
    private val thresholdSeckeyEven = Hex.decode("44a2825e4626fa53f52c2e6a407afcb9b7e87d63306b0d69ae3d0d29eb6ca608")
    private val thresholdSeckeyOdd = Hex.decode("d327593fe753f6fde38f29fd2639d44f62054babea21a359a41d651c81f1e01e")

    private val msg = ByteArray(32) { 0x42 }
    private val cosignerSeckey = ByteArray(32) { 0x17 }

    private class Session(
        val ids: UIntArray,
        val secshares: Array<ByteArray>,
        val pubshares: Array<ByteArray>,
        val signerPubshares: Array<ByteArray>,
        val threshPk: ByteArray,
        val tweakCache: ByteArray,
        val secnonces: List<ByteArray>,
        val pubnonces: List<ByteArray>,
        val groupPubnonce: ByteArray,
        val aggnonce: ByteArray,
        val keyaggCache: ByteArray,
        val cosignerSecnonce: ByteArray,
        val cosignerAggnonce: ByteArray,
        val fullAggnonce: ByteArray,
        val aggXonly: ByteArray,
    )

    /**
     * Deal a group, aggregate it with one stock musig2 cosigner, and run round one on both sides.
     *
     * @param groupFirst which side of the outer aggregation the group key sits on. BIP 327 KeyAgg
     *   gives the second distinct key a coefficient of exactly 1 and hashes every other one, so the
     *   two orders exercise different arithmetic for the group.
     * @param xonlyTweak applied to the OUTER cache only, which is the arrangement the channel
     *   protocols use.
     */
    private fun setup(n: Int, t: Int, threshSeckey: ByteArray, groupFirst: Boolean, xonlyTweak: ByteArray?): Session {
        val (threshPk, secshares, pubshares) = Secp256k1.frostTrustedDealerKeygen(threshSeckey, n, t)
        val tweakCache = Secp256k1.frostTweakCacheInit(threshPk)
        val ids = UIntArray(t) { it.toUInt() }
        val signerPubshares = ids.map { pubshares[it.toInt()] }.toTypedArray()

        val cosignerPk = Secp256k1.pubkeyCreate(cosignerSeckey)
        val outerKeys = if (groupFirst) arrayOf(threshPk, cosignerPk) else arrayOf(cosignerPk, threshPk)
        val keyaggCache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        Secp256k1.musigPubkeyAgg(outerKeys, keyaggCache)
        val aggXonly = if (xonlyTweak == null) {
            Secp256k1.musigPubkeyGet(keyaggCache).drop(1).take(32).toByteArray()
        } else {
            // Tweaking mutates the cache in place; the tweaked aggregate key is what the final
            // signature verifies against.
            Secp256k1.musigPubkeyXonlyTweakAdd(keyaggCache, xonlyTweak).drop(1).take(32).toByteArray()
        }

        // Cosigner round one.
        val cosignerNonce = Secp256k1.musigNonceGen(ByteArray(32) { 0x33 }, cosignerSeckey, cosignerPk, msg, keyaggCache, null)
        val cosignerSecnonce = cosignerNonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE)
        val cosignerPubnonce = cosignerNonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, cosignerNonce.size)
        val cosignerAggnonce = Secp256k1.musigNonceAgg(arrayOf(cosignerPubnonce))

        // Group round one. msg = null: the wire nonce is published before the message exists, which
        // is the whole reason this module's nonce coefficient does not commit to it.
        val threshPk32 = threshPk.drop(1).take(32).toByteArray()
        val nonces = ids.mapIndexed { i, id ->
            Secp256k1.frostNonceGen(ByteArray(32) { (0xA0 + i).toByte() }, secshares[id.toInt()], pubshares[id.toInt()], threshPk32, null, null)
        }
        val secnonces = nonces.map { it.copyOfRange(0, Secp256k1.FROST_SECRET_NONCE_SIZE) }
        val pubnonces = nonces.map { it.copyOfRange(Secp256k1.FROST_SECRET_NONCE_SIZE, nonces[0].size) }

        val (groupPubnonce, aggnonce) = Secp256k1.prefractalNonceAgg(pubnonces.toTypedArray(), ids, threshPk)
        assertEquals(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE, groupPubnonce.size)
        assertEquals(Secp256k1.FROST_PUBLIC_NONCE_SIZE, aggnonce.size)

        val allNonces = if (groupFirst) arrayOf(groupPubnonce, cosignerPubnonce) else arrayOf(cosignerPubnonce, groupPubnonce)
        val fullAggnonce = Secp256k1.musigNonceAgg(allNonces)

        return Session(ids, secshares, pubshares, signerPubshares, threshPk, tweakCache, secnonces, pubnonces,
                       groupPubnonce, aggnonce, keyaggCache, cosignerSecnonce, cosignerAggnonce, fullAggnonce, aggXonly)
    }

    /** Round two on both sides, ending in a BIP 340 signature over the outer aggregate key. */
    private fun finish(s: Session, groupFirst: Boolean): Boolean {
        val session = Secp256k1.musigNonceProcess(s.fullAggnonce, msg, s.keyaggCache)
        val cosignerPsig = Secp256k1.musigPartialSign(s.cosignerSecnonce, cosignerSeckey, s.keyaggCache, session)

        val psigs = s.ids.mapIndexed { i, id ->
            val psig = Secp256k1.prefractalSign(
                s.secnonces[i], s.secshares[id.toInt()], id, s.ids, s.signerPubshares, s.aggnonce,
                s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg
            )
            assertEquals(32, psig.size)
            // Every share verifies against its author's public share.
            assertEquals(1, Secp256k1.prefractalPartialSigVerify(
                psig, s.pubnonces[i], s.pubshares[id.toInt()], id, s.ids, s.aggnonce,
                s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg
            ))
            psig
        }
        val groupPsig = Secp256k1.prefractalPartialSigAgg(psigs.toTypedArray(), s.tweakCache)
        assertEquals(32, groupPsig.size)

        val all = if (groupFirst) arrayOf(groupPsig, cosignerPsig) else arrayOf(cosignerPsig, groupPsig)
        val sig = Secp256k1.musigPartialSigAgg(session, all)
        return Secp256k1.verifySchnorr(sig, msg, s.aggXonly)
    }

    @Test
    fun nestedRoundTrip() {
        val configs = listOf(2 to 2, 3 to 2, 5 to 3, 4 to 3)
        for ((n, t) in configs) {
            for (groupFirst in listOf(true, false)) {
                for (seckey in listOf(thresholdSeckeyEven, thresholdSeckeyOdd)) {
                    for (tweak in listOf(null, ByteArray(32) { 0x55 })) {
                        val s = setup(n, t, seckey, groupFirst, tweak)
                        assertTrue(finish(s, groupFirst), "failed for n=$n t=$t groupFirst=$groupFirst tweaked=${tweak != null}")
                    }
                }
            }
        }
    }

    /**
     * The odd-Y case on its own. If the binding layer or the C module ever applied stock frost's
     * key-side parity, this would fail while the even-Y case above kept passing.
     */
    @Test
    fun oddYGroupKey() {
        val s = setup(3, 2, thresholdSeckeyOdd, true, null)
        // The fixture really is odd-Y: an uncompressed pubkey's last byte carries the Y parity.
        assertEquals(1, s.threshPk.last().toInt() and 1)
        assertTrue(finish(s, true))
    }

    @Test
    fun partialSigVerifyRejects() {
        val s = setup(5, 3, thresholdSeckeyOdd, true, null)
        val psig = Secp256k1.prefractalSign(
            s.secnonces[0], s.secshares[0], s.ids[0], s.ids, s.signerPubshares, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg
        )
        assertEquals(1, Secp256k1.prefractalPartialSigVerify(
            psig, s.pubnonces[0], s.pubshares[0], s.ids[0], s.ids, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg))

        // A tampered share.
        val tampered = psig.copyOf().also { it[10] = (it[10].toInt() xor 0x40).toByte() }
        assertEquals(0, Secp256k1.prefractalPartialSigVerify(
            tampered, s.pubnonces[0], s.pubshares[0], s.ids[0], s.ids, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg))

        // The right share against the wrong member.
        assertEquals(0, Secp256k1.prefractalPartialSigVerify(
            psig, s.pubnonces[1], s.pubshares[1], s.ids[1], s.ids, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg))

        // A different message.
        val otherMsg = msg.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(0, Secp256k1.prefractalPartialSigVerify(
            psig, s.pubnonces[0], s.pubshares[0], s.ids[0], s.ids, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, otherMsg))
    }

    /** A tweaked frost cache is refused everywhere it can be passed. */
    @Test
    fun identityTweakCacheRequired() {
        val s = setup(3, 2, thresholdSeckeyOdd, true, null)
        val tweaked = s.tweakCache.copyOf()
        Secp256k1.frostPubkeyXonlyTweakAdd(tweaked, ByteArray(32) { 0x09 })

        assertFailsWith<Secp256k1Exception> {
            Secp256k1.prefractalSign(
                s.secnonces[0], s.secshares[0], s.ids[0], s.ids, s.signerPubshares, s.aggnonce,
                s.threshPk, tweaked, s.keyaggCache, s.cosignerAggnonce, msg)
        }

        // The secnonce above was consumed even though the call failed, so this uses the other one.
        val psig = Secp256k1.prefractalSign(
            s.secnonces[1], s.secshares[1], s.ids[1], s.ids, s.signerPubshares, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg)
        assertEquals(0, Secp256k1.prefractalPartialSigVerify(
            psig, s.pubnonces[1], s.pubshares[1], s.ids[1], s.ids, s.aggnonce,
            s.threshPk, tweaked, s.keyaggCache, s.cosignerAggnonce, msg))
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.prefractalPartialSigAgg(arrayOf(psig), tweaked)
        }
        // The identity cache is accepted at the same call, so the refusals are about the tweak.
        assertEquals(32, Secp256k1.prefractalPartialSigAgg(arrayOf(psig), s.tweakCache).size)
    }

    /**
     * Nonce single-use is NOT enforced at this layer, and this test pins that so nobody mistakes it
     * for an oversight later.
     *
     * The C module wipes the secnonce it is given, but both bindings copy the caller's array into a
     * local struct and never write the wipe back - the same convention the existing frostSign and
     * musigPartialSign bindings follow, and the reason these functions can take a plain ByteArray.
     * Enforcement lives one layer up, in bitcoin-kmp's Frost.SecretNonce, which is single-use
     * through an AtomicBoolean and hands its bytes out only via consume {}.
     *
     * So a caller driving these raw bindings directly gets no protection: reusing a secnonce across
     * two DIFFERENT messages leaks the secret share. Use the bitcoin-kmp wrapper.
     */
    @Test
    fun nonceWipeIsNotPropagatedToTheCaller() {
        val s = setup(3, 2, thresholdSeckeyOdd, true, null)
        val secnonce = s.secnonces[0].copyOf()
        val first = Secp256k1.prefractalSign(
            secnonce, s.secshares[0], s.ids[0], s.ids, s.signerPubshares, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg)
        // The caller's array is untouched by the call.
        assertContentEquals(s.secnonces[0], secnonce)
        // ...so a second call over the same message succeeds and is deterministic in the nonce.
        val second = Secp256k1.prefractalSign(
            secnonce, s.secshares[0], s.ids[0], s.ids, s.signerPubshares, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg)
        assertContentEquals(first, second)
    }

    /** A secnonce whose magic has been cleared is refused before it reaches libsecp256k1. */
    @Test
    fun wipedNonceRefused() {
        val s = setup(3, 2, thresholdSeckeyOdd, true, null)
        val wiped = ByteArray(Secp256k1.FROST_SECRET_NONCE_SIZE)
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.prefractalSign(
                wiped, s.secshares[0], s.ids[0], s.ids, s.signerPubshares, s.aggnonce,
                s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg)
        }
    }

    /** Argument validation happens in the binding layer, before anything reaches libsecp256k1. */
    @Test
    fun argumentValidation() {
        val s = setup(3, 2, thresholdSeckeyEven, true, null)
        assertFailsWith<IllegalArgumentException> { Secp256k1.prefractalNonceAgg(arrayOf(), s.ids, s.threshPk) }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.prefractalNonceAgg(s.pubnonces.toTypedArray(), uintArrayOf(0u, 0u), s.threshPk)
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.prefractalSign(s.secnonces[0], ByteArray(31), s.ids[0], s.ids, s.signerPubshares,
                s.aggnonce, s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg)
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.prefractalSign(s.secnonces[0], s.secshares[0], 99u, s.ids, s.signerPubshares,
                s.aggnonce, s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg)
        }
        assertFailsWith<IllegalArgumentException> { Secp256k1.prefractalPartialSigAgg(arrayOf(), s.tweakCache) }
    }

    /**
     * Passing null pubshares skips the share/pubshare consistency check, as documented, and still
     * produces a correct signature. This is also the argument shape most likely to diverge between
     * the JVM and native bindings.
     */
    @Test
    fun nullPubsharesAccepted() {
        val s = setup(3, 2, thresholdSeckeyOdd, true, null)
        val psig = Secp256k1.prefractalSign(
            s.secnonces[0], s.secshares[0], s.ids[0], s.ids, null, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg)
        assertEquals(1, Secp256k1.prefractalPartialSigVerify(
            psig, s.pubnonces[0], s.pubshares[0], s.ids[0], s.ids, s.aggnonce,
            s.threshPk, s.tweakCache, s.keyaggCache, s.cosignerAggnonce, msg))
    }
}
