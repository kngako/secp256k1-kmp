package fr.acinq.secp256k1

import kotlin.test.*

class IcebergTest {
    private val seed = Hex.decode("EEC1CB7D1B7254C5CAB0D9C61AB02E643D464A59FE6C96A7EFE871F07C5AEF54")
    private val cosignerSeckey = Hex.decode("487356F98AA7A0DC5E0E0F61B4CDA5D1A5B4C59F1B1E5A70E0D55C11FE0A99A1")
    private val msg32 = ByteArray(32) { 0x42 }
    private val sid32 = ByteArray(32) { 0x77 }

    /** Deal a 2-of-4 group and return its shares, public shares and group public key. */
    private fun dealGroup(): Triple<Array<ByteArray>, Array<ByteArray>, ByteArray> {
        val shares = Secp256k1.icebergSharesGen(4, 2, seed)
        assertEquals(4, shares.size)
        // 2-of-4 shares hold C(3, 1) = 3 seeds each
        shares.forEach { assertEquals(4 + 32 * 3, it.size) }
        val caches = shares.map { Secp256k1.icebergShareCacheCreate(it) }
        val pubshares = shares.mapIndexed { i, share -> Secp256k1.icebergPubshareGen(share, caches[i]) }.toTypedArray()
        pubshares.forEach { assertEquals(Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE, it.size) }
        val groupPubkey = Secp256k1.icebergPubkeyAgg(pubshares, 4, 2)
        assertEquals(65, groupPubkey.size)
        return Triple(shares, pubshares, groupPubkey)
    }

    @Test
    fun signingSession() {
        val (shares, pubshares, groupPubkey) = dealGroup()
        val cosignerPubkey = Secp256k1.pubkeyCreate(cosignerSeckey)

        // The group participates in an outer musig2 session alongside a cosigner, as if it were a single signer.
        val pubkeys = arrayOf(groupPubkey, cosignerPubkey)
        val keyaggCache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        val aggPubkey = Secp256k1.musigPubkeyAgg(pubkeys, keyaggCache)
        assertTrue(Secp256k1.icebergKeyaggCheck(keyaggCache, pubkeys, groupPubkey))
        assertFalse(Secp256k1.icebergKeyaggCheck(keyaggCache, pubkeys, Secp256k1.pubkeyCreate(ByteArray(32) { 0x09 })))
        assertFalse(Secp256k1.icebergKeyaggCheck(keyaggCache, pubkeys.reversed().toTypedArray(), groupPubkey))

        // Round 1: a quorum of 2t-1 = 3 members publishes its nonce contribution (before the message is known).
        val contributingMembers = listOf(0, 1, 2)
        val pubnonces = contributingMembers.map { Secp256k1.icebergNonceGen(shares[it], null, sid32) }
        pubnonces.forEach { assertEquals(Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE, it.size) }
        // The group's contributions combine into one ordinary musig2 public nonce.
        val groupPubnonce = Secp256k1.icebergNonceAgg(pubnonces.toTypedArray(), 4, 2, groupPubkey)
        assertEquals(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE, groupPubnonce.size)

        // The cosigner generates a regular musig2 nonce, and the outer session starts.
        val cosignerNonce = Secp256k1.musigNonceGen(ByteArray(32) { 0x11 }, cosignerSeckey, cosignerPubkey, msg32, keyaggCache, null)
        val cosignerSecnonce = cosignerNonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE)
        val cosignerPubnonce = cosignerNonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, Secp256k1.MUSIG2_SECRET_NONCE_SIZE + Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        val aggnonce = Secp256k1.musigNonceAgg(arrayOf(groupPubnonce, cosignerPubnonce))
        val cosignerAggnonce = Secp256k1.musigNonceAgg(arrayOf(cosignerPubnonce))
        val session = Secp256k1.musigNonceProcess(aggnonce, msg32, keyaggCache)

        // Round 2: the cosigner signs with plain musig2, the group members with iceberg.
        val cosignerPsig = Secp256k1.musigPartialSign(cosignerSecnonce, cosignerSeckey, keyaggCache, session)
        val psigs = contributingMembers.map { Secp256k1.icebergPartialSign(shares[it], null, sid32, pubnonces.toTypedArray(), groupPubkey, keyaggCache, msg32, cosignerAggnonce) }
        psigs.forEach { assertEquals(Secp256k1.ICEBERG_PARTIAL_SIG_SIZE, it.size) }
        psigs.forEachIndexed { i, psig ->
            assertEquals(1, Secp256k1.icebergPartialSigVerify(psig, pubshares[contributingMembers[i]], pubnonces.toTypedArray(), 4, 2, groupPubkey, keyaggCache, msg32, cosignerAggnonce))
        }
        // The group's signature shares combine into one ordinary musig2 partial signature.
        val groupPsig = Secp256k1.icebergPartialSigAgg(psigs.toTypedArray(), 4, 2)
        assertEquals(32, groupPsig.size)
        assertEquals(1, Secp256k1.musigPartialSigVerify(groupPsig, groupPubnonce, groupPubkey, keyaggCache, session))

        // The final signature is a plain BIP340 signature for the aggregated public key.
        val sig = Secp256k1.musigPartialSigAgg(session, arrayOf(groupPsig, cosignerPsig))
        assertTrue(Secp256k1.verifySchnorr(sig, msg32, aggPubkey))

        // A signature share does not verify against another member's public share.
        assertEquals(0, Secp256k1.icebergPartialSigVerify(psigs[0], pubshares[3], pubnonces.toTypedArray(), 4, 2, groupPubkey, keyaggCache, msg32, cosignerAggnonce))
    }

    @Test
    fun signingSessionWithCaches() {
        val (shares, pubshares, groupPubkey) = dealGroup()
        val cosignerPubkey = Secp256k1.pubkeyCreate(cosignerSeckey)
        val pubkeys = arrayOf(groupPubkey, cosignerPubkey)
        val keyaggCache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        Secp256k1.musigPubkeyAgg(pubkeys, keyaggCache)
        val caches = shares.map { Secp256k1.icebergShareCacheCreate(it) }
        val pubnonces = listOf(0, 2, 3).map { Secp256k1.icebergNonceGen(shares[it], caches[it], sid32) }
        val groupPubnonce = Secp256k1.icebergNonceAgg(pubnonces.toTypedArray(), 4, 2, groupPubkey)
        val cosignerNonce = Secp256k1.musigNonceGen(ByteArray(32) { 0x22 }, cosignerSeckey, cosignerPubkey, msg32, keyaggCache, null)
        val cosignerSecnonce = cosignerNonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE)
        val cosignerPubnonce = cosignerNonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, Secp256k1.MUSIG2_SECRET_NONCE_SIZE + Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        val session = Secp256k1.musigNonceProcess(Secp256k1.musigNonceAgg(arrayOf(groupPubnonce, cosignerPubnonce)), msg32, keyaggCache)
        val cosignerPsig = Secp256k1.musigPartialSign(cosignerSecnonce, cosignerSeckey, keyaggCache, session)
        val cosignerAggnonce = Secp256k1.musigNonceAgg(arrayOf(cosignerPubnonce))
        val psigs = listOf(0, 2, 3).map { Secp256k1.icebergPartialSign(shares[it], caches[it], sid32, pubnonces.toTypedArray(), groupPubkey, keyaggCache, msg32, cosignerAggnonce) }
        // Exactly t = 2 shares are enough to aggregate.
        val groupPsig = Secp256k1.icebergPartialSigAgg(psigs.take(2).toTypedArray(), 4, 2)
        val sig = Secp256k1.musigPartialSigAgg(session, arrayOf(groupPsig, cosignerPsig))
        assertTrue(Secp256k1.verifySchnorr(sig, msg32, Secp256k1.musigPubkeyAgg(pubkeys, null)))
    }

    @Test
    fun invalidInputs() {
        val (shares, pubshares, groupPubkey) = dealGroup()
        // 2-of-2 is inexpressible: the quorum 2t-1 must fit in the group
        assertFails { Secp256k1.icebergSharesGen(2, 2, seed) }
        assertFails { Secp256k1.icebergSharesGen(4, 3, seed) }
        assertFails { Secp256k1.icebergSharesGen(11, 2, seed) }
        assertFails { Secp256k1.icebergSharesGen(4, 2, ByteArray(31)) }
        // too few contributions
        val pubnonces = listOf(0, 1).map { Secp256k1.icebergNonceGen(shares[it], null, sid32) }
        assertFails { Secp256k1.icebergNonceAgg(pubnonces.toTypedArray(), 4, 2, groupPubkey) }
        // duplicate contribution
        val three = listOf(0, 1, 2).map { Secp256k1.icebergNonceGen(shares[it], null, sid32) }
        assertFails { Secp256k1.icebergNonceAgg(arrayOf(three[0], three[0], three[1]), 4, 2, groupPubkey) }
        // a malformed share or public share is rejected
        assertFails { Secp256k1.icebergPubshareGen(ByteArray(100), null) }
        assertFails { Secp256k1.icebergPubkeyAgg(arrayOf(ByteArray(Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE)), 4, 2) }
        // inconsistent public shares are rejected
        val tamperedPubshares = pubshares.copyOf()
        tamperedPubshares[1] = Secp256k1.icebergPubshareGen(shares[2], null)
        // (this duplicates member 3's share under member 2's entry: either the duplicate index or the degree check must catch it)
        assertFails { Secp256k1.icebergPubkeyAgg(tamperedPubshares.toList().toTypedArray(), 4, 2) }
    }

    /**
     * The share cache is an opaque blob without a serialized form, checked against its magic prefix before being
     * handed to libsecp256k1, whose default illegal-argument callback aborts the process. If any of these cases
     * regresses, this test does not fail, it takes the whole test run down with SIGABRT.
     */
    @Test
    fun rejectMalformedOpaqueBlobs() {
        val (shares, _, _) = dealGroup()
        val badCache = ByteArray(Secp256k1.ICEBERG_SHARE_CACHE_SIZE)
        assertFails { Secp256k1.icebergPubshareGen(shares[0], badCache) }
        assertFails { Secp256k1.icebergNonceGen(shares[0], badCache, sid32) }
    }
}
