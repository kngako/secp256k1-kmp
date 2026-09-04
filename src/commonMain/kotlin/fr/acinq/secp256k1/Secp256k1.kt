/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.secp256k1

import kotlin.jvm.JvmStatic

public interface Secp256k1 {

    /**
     * Verify an ECDSA signature.
     *
     * @param signature signature in compact encoding (64 bytes).
     * @param message message signed.
     * @param pubkey signer's public key.
     */
    public fun verify(signature: ByteArray, message: ByteArray, pubkey: ByteArray): Boolean

    /**
     * Create a normalized ECDSA signature.
     *
     * @param message message to sign.
     * @param privkey signer's private key.
     * @param ndata optional 32 bytes of auxiliary data passed to the nonce generation function.
     *              This can be used to implement low-R grinding by passing a counter value.
     */
    public fun sign(message: ByteArray, privkey: ByteArray, ndata: ByteArray? = null): ByteArray

    /**
     * Verify a Schnorr signature.
     *
     * @param signature 64 bytes signature.
     * @param data message signed.
     * @param pub signer's x-only public key (32 bytes).
     */
    public fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean

    /**
     * Create a Schnorr signature.
     *
     * @param data message to sign.
     * @param sec signer's private key.
     * @param auxrand32 32 bytes of fresh randomness (optional).
     */
    public fun signSchnorr(data: ByteArray, sec: ByteArray, auxrand32: ByteArray?): ByteArray

    /**
     * Convert an ECDSA signature to a normalized lower-S form (bitcoin standardness rule).
     * Returns the normalized signature and a boolean set to true if the input signature was not normalized.
     *
     * @param sig signature that should be normalized.
     */
    public fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean>

    /**
     * Verify the validity of a private key.
     */
    public fun secKeyVerify(privkey: ByteArray): Boolean

    /**
     * Get the public key corresponding to the given private key.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubkeyCreate(privkey: ByteArray): ByteArray

    /**
     * Parse a serialized public key.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubkeyParse(pubkey: ByteArray): ByteArray

    /**
     * Negate the given private key.
     */
    public fun privKeyNegate(privkey: ByteArray): ByteArray

    /**
     * Tweak a private key by adding tweak to it.
     */
    public fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray

    /**
     * Tweak a private key by multiplying it by a tweak.
     */
    public fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray

    /**
     * Negate the given public key.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubKeyNegate(pubkey: ByteArray): ByteArray

    /**
     * Tweak a public key by adding tweak times the generator to it.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray

    /**
     * Tweak a public key by multiplying it by a tweak value.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray

    /**
     * Add a number of public keys together.
     * Returns the uncompressed public key (65 bytes).
     */
    public fun pubKeyCombine(pubkeys: Array<ByteArray>): ByteArray

    /**
     * Compute an elliptic curve Diffie-Hellman secret.
     */
    public fun ecdh(privkey: ByteArray, pubkey: ByteArray): ByteArray

    /**
     * Recover a public key from an ECDSA signature.
     *
     * @param sig ecdsa compact signature (64 bytes).
     * @param message message signed.
     * @param recid recoveryId (should have been provided with the signature to allow recovery).
     */
    public fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray

    /**
     * Convert a compact ECDSA signature (64 bytes) to a der-encoded ECDSA signature.
     */
    public fun compact2der(sig: ByteArray): ByteArray

    /**
     * Convert a DER signature to compact format (64 bytes)
     */
    public fun der2compact(sig: ByteArray): ByteArray

    /**
     * Serialize a public key to compact form (33 bytes).
     */
    public fun pubKeyCompress(pubkey: ByteArray): ByteArray {
        return when {
            pubkey.size == 33 && (pubkey[0] == 2.toByte() || pubkey[0] == 3.toByte()) -> pubkey
            pubkey.size == 65 && pubkey[0] == 4.toByte() -> {
                val compressed = pubkey.copyOf(33)
                compressed[0] = if (pubkey.last() % 2 == 0) 2.toByte() else 3.toByte()
                compressed
            }

            else -> throw Secp256k1Exception("invalid public key")
        }
    }

    /**
     * Generate a secret nonce to be used in a musig2 signing session.
     * This nonce must never be persisted or reused across signing sessions.
     * All optional arguments exist to enrich the quality of the randomness used, which is critical for security.
     *
     * @param sessionRandom32 unique 32-byte random data that must not be reused to generate other nonces
     * @param privkey (optional) signer's private key.
     * @param pubkey signer's public key
     * @param msg32 (optional) 32-byte message that will be signed, if already known.
     * @param keyaggCache (optional) key aggregation cache data from the signing session.
     * @param extraInput32 (optional) additional 32-byte random data.
     * @return serialized version of the secret nonce and the corresponding public nonce.
     */
    public fun musigNonceGen(sessionRandom32: ByteArray, privkey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray

    /**
     * Alternative counter-based method for generating nonce.
     * This nonce must never be persisted or reused across signing sessions.
     * All optional arguments exist to enrich the quality of the randomness used, which is critical for security.
     *
     * @param nonRepeatingCounter non-repeating counter that must never be reused with the same private key
     * @param privkey signer's private key.
     * @param msg32 (optional) 32-byte message that will be signed, if already known.
     * @param keyaggCache (optional) key aggregation cache data from the signing session.
     * @param extraInput32 (optional) additional 32-byte random data.
     * @return serialized version of the secret nonce and the corresponding public nonce.
     */
    public fun musigNonceGenCounter(nonRepeatingCounter: ULong, privkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray

    /**
     * Aggregate public nonces from all participants of a signing session.
     *
     * @param pubnonces public nonces (one per participant).
     * @return 66-byte aggregate public nonce (two public keys) or throws an exception is a nonce is invalid.
     */
    public fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray

    /**
     * Aggregate public keys from all participants of a signing session.
     *
     * @param pubkeys public keys of all participants in the signing session.
     * @param keyaggCache (optional) key aggregation cache data from the signing session. If an empty byte array is
     * provided, it will be filled with key aggregation data that can be used for the next steps of the signing process.
     * @return 32-byte x-only public key.
     */
    public fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray

    /**
     * Tweak the aggregated public key of a signing session.
     *
     * @param keyaggCache key aggregation cache filled by [musigPubkeyAgg].
     * @param tweak32 private key tweak to apply.
     * @return P + tweak32 * G (where P is the aggregated public key from [keyaggCache]). The key aggregation cache will
     * be updated with the tweaked public key.
     */
    public fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray

    /**
     * Tweak the aggregated public key of a signing session, treating it as an x-only public key (e.g. when using taproot).
     *
     * @param keyaggCache key aggregation cache filled by [musigPubkeyAgg].
     * @param tweak32 private key tweak to apply.
     * @return with_even_y(P) + tweak32 * G (where P is the aggregated public key from [keyaggCache]). The key aggregation
     * cache will be updated with the tweaked public key.
     */
    public fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray

    /**
     * Create a signing session context based on the public information from all participants.
     *
     * @param aggnonce aggregated public nonce (see [musigNonceAgg]).
     * @param msg32 32-byte message that will be signed.
     * @param keyaggCache aggregated public key cache filled by calling [musigPubkeyAgg] with the public keys of all participants.
     * @return signing session context that can be used to create partial signatures and aggregate them.
     */
    public fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray

    /**
     * Check that a secret nonce was generated with a public key that matches the private key used for signing.
     * @param secretnonce secret nonce.
     * @param pubkey public key for the private key that will be used, with the secret nonce, to generate a partial signature.
     * @return false if the secret nonce does not match the public key.
     */
    public fun musigNonceValidate(secretnonce: ByteArray, pubkey: ByteArray): Boolean {
        if (secretnonce.size != MUSIG2_SECRET_NONCE_SIZE) return false
        if (!MUSIG2_SECNONCE_MAGIC.indices.all { secretnonce[it] == MUSIG2_SECNONCE_MAGIC[it] }) return false
        if (pubkey.size != 33 && pubkey.size != 65) return false
        val pk = Secp256k1.pubkeyParse(pubkey)
        // this is a bit hackish but the secp256k1 library does not export methods to do this cleanly
        val x = secretnonce.copyOfRange(68, 68 + 32)
        x.reverse()
        val y = secretnonce.copyOfRange(68 + 32, 68 + 32 + 32)
        y.reverse()
        val pkx = pk.copyOfRange(1, 1 + 32)
        val pky = pk.copyOfRange(33, 33 + 32)
        return x.contentEquals(pkx) && y.contentEquals(pky)
    }

    /**
     * Create a partial signature.
     *
     * @param secnonce signer's secret nonce (see [musigNonceGen]).
     * @param privkey signer's private key.
     * @param keyaggCache aggregated public key cache filled by calling [musigPubkeyAgg] with the public keys of all participants.
     * @param session signing session context (see [musigNonceProcess]).
     * @return 32-byte partial signature.
     */
    public fun musigPartialSign(secnonce: ByteArray, privkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): ByteArray

    /**
     * Verify the partial signature from one of the signing session's participants.
     *
     * @param psig 32-byte partial signature.
     * @param pubnonce individual public nonce of the signing participant.
     * @param pubkey individual public key of the signing participant.
     * @param keyaggCache aggregated public key cache filled by calling [musigPubkeyAgg] with the public keys of all participants.
     * @param session signing session context (see [musigNonceProcess]).
     * @return result code (1 if the partial signature is valid, 0 otherwise).
     */
    public fun musigPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int

    /**
     * Aggregate partial signatures from all participants into a single schnorr signature. If some of the partial
     * signatures are invalid, this function will return an invalid aggregated signature without raising an error.
     * It is recommended to use [musigPartialSigVerify] to verify partial signatures first.
     *
     * @param session signing session context (see [musigNonceProcess]).
     * @param psigs list of 32-byte partial signatures.
     * @return 64-byte aggregated schnorr signature.
     */
    public fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray

    /**
     * Get the full aggregated public key from a key aggregation cache.
     *
     * @param keyaggCache key aggregation cache filled by [musigPubkeyAgg].
     * @return the uncompressed aggregated public key (65 bytes).
     */
    public fun musigPubkeyGet(keyaggCache: ByteArray): ByteArray

    /**
     * Get the parity of the aggregate nonce used by a signing session. This is needed when using adaptor
     * signatures: it must be provided to [musigAdapt] and [musigExtractAdaptor].
     *
     * @param session signing session context (see [musigNonceProcess]).
     * @return 0 if the aggregate nonce has an even y coordinate, 1 otherwise.
     */
    public fun musigNonceParity(session: ByteArray): Int

    /**
     * Create a signature from a musig2 pre-signature and an adaptor secret.
     *
     * @param preSig64 64-byte pre-signature (see [musigPartialSigAgg]).
     * @param secAdaptor32 32-byte adaptor secret.
     * @param nonceParity parity of the aggregate nonce (see [musigNonceParity]).
     * @return 64-byte schnorr signature. Note that this function does not verify the signature: if the adaptor
     * secret is incorrect, the returned signature will be invalid.
     */
    public fun musigAdapt(preSig64: ByteArray, secAdaptor32: ByteArray, nonceParity: Int): ByteArray

    /**
     * Extract an adaptor secret from a musig2 pre-signature and its corresponding adapted signature.
     *
     * @param sig64 64-byte adapted schnorr signature (see [musigAdapt]).
     * @param preSig64 64-byte pre-signature corresponding to [sig64].
     * @param nonceParity parity of the aggregate nonce (see [musigNonceParity]).
     * @return 32-byte adaptor secret.
     */
    public fun musigExtractAdaptor(sig64: ByteArray, preSig64: ByteArray, nonceParity: Int): ByteArray

    /**
     * Generate FROST threshold key material with a trusted dealer (BIP 445).
     * The dealer must transmit each secret share to its participant over a secure channel and erase all secret
     * key material afterwards. Participants are identified by ids 0..[nParticipants]-1.
     *
     * WARNING: the underlying secp256k1 FROST module is experimental and must not be used in production.
     *
     * @param thresholdSeckey32 32-byte threshold secret key.
     * @param nParticipants total number of participants n (at most [FROST_MAX_PARTICIPANTS]).
     * @param threshold threshold t: the number of signers required to produce a signature.
     * @return the threshold public key (65 bytes, uncompressed), the secret share of each participant (32 bytes
     * each, entry i belongs to participant id i), and the public share of each participant (65 bytes each,
     * uncompressed, entry i belongs to participant id i).
     */
    public fun frostTrustedDealerKeygen(thresholdSeckey32: ByteArray, nParticipants: Int, threshold: Int): Triple<ByteArray, Array<ByteArray>, Array<ByteArray>>

    /**
     * Validate FROST threshold key material (BIP 445 ValidateThresholdInfo): checks that the public shares lie on
     * a single polynomial and that they are consistent with the threshold public key. This does NOT validate the
     * security of the key generation that produced the key material.
     *
     * @param thresholdPubkey threshold public key (33 or 65 bytes).
     * @param pubshares public shares of all participants (entry i belongs to participant id i).
     * @param threshold threshold t.
     * @return true if the key material is valid and consistent, false otherwise.
     */
    public fun frostThresholdInfoValidate(thresholdPubkey: ByteArray, pubshares: Array<ByteArray>, threshold: Int): Boolean

    /**
     * Initialize a FROST tweak cache from the threshold public key.
     * A tweak cache is required to create signing sessions (see [frostSessionInit]), even if no tweaks are applied.
     *
     * @param thresholdPubkey the (untweaked) threshold public key (33 or 65 bytes).
     * @return the tweak cache (opaque [FROST_TWEAK_CACHE_SIZE]-byte blob).
     */
    public fun frostTweakCacheInit(thresholdPubkey: ByteArray): ByteArray

    /**
     * Get the current (tweaked) threshold public key from a tweak cache. This is the BIP340 x-only public key
     * that final signatures of sessions created with this cache verify against.
     *
     * @param tweakCache tweak cache (see [frostTweakCacheInit]).
     * @return 32-byte x-only tweaked threshold public key.
     */
    public fun frostTweakedPubkeyGet(tweakCache: ByteArray): ByteArray

    /**
     * Apply an x-only tweak to a FROST tweak cache (BIP 341 "Taproot" tweaking: the current public key is
     * negated if it has an odd y coordinate before the tweak is applied). The tweak cache is updated in place.
     *
     * @param tweakCache tweak cache (see [frostTweakCacheInit]).
     * @param tweak32 32-byte tweak to apply.
     * @return 32-byte x-only tweaked threshold public key.
     */
    public fun frostPubkeyXonlyTweakAdd(tweakCache: ByteArray, tweak32: ByteArray): ByteArray

    /**
     * Apply a plain tweak to a FROST tweak cache (BIP 32-style tweaking: the current public key is not negated
     * before the tweak is applied). The tweak cache is updated in place.
     *
     * @param tweakCache tweak cache (see [frostTweakCacheInit]).
     * @param tweak32 32-byte tweak to apply.
     * @return 32-byte x-only tweaked threshold public key.
     */
    public fun frostPubkeyEcTweakAdd(tweakCache: ByteArray, tweak32: ByteArray): ByteArray

    /**
     * Generate a secret nonce to be used in a FROST signing session (BIP 445 NonceGen).
     * This nonce must never be persisted or reused across signing sessions: reusing it leaks the secret share.
     * All optional arguments exist to enrich the quality of the randomness used, which is critical for security.
     *
     * @param sessionRandom32 unique 32-byte random data that must not be reused to generate other nonces.
     * @param secshare32 (optional) signer's 32-byte secret share (see [frostTrustedDealerKeygen]).
     * @param pubshare (optional) signer's public share.
     * @param thresholdPubkey32 (optional) 32-byte x-only encoding of the threshold public key the signature will
     * verify against (i.e. after applying tweaks, if any, see [frostTweakedPubkeyGet]).
     * @param msg (optional) message that will be signed, if already known.
     * @param extraInput (optional) additional data to bind into the nonce derivation.
     * @return serialized version of the secret nonce and the corresponding public nonce.
     */
    public fun frostNonceGen(sessionRandom32: ByteArray, secshare32: ByteArray?, pubshare: ByteArray?, thresholdPubkey32: ByteArray?, msg: ByteArray?, extraInput: ByteArray?): ByteArray

    /**
     * Aggregate the public nonces of all signers of a FROST signing session.
     *
     * @param pubnonces public nonces (one per signer). The pubnonce at index i must belong to the signer whose id
     * is at index i in the ids array passed to [frostSessionInit].
     * @return 66-byte aggregate public nonce.
     */
    public fun frostNonceAgg(pubnonces: Array<ByteArray>): ByteArray

    /**
     * Create a FROST signing session context based on the public information from all participants.
     * All signers and the coordinator must use identical parameters. The session is signer-agnostic: the same
     * session can be used by the coordinator to verify the partial signatures of all signers.
     *
     * @param aggnonce aggregated public nonce (see [frostNonceAgg]).
     * @param ids identifiers of the u signers. Every id must be unique and smaller than [nParticipants].
     * @param pubshares (optional) public shares of the signers (entry i belongs to ids[i]). If provided, they are
     * validated against the threshold public key.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @param tweakCache tweak cache holding the threshold public key and all tweaks applied to it.
     * @param msg message that will be signed.
     * @return signing session context (opaque [FROST_SESSION_SIZE]-byte blob).
     */
    public fun frostSessionInit(aggnonce: ByteArray, ids: UIntArray, pubshares: Array<ByteArray>?, nParticipants: Int, threshold: Int, tweakCache: ByteArray, msg: ByteArray): ByteArray

    /**
     * Create a FROST partial signature (BIP 445 Sign).
     *
     * @param secnonce signer's secret nonce (see [frostNonceGen]). It must not be reused afterwards.
     * @param secshare32 signer's 32-byte secret share.
     * @param session signing session context (see [frostSessionInit]).
     * @param ids identifiers of the u signers (identical to [frostSessionInit]).
     * @param pubshares (optional) public shares of the signers (identical to [frostSessionInit]). If provided, the
     * secret share is checked against the signer's public share (recommended).
     * @param myId signer's identifier (must be one of [ids]).
     * @return 32-byte partial signature.
     */
    public fun frostSign(secnonce: ByteArray, secshare32: ByteArray, session: ByteArray, ids: UIntArray, pubshares: Array<ByteArray>?, myId: UInt): ByteArray

    /**
     * Aggregate a prefractal group's public nonces (nested FROST+MuSig2).
     *
     * The group's threshold public key occupies one participant slot of an ordinary musig2 session. This returns
     * the nonce the group puts on the wire, which is an ordinary 66-byte musig2 public nonce, together with the
     * UNSCALED frost aggregate nonce that the members need for [prefractalSign]. The latter is an internal value,
     * not a wire value: hand it back to [prefractalSign] and [prefractalPartialSigVerify] unchanged.
     *
     * The signer set fixed here must be exactly the set that signs: both the Lagrange coefficients and the
     * aggregate nonce are defined over the participating set, so signing with a subset produces an invalid
     * signature and raises nothing.
     *
     * @param pubnonces public nonces of the u members (see [frostNonceGen]), 66 bytes each.
     * @param ids identifiers of the u members (entry i belongs to pubnonces[i]). Must be unique.
     * @param threshPk the group's untweaked threshold public key.
     * @return the group's 66-byte musig2 public nonce, and the 66-byte unscaled frost aggregate nonce.
     */
    public fun prefractalNonceAgg(pubnonces: Array<ByteArray>, ids: UIntArray, threshPk: ByteArray): Pair<ByteArray, ByteArray>

    /**
     * Create one prefractal group member's partial signature (nested FROST+MuSig2).
     *
     * @param secnonce member's secret nonce (see [frostNonceGen]). It is wiped and must not be reused, including
     * when this call fails.
     * @param secshare32 member's 32-byte secret share.
     * @param myId member's identifier (must be one of [ids]).
     * @param ids identifiers of the u members, identical to the array given to [prefractalNonceAgg].
     * @param pubshares (optional) public shares of the members, in the order of [ids]. If provided, the secret
     * share is checked against the member's public share (recommended).
     * @param aggnonce the unscaled frost aggregate nonce returned by [prefractalNonceAgg].
     * @param threshPk the group's untweaked threshold public key.
     * @param tweakCache the group's frost tweak cache, which must be the identity: this composition tweaks only
     * the outer aggregate key.
     * @param keyaggCache the OUTER musig2 keyagg cache, already carrying any BIP341 tweak.
     * @param cosignerAggnonce aggregate of the NON-group participants' musig2 public nonces.
     * @param msg32 the 32-byte message being signed.
     * @return 32-byte partial signature.
     */
    public fun prefractalSign(secnonce: ByteArray, secshare32: ByteArray, myId: UInt, ids: UIntArray, pubshares: Array<ByteArray>?, aggnonce: ByteArray, threshPk: ByteArray, tweakCache: ByteArray, keyaggCache: ByteArray, cosignerAggnonce: ByteArray, msg32: ByteArray): ByteArray

    /**
     * Verify one prefractal group member's partial signature, for identifiable abort.
     *
     * Every session parameter must match the one [prefractalSign] was given.
     *
     * @param partialSig the 32-byte partial signature to verify.
     * @param pubnonce the member's 66-byte public nonce, as given to [prefractalNonceAgg].
     * @param pubshare the member's public share.
     * @return 1 if the partial signature is valid, 0 otherwise.
     */
    public fun prefractalPartialSigVerify(partialSig: ByteArray, pubnonce: ByteArray, pubshare: ByteArray, myId: UInt, ids: UIntArray, aggnonce: ByteArray, threshPk: ByteArray, tweakCache: ByteArray, keyaggCache: ByteArray, cosignerAggnonce: ByteArray, msg32: ByteArray): Int

    /**
     * Sum a prefractal group's partial signatures into one ordinary musig2 partial signature, ready to be
     * aggregated alongside the cosigners' with [musigPartialSigAgg].
     *
     * @param partialSigs the members' 32-byte partial signatures (see [prefractalSign]).
     * @param tweakCache the group's frost tweak cache, which must be the identity.
     * @return 32-byte musig2 partial signature.
     */
    public fun prefractalPartialSigAgg(partialSigs: Array<ByteArray>, tweakCache: ByteArray): ByteArray

    /**
     * Create a FROST partial signature with a deterministically derived nonce (BIP 445 DeterministicSign), for a
     * signer that is online throughout the whole session. The nonce is derived from the secret share, the signer
     * set, the other signers' aggregate nonce, the tweaked threshold public key, and the message.
     *
     * @param secshare32 signer's 32-byte secret share.
     * @param myId signer's identifier.
     * @param aggOtherNonce aggregate of all _other_ signers' public nonces (see [frostNonceAgg]), or null for a
     * sole signer.
     * @param ids identifiers of the u signers.
     * @param pubshares (optional) public shares of the signers.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @param tweakCache tweak cache holding the threshold public key and all tweaks applied to it.
     * @param msg message that will be signed.
     * @param auxRand32 (optional) 32 bytes of auxiliary randomness mixed into the nonce derivation.
     * @return the signer's 32-byte partial signature and 66-byte public nonce (to be sent to the coordinator).
     */
    public fun frostDeterministicSign(secshare32: ByteArray, myId: UInt, aggOtherNonce: ByteArray?, ids: UIntArray, pubshares: Array<ByteArray>?, nParticipants: Int, threshold: Int, tweakCache: ByteArray, msg: ByteArray, auxRand32: ByteArray?): Pair<ByteArray, ByteArray>

    /**
     * Verify the partial signature from one of the FROST signing session's signers.
     *
     * @param psig 32-byte partial signature.
     * @param pubnonce public nonce of the signing participant.
     * @param pubshare public share of the signing participant.
     * @param session signing session context (see [frostSessionInit]).
     * @param ids identifiers of the u signers (identical to [frostSessionInit]).
     * @param signerIndex index of the signer in the [ids] array.
     * @return result code (1 if the partial signature is valid, 0 otherwise).
     */
    public fun frostPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubshare: ByteArray, session: ByteArray, ids: UIntArray, signerIndex: Int): Int

    /**
     * Aggregate partial signatures from all signers into a single BIP340 schnorr signature. If some of the
     * partial signatures are invalid, this function will return an invalid aggregated signature without raising
     * an error. It is recommended to use [frostPartialSigVerify] to verify partial signatures first.
     *
     * @param session signing session context (see [frostSessionInit]).
     * @param psigs list of 32-byte partial signatures. The partial signature at index i must belong to the signer
     * whose id is at index i in the ids array passed to [frostSessionInit].
     * @return 64-byte aggregated schnorr signature.
     */
    public fun frostPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray

    /**
     * Compute the FROST enrollment parameters hash, which every party of an enrollment run computes for itself
     * and compares against the ones it receives. Binding the threshold public key makes the hash identify a
     * group rather than a tuple of numbers: two unrelated groups that happen to share (t, n, ids, newId) produce
     * different hashes.
     *
     * This function operates on public data only, and enforces exactly the same parameter constraints as the
     * other enrollment functions, so it is also the natural way to pre-validate a parameter tuple.
     *
     * WARNING: the underlying secp256k1 FROST enrollment module is experimental and must not be used in
     * production.
     *
     * @param threshPk threshold public key of the group (33 or 65 bytes).
     * @param ids identifiers of the u helpers. Every id must be unique, smaller than [nParticipants] and
     * different from [newId]; the order is irrelevant to the hash, which sorts them, but fixes the alignment of
     * every array in the other enrollment functions.
     * @param newId identifier of the participant receiving the share: equal to [nParticipants] to enroll a new
     * participant, or smaller than it to repair the share of an existing one.
     * @param nParticipants total number of participants n, at most [FROST_MAX_PARTICIPANTS] and strictly
     * smaller in enrollment mode.
     * @param threshold threshold t, at least 2 and at most [nParticipants].
     * @return 32-byte parameters hash.
     */
    public fun frostEnrollmentParamsHash(threshPk: ByteArray, ids: UIntArray, newId: UInt, nParticipants: Int, threshold: Int): ByteArray

    /**
     * Round 1.1 of FROST enrollment: generate a helper's enrollment shares. Computes this helper's Lagrange-scaled
     * contribution at the target identifier and splits it into u additive shares.
     *
     * The returned shares are aligned with [ids]: the entry at [myId]'s own position is kept locally and passed
     * back into [frostEnrollmentShareAgg], and every other entry must be sent to the helper it is aligned with,
     * together with the returned parameters hash.
     *
     * SECURITY: the returned shares are additive shares of a real secret share. They must be transmitted over
     * confidential and authenticated channels; this module handles bytes only, transport is the caller's
     * responsibility.
     *
     * Note that, following the convention of [frostSign] and [musigPartialSign], the wipe libsecp256k1 performs
     * on [sessionSecrand32] is not propagated back to the caller's array: single use is not enforced at this
     * layer and must be guaranteed by the caller.
     *
     * WARNING: the underlying secp256k1 FROST enrollment module is experimental and must not be used in
     * production.
     *
     * @param sessionSecrand32 32 bytes of fresh randomness, which must not be reused across runs.
     * @param secshare32 this helper's own 32-byte secret share; left unmodified.
     * @param threshPk threshold public key of the group (33 or 65 bytes).
     * @param ids identifiers of the u helpers, which fixes the alignment of the returned shares.
     * @param myId this helper's own identifier, which must appear in [ids].
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @return the u 32-byte enrollment shares aligned with [ids], and the 32-byte parameters hash.
     */
    public fun frostEnrollmentSharesGen(sessionSecrand32: ByteArray, secshare32: ByteArray, threshPk: ByteArray, ids: UIntArray, myId: UInt, newId: UInt, nParticipants: Int, threshold: Int): Pair<Array<ByteArray>, ByteArray>

    /**
     * Round 1.2 of FROST enrollment: check that every helper ran round 1.1 on the same parameters, and aggregate
     * this helper's enrollment shares into the single value to send to the target participant.
     *
     * The two u-entry arrays are both aligned with [ids] but have deliberately opposite conventions for the
     * caller's own slot, which is what makes this a recomputation check rather than an equality test between
     * caller-supplied strings:
     *
     *  - [allShares32]: the entry at [myId]'s position is read. It is the share [frostEnrollmentSharesGen] kept
     *    locally.
     *  - [receivedParamsHashes32]: the entry at [myId]'s position is never read and may be left zero. The own
     *    hash is always recomputed.
     *
     * A helper's contribution is at fault either because its parameters hash disagrees with the recomputed one,
     * or because its share is not a valid scalar. The two causes are not distinguished, so a caller should not
     * report one of them specifically; note that the second can name the caller's own identifier, since the
     * locally kept share is summed along with the rest.
     *
     * WARNING: the underlying secp256k1 FROST enrollment module is experimental and must not be used in
     * production.
     *
     * @param allShares32 u 32-byte shares aligned with [ids]: the share kept locally at [myId]'s position, and
     * the share received from each other helper at theirs.
     * @param receivedParamsHashes32 u 32-byte parameters hashes aligned with [ids], holding the hash received
     * from each other helper. The entry at [myId]'s position is ignored.
     * @param threshPk threshold public key of the group (33 or 65 bytes).
     * @param ids identifiers of the u helpers, in the same order as in round 1.1.
     * @param myId this helper's own identifier, which must appear in [ids].
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @return the aggregated share to send to the target participant, or the identifier of the helper at fault.
     * @throws Secp256k1Exception if the arguments are invalid, as opposed to a helper being at fault.
     */
    public fun frostEnrollmentShareAgg(allShares32: Array<ByteArray>, receivedParamsHashes32: Array<ByteArray>, threshPk: ByteArray, ids: UIntArray, myId: UInt, newId: UInt, nParticipants: Int, threshold: Int): FrostEnrollmentShareAggResult

    /**
     * Derive the public share at the target identifier: the value of the group's public-share polynomial at the
     * target participant's x-coordinate. This is used both to verify the new secret share in
     * [frostEnrollmentSecshareGen] and, after an enrollment, to extend the group's table of public shares from n
     * to n+1 entries.
     *
     * This function operates on public data only.
     *
     * WARNING: the underlying secp256k1 FROST enrollment module is experimental and must not be used in
     * production.
     *
     * @param pubshares public shares of the u helpers (33 or 65 bytes each), aligned with [ids].
     * @param ids identifiers of the u helpers.
     * @param newId identifier of the participant receiving the share.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @return the derived public share, in uncompressed 65-byte format.
     */
    public fun frostEnrollmentPubshareDerive(pubshares: Array<ByteArray>, ids: UIntArray, newId: UInt, nParticipants: Int, threshold: Int): ByteArray

    /**
     * Round 2 of FROST enrollment: derive the target participant's secret share from the values received from the
     * helpers, checking the parameters hash and verifying the result against the expected public share.
     *
     * [expectedPubshare] is load-bearing: it is the only check that a helper contributed a correct value. Pass
     * null only if the resulting share is validated by other means.
     *
     * PRECONDITION, documented but not enforced: [threshPk] must come from a source the target participant
     * authenticates independently of the helpers, and [expectedPubshare] must be derived from public shares
     * validated against it with [frostThresholdInfoValidate]. Otherwise both checks are circular: t colluding
     * helpers can present a consistent but fabricated polynomial, and every check here passes on a worthless
     * share.
     *
     * WARNING: the underlying secp256k1 FROST enrollment module is experimental and must not be used in
     * production.
     *
     * @param sigmas32 the u 32-byte values received from the helpers (see [frostEnrollmentShareAgg]), aligned
     * with [ids].
     * @param threshPk the independently authenticated threshold public key of the group (33 or 65 bytes).
     * @param ids identifiers of the u helpers, in the same order as [sigmas32].
     * @param newId own identifier, the one the share is being derived for.
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @param expectedParamsHash32 the 32-byte parameters hash received from the helpers, or null to skip the
     * comparison.
     * @param expectedPubshare the expected public share, from [frostEnrollmentPubshareDerive], or null to skip
     * the verification (not recommended).
     * @return the participant's 32-byte secret share.
     */
    public fun frostEnrollmentSecshareGen(sigmas32: Array<ByteArray>, threshPk: ByteArray, ids: UIntArray, newId: UInt, nParticipants: Int, threshold: Int, expectedParamsHash32: ByteArray?, expectedPubshare: ByteArray?): ByteArray

    /**
     * Compute the ChillDKG host public key of a participant. The host public key is the long-term cryptographic
     * identity of the participant in a DKG session.
     *
     * WARNING: the underlying secp256k1 ChillDKG module is experimental and must not be used in production.
     *
     * @param hostseckey32 32-byte host secret key.
     * @return 33-byte compressed host public key.
     */
    public fun chilldkgHostpubkeyGen(hostseckey32: ByteArray): ByteArray

    /**
     * Compute a hash of the ChillDKG session parameters, for out-of-band comparison between participants. If all
     * participants obtain the same hash, they all agree on the host public keys and the threshold.
     *
     * @param hostpubkeys33 33-byte compressed host public keys of all participants (in the order agreed upon by
     * all participants).
     * @param threshold threshold t: the number of signers required to produce a signature.
     * @return 32-byte hash of the session parameters.
     */
    public fun chilldkgParamsHash(hostpubkeys33: Array<ByteArray>, threshold: Int): ByteArray

    /**
     * Perform a participant's first step of a ChillDKG session.
     *
     * @param hostseckey32 32-byte host secret key.
     * @param hostpubkeys33 33-byte compressed host public keys of all participants; all participants must agree
     * on the order.
     * @param threshold threshold t.
     * @param random32 32 bytes of fresh randomness.
     * @return the participant's session state (opaque [CHILLDKG_PARTICIPANT_STATE1_SIZE]-byte blob, to be passed
     * to a single [chilldkgParticipantStep2] call) and the message to send to the coordinator (pmsg1).
     */
    public fun chilldkgParticipantStep1(hostseckey32: ByteArray, hostpubkeys33: Array<ByteArray>, threshold: Int, random32: ByteArray): Pair<ByteArray, ByteArray>

    /**
     * Perform the coordinator's first step of a ChillDKG session: aggregate the participants' first messages
     * into the message to broadcast to all participants.
     *
     * @param pmsgs1 the participants' first messages (see [chilldkgParticipantStep1]), in the same order as
     * [hostpubkeys33].
     * @param hostpubkeys33 33-byte compressed host public keys of all participants; must be identical (in content
     * and order) to the arrays used by the participants.
     * @param threshold threshold t.
     * @return the fault report, the coordinator's session state (opaque [CHILLDKG_COORDINATOR_STATE_SIZE]-byte
     * blob, to be passed to a single [chilldkgCoordinatorFinalize] call) and the message to broadcast to all
     * participants (cmsg1).
     */
    public fun chilldkgCoordinatorStep1(pmsgs1: Array<ByteArray>, hostpubkeys33: Array<ByteArray>, threshold: Int): ChilldkgCoordinatorStep1Result

    /**
     * Perform a participant's second step of a ChillDKG session: verify the coordinator's first message, compute
     * the DKG output, and produce the CertEq signature over the session transcript (pmsg2).
     *
     * Warning: after sending the produced signature to the coordinator, the caller must not erase its host secret
     * key, even if the coordinator's reply needed for [chilldkgParticipantFinalize] is not received (some other
     * participant may deem the session successful and use the resulting threshold public key).
     *
     * @param hostseckey32 32-byte host secret key (must be the same as in [chilldkgParticipantStep1]).
     * @param state1 session state output by [chilldkgParticipantStep1] (must not be reused).
     * @param cmsg1 the coordinator's first message (see [chilldkgCoordinatorStep1]).
     * @param auxRand32 32 bytes of auxiliary randomness for the CertEq signature (see BIP 340).
     * @return the fault report, the participant's session state (opaque [CHILLDKG_PARTICIPANT_STATE2_SIZE]-byte
     * blob, to be passed to a single [chilldkgParticipantFinalize] call), the 64-byte CertEq signature to send to
     * the coordinator, and the investigation data to pass to [chilldkgParticipantInvestigate] (only set when the
     * fault code is [ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR]).
     */
    public fun chilldkgParticipantStep2(hostseckey32: ByteArray, state1: ByteArray, cmsg1: ByteArray, auxRand32: ByteArray): ChilldkgParticipantStep2Result

    /**
     * Perform the coordinator's final step of a ChillDKG session: collect the CertEq signatures into the
     * certificate and verify all of them.
     *
     * @param state coordinator's session state output by [chilldkgCoordinatorStep1] (must not be reused).
     * @param pmsgs2 the participants' second messages (64-byte CertEq signatures), in the same order as the
     * host public keys.
     * @param threshold threshold t.
     * @return the fault report, the certificate to broadcast to all participants (cmsg2), the threshold public
     * key (33 bytes, compressed), the public shares of all participants (33 bytes each) and the recovery data.
     */
    public fun chilldkgCoordinatorFinalize(state: ByteArray, pmsgs2: Array<ByteArray>, threshold: Int): ChilldkgCoordinatorFinalizeResult

    /**
     * Perform a participant's final step of a ChillDKG session: verify the certificate and compute the DKG output.
     * If the returned fault report is ok, this participant deems the DKG session successful.
     *
     * @param state2 session state output by [chilldkgParticipantStep2] (must not be reused).
     * @param cmsg2 the certificate (see [chilldkgCoordinatorFinalize]).
     * @param nParticipants total number of participants n.
     * @param threshold threshold t.
     * @return the fault report, the participant's 32-byte secret share, the threshold public key (33 bytes,
     * compressed), the public shares of all participants (33 bytes each) and the recovery data.
     */
    public fun chilldkgParticipantFinalize(state2: ByteArray, cmsg2: ByteArray, nParticipants: Int, threshold: Int): ChilldkgParticipantFinalizeResult

    /**
     * Recover a participant's DKG output from recovery data, e.g. after a failure of [chilldkgParticipantFinalize]
     * (using recovery data obtained from another participant or the coordinator) or after data loss. The recovery
     * data is self-delimiting: the number of participants and the threshold are derived from it.
     *
     * @param hostseckey32 32-byte host secret key.
     * @param recovery the recovery data of the session.
     * @return the fault report, the participant's 32-byte secret share, the threshold public key, the public
     * shares and host public keys of all participants, and the number of participants and threshold of the
     * recovered session.
     */
    public fun chilldkgParticipantRecover(hostseckey32: ByteArray, recovery: ByteArray): ChilldkgRecoverResult

    /**
     * Recover the DKG output of the coordinator from recovery data. Like [chilldkgParticipantRecover], but for
     * the coordinator, who has no secret share (the returned secret share is null).
     *
     * @param recovery the recovery data of the session.
     */
    public fun chilldkgCoordinatorRecover(recovery: ByteArray): ChilldkgRecoverResult

    /**
     * Sign recovery data to create a recovery acknowledgment. Acks can be collected in an optional acknowledgment
     * round to confirm that all participants have received the recovery data.
     *
     * @param hostseckey32 32-byte host secret key.
     * @param hostpubkeys33 33-byte compressed host public keys of all participants.
     * @param threshold threshold t.
     * @param recovery the recovery data of the session.
     * @param auxRand32 32 bytes of auxiliary randomness (see BIP 340).
     * @return the 64-byte acknowledgment signature.
     */
    public fun chilldkgRecoveryAckSign(hostseckey32: ByteArray, hostpubkeys33: Array<ByteArray>, threshold: Int, recovery: ByteArray, auxRand32: ByteArray): ByteArray

    /**
     * Verify the recovery acknowledgment signatures of all participants. Note that a failure does NOT mean the
     * DKG failed (reaching this point implies the DKG itself was successful); it only means it cannot be confirmed
     * that all participants have a copy of the recovery data.
     *
     * @param hostpubkeys33 33-byte compressed host public keys of all participants.
     * @param threshold threshold t.
     * @param recovery the recovery data of the session.
     * @param ackSigs64 the 64-byte acknowledgment signatures, in the same order as [hostpubkeys33].
     * @return the fault report (ok if all signatures are valid).
     */
    public fun chilldkgRecoveryAcksVerify(hostpubkeys33: Array<ByteArray>, threshold: Int, recovery: ByteArray, ackSigs64: Array<ByteArray>): ChilldkgFault

    /**
     * Generate the investigation message for a single participant, which allows that participant to investigate
     * who is to blame for a failed ChillDKG session (see [chilldkgParticipantInvestigate]). The message contains
     * no confidential information and can be safely broadcast.
     *
     * @param pmsgs1 the participants' first messages, in the same order as [hostpubkeys33].
     * @param hostpubkeys33 33-byte compressed host public keys of all participants.
     * @param threshold threshold t.
     * @param participantId the participant the investigation message is for.
     * @return the fault report and the investigation message for the given participant.
     */
    public fun chilldkgCoordinatorInvestigate(pmsgs1: Array<ByteArray>, hostpubkeys33: Array<ByteArray>, threshold: Int, participantId: UInt): Pair<ChilldkgFault, ByteArray>

    /**
     * Investigate who is to blame for a failed ChillDKG session. Can be called when [chilldkgParticipantStep2]
     * returned [ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR].
     *
     * @param investigationData the investigation data output by [chilldkgParticipantStep2] (secret, must not be
     * shared).
     * @param cinv the coordinator's investigation message for this participant (see [chilldkgCoordinatorInvestigate]).
     * @return the fault report identifying the suspected faulty party.
     */
    public fun chilldkgParticipantInvestigate(investigationData: ByteArray, cinv: ByteArray): ChilldkgFault

    /**
     * Deal the shares of an Iceberg group from a single seed (trusted dealer).
     *
     * Iceberg is a threshold scheme that lets a group of parties stand in for a single MuSig2 participant. The
     * group's public key (see [icebergPubkeyAgg]) is aggregated with the cosigners' keys with [musigPubkeyAgg],
     * and the group produces one ordinary MuSig2 public nonce and partial signature per signing session, so
     * cosigners cannot tell a group is involved.
     *
     * WARNING: the underlying secp256k1 Iceberg module is experimental ("neither the scheme nor this
     * implementation has been reviewed by anyone outside the project") and must not be used to protect anything
     * of value. A trusted dealer momentarily holds everything needed to reconstruct the group's private key; the
     * seed must be erased afterwards.
     *
     * @param n number of participants (at most [ICEBERG_MAX_PARTICIPANTS]).
     * @param t threshold: the quorum is 2t-1 participants, so t must be at most (n+1)/2 (2-of-2 and 3-of-4 are
     * inexpressible; 2-of-4 is the smallest usable group).
     * @param seed32 32 bytes of uniformly random data.
     * @return the serialized share of each participant (entry k belongs to participant k+1: participant indices
     * are 1-based).
     */
    public fun icebergSharesGen(n: Int, t: Int, seed32: ByteArray): Array<ByteArray>

    /**
     * Derive the Lagrange weights for an Iceberg share (an optimization: [icebergPubshareGen], [icebergNonceGen]
     * and [icebergPartialSign] recompute them when no cache is provided). The cache contains no secret material,
     * but has no serialized form: it is returned as an opaque [ICEBERG_SHARE_CACHE_SIZE]-byte blob.
     *
     * @param share the participant's serialized share (see [icebergSharesGen]).
     * @return the share cache (opaque blob; rebuild it from the share rather than persisting it).
     */
    public fun icebergShareCacheCreate(share: ByteArray): ByteArray

    /**
     * Compute a participant's Iceberg public key share.
     *
     * @param share the participant's serialized share.
     * @param cache (optional) the participant's share cache (see [icebergShareCacheCreate]).
     * @return 34-byte serialized public key share, meant to be published.
     */
    public fun icebergPubshareGen(share: ByteArray, cache: ByteArray?): ByteArray

    /**
     * Verify Iceberg public key shares and combine them into the group's public key.
     *
     * @param pubshares 34-byte public key shares (at least 2t-1, at most n).
     * @param n group size the shares were dealt for.
     * @param t threshold.
     * @return the group's public key (65 bytes, uncompressed), to be aggregated with the cosigners' keys with
     * [musigPubkeyAgg] exactly as if it belonged to a single signer.
     */
    public fun icebergPubkeyAgg(pubshares: Array<ByteArray>, n: Int, t: Int): ByteArray

    /**
     * Derive a participant's nonce contribution for a signing session. It depends only on the share and the
     * session label, so this round can run before the message exists, and there is no secret nonce to keep
     * between the two rounds.
     *
     * @param share the participant's serialized share.
     * @param cache (optional) the participant's share cache.
     * @param sid32 32-byte session label: public, need not be random, but must never be used twice by the group.
     * @return 67-byte serialized nonce contribution, to publish to the other group members.
     */
    public fun icebergNonceGen(share: ByteArray, cache: ByteArray?, sid32: ByteArray): ByteArray

    /**
     * Verify the group members' nonce contributions and combine them into one ordinary MuSig2 public nonce.
     * From that nonce upwards, signing is plain MuSig2.
     *
     * @param pubnonces 67-byte nonce contributions (at least 2t-1, at most n).
     * @param n group size.
     * @param t threshold.
     * @param groupPubkey the group's public key (see [icebergPubkeyAgg]).
     * @return 66-byte serialized MuSig2 public nonce, to publish to the cosigners.
     */
    public fun icebergNonceAgg(pubnonces: Array<ByteArray>, n: Int, t: Int, groupPubkey: ByteArray): ByteArray

    /**
     * Check that a MuSig2 key aggregation cache aggregates exactly the given list of public keys, in this order,
     * and that the group's public key is one of them. Run this once where the cache is built: signing with a
     * cache built over a different key set spends the session label on a useless signature share.
     *
     * @param keyaggCache the outer MuSig2 key aggregation cache (see [musigPubkeyAgg]).
     * @param pubkeys the keys the cache should have been built from, in the order they were passed to
     * [musigPubkeyAgg].
     * @param groupPubkey the group's public key, which must be one of [pubkeys].
     * @return true if the cache aggregates exactly this key list and contains the group's public key.
     */
    public fun icebergKeyaggCheck(keyaggCache: ByteArray, pubkeys: Array<ByteArray>, groupPubkey: ByteArray): Boolean

    /**
     * Produce a participant's Iceberg signature share.
     *
     * Never call this twice with the same [sid32], whatever else changes: a participant's secrets are fixed by
     * the label alone, so two answers under one label leak the share by elimination. Callers must durably record
     * the labels they have answered under.
     *
     * @param share the participant's serialized share.
     * @param cache (optional) the participant's share cache.
     * @param sid32 the session label, the same one [icebergNonceGen] used.
     * @param pubnonces the group's own 67-byte nonce contributions (at least 2t-1; any qualifying set from the
     * session gives the same result).
     * @param groupPubkey the group's public key (the one [icebergNonceAgg] was given).
     * @param keyaggCache the outer MuSig2 key aggregation cache (see [icebergKeyaggCheck]).
     * @param msg32 32-byte message being signed.
     * @param cosignerAggnonce the cosigners' aggregate nonce, theirs alone (see [musigNonceAgg]).
     * @return 33-byte serialized signature share, to publish to the other group members.
     */
    public fun icebergPartialSign(share: ByteArray, cache: ByteArray?, sid32: ByteArray, pubnonces: Array<ByteArray>, groupPubkey: ByteArray, keyaggCache: ByteArray, msg32: ByteArray, cosignerAggnonce: ByteArray): ByteArray

    /**
     * Check one Iceberg signature share against what its author published. A 0 means the share does not satisfy
     * the signing equation against these inputs: it does not distinguish a bad share from bad inputs, and does
     * not name a culprit.
     *
     * @param psig 33-byte signature share to check.
     * @param pubshare 34-byte public key share of the participant the signature share is attributed to.
     * @param pubnonces a qualifying set of 67-byte nonce contributions from the same session (at least 2t-1).
     * @param n group size.
     * @param t threshold.
     * @param groupPubkey the group's public key.
     * @param keyaggCache the outer MuSig2 key aggregation cache.
     * @param msg32 32-byte message being signed.
     * @param cosignerAggnonce the cosigners' aggregate nonce.
     * @return result code (1 if the signature share is valid, 0 otherwise).
     */
    public fun icebergPartialSigVerify(psig: ByteArray, pubshare: ByteArray, pubnonces: Array<ByteArray>, n: Int, t: Int, groupPubkey: ByteArray, keyaggCache: ByteArray, msg32: ByteArray, cosignerAggnonce: ByteArray): Int

    /**
     * Combine Iceberg signature shares into one ordinary MuSig2 partial signature, to be aggregated with the
     * cosigners' partial signatures with [musigPartialSigAgg]. Given more than t shares, a self-contradicting
     * set is refused.
     *
     * @param psigs 33-byte signature shares (at least t, at most n).
     * @param n group size.
     * @param t threshold.
     * @return 32-byte serialized MuSig2 partial signature.
     */
    public fun icebergPartialSigAgg(psigs: Array<ByteArray>, n: Int, t: Int): ByteArray
    
    public companion object : Secp256k1 by getSecpk256k1() {
        @JvmStatic
        public fun get(): Secp256k1 = this

        // @formatter:off
        public const val MUSIG2_SECRET_NONCE_SIZE: Int = 132
        public const val MUSIG2_PUBLIC_NONCE_SIZE: Int = 66
        public const val MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE: Int = 197
        public const val MUSIG2_PUBLIC_SESSION_SIZE: Int = 133

        public const val FROST_SECRET_NONCE_SIZE: Int = 68
        public const val FROST_PUBLIC_NONCE_SIZE: Int = 66
        public const val FROST_TWEAK_CACHE_SIZE: Int = 165
        public const val FROST_SESSION_SIZE: Int = 137
        public const val FROST_MAX_PARTICIPANTS: Int = 128

        public const val CHILLDKG_MAX_PARTICIPANTS: Int = 128
        public const val CHILLDKG_PARTICIPANT_STATE1_SIZE: Int = 4306
        public const val CHILLDKG_PARTICIPANT_STATE2_SIZE: Int = 21073
        public const val CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE: Int = 4205
        public const val CHILLDKG_COORDINATOR_STATE_SIZE: Int = 21041

        public const val ICEBERG_MAX_PARTICIPANTS: Int = 10
        /** Largest size of a serialized Iceberg share (a share of a given group may serialize to fewer bytes). */
        public const val ICEBERG_SHARE_MAX_SIZE: Int = 4036
        /** Size of the opaque share cache blob (see [icebergShareCacheCreate]). */
        public const val ICEBERG_SHARE_CACHE_SIZE: Int = 4040
        public const val ICEBERG_PUBLIC_SHARE_SIZE: Int = 34
        public const val ICEBERG_PUBLIC_NONCE_SIZE: Int = 67
        public const val ICEBERG_PARTIAL_SIG_SIZE: Int = 33
        /*
         * libsecp256k1 tags each of its opaque musig2 objects with a 4-byte magic prefix and validates it
         * internally with ARG_CHECK, which invokes the context's illegal-argument callback. The default
         * callback aborts the process, so a blob that has the right size but does not actually hold a
         * musig2 object would kill the application instead of raising an exception. We check the prefix
         * before handing the blob to libsecp256k1 so that these cases throw Secp256k1Exception.
         *
         * Keep in sync with native/secp256k1/src/modules/musig/{keyagg,session}_impl.h.
         */
        internal val MUSIG_KEYAGG_CACHE_MAGIC = byteArrayOf(0xf4.toByte(), 0xad.toByte(), 0xbb.toByte(), 0xdf.toByte())
        internal val MUSIG_SESSION_MAGIC = byteArrayOf(0x9d.toByte(), 0xed.toByte(), 0xe9.toByte(), 0x17)
        internal val MUSIG2_SECNONCE_MAGIC = byteArrayOf(0x22.toByte(), 0x0e.toByte(), 0xdc.toByte(), 0xf1.toByte())
        /*
         * Same thing for the opaque FROST objects that are passed back to libsecp256k1 as raw byte arrays.
         *
         * Keep in sync with native/secp256k1/src/modules/frost/{keygen,session}_impl.h.
         */
        internal val FROST_SECNONCE_MAGIC = byteArrayOf(0x5c.toByte(), 0xcf.toByte(), 0xb9.toByte(), 0x99.toByte())
        internal val FROST_TWEAK_CACHE_MAGIC = byteArrayOf(0x8d.toByte(), 0x86.toByte(), 0xb5.toByte(), 0x01.toByte())
        internal val FROST_SESSION_MAGIC = byteArrayOf(0x34.toByte(), 0xb5.toByte(), 0x27.toByte(), 0x3d.toByte())
        /*
         * Same thing for the opaque ChillDKG state objects that are passed back to libsecp256k1 as raw byte arrays.
         *
         * Keep in sync with native/secp256k1/src/modules/chilldkg/main_impl.h.
         */
        internal val CHILLDKG_PARTICIPANT_STATE1_MAGIC = byteArrayOf(0x3f.toByte(), 0x2c.toByte(), 0x9e.toByte(), 0x51.toByte())
        internal val CHILLDKG_PARTICIPANT_STATE2_MAGIC = byteArrayOf(0x7a.toByte(), 0xd1.toByte(), 0x44.toByte(), 0x0b.toByte())
        internal val CHILLDKG_COORDINATOR_STATE_MAGIC = byteArrayOf(0x1b.toByte(), 0x8e.toByte(), 0x63.toByte(), 0xa7.toByte())
        internal val CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_MAGIC = byteArrayOf(0x62.toByte(), 0x4a.toByte(), 0xc5.toByte(), 0x90.toByte())
        /*
         * Same thing for the opaque Iceberg share cache, the only Iceberg object without a serialized form.
         *
         * Keep in sync with native/secp256k1/src/modules/iceberg/keygen_impl.h.
         */
        internal val ICEBERG_SHARE_CACHE_MAGIC = byteArrayOf(0x1c.toByte(), 0xeb.toByte(), 0xc4.toByte(), 0x03.toByte())
        // @formatter:on
    }
}

internal expect fun getSecpk256k1(): Secp256k1

/**
 * Fault report of a ChillDKG protocol step, mapping the fault taxonomy of the bip-frost-dkg reference
 * implementation. Protocol faults (a faulty participant or coordinator) are normal outcomes of a DKG session
 * and are reported through this type instead of exceptions.
 */
public data class ChilldkgFault(val code: Int, val participantIndex: UInt?) {
    public val isOk: Boolean get() = code == OK

    public companion object {
        /** No fault; the step succeeded. */
        public const val OK: Int = 0
        /** The coordinator is faulty. */
        public const val FAULTY_COORDINATOR: Int = 1
        /** The participant identified by [participantIndex] is faulty. */
        public const val FAULTY_PARTICIPANT: Int = 2
        /** The participant identified by [participantIndex] or the coordinator is faulty. */
        public const val FAULTY_PARTICIPANT_OR_COORDINATOR: Int = 3
        /** Some unknown participant or the coordinator is faulty; the investigation procedure of the protocol
         * (see [Secp256k1.chilldkgCoordinatorInvestigate] and [Secp256k1.chilldkgParticipantInvestigate]) is
         * necessary to determine a suspected participant. */
        public const val UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR: Int = 4
        /** The caller provided invalid input (e.g. an invalid host secret key or invalid session parameters). */
        public const val INVALID_INPUT: Int = 5
    }
}

/** Result of [Secp256k1.chilldkgCoordinatorStep1]. On fault, [state] and [cmsg1] are zeroed. */
public data class ChilldkgCoordinatorStep1Result(val fault: ChilldkgFault, val state: ByteArray, val cmsg1: ByteArray)

/** Result of [Secp256k1.chilldkgParticipantStep2]. On fault, [state2] and [sig64] are zeroed; [investigationData]
 * is only set when the fault code is [ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR]. */
public data class ChilldkgParticipantStep2Result(val fault: ChilldkgFault, val state2: ByteArray, val sig64: ByteArray, val investigationData: ByteArray?)

/** Result of [Secp256k1.chilldkgCoordinatorFinalize]: the certificate ([cmsg2]) to broadcast to all
 * participants, and the resulting DKG output. On fault, all outputs are zeroed. */
public data class ChilldkgCoordinatorFinalizeResult(val fault: ChilldkgFault, val cmsg2: ByteArray, val thresholdPubkey: ByteArray, val pubshares: Array<ByteArray>, val recovery: ByteArray)

/** Result of [Secp256k1.chilldkgParticipantFinalize]: the participant's secret share and the resulting DKG
 * output. On fault, all outputs are zeroed. */
public data class ChilldkgParticipantFinalizeResult(val fault: ChilldkgFault, val secshare: ByteArray, val thresholdPubkey: ByteArray, val pubshares: Array<ByteArray>, val recovery: ByteArray)

/** Result of [Secp256k1.chilldkgParticipantRecover] and [Secp256k1.chilldkgCoordinatorRecover]. [secshare] is
 * null for the coordinator, who has no secret share. On fault, all outputs are zeroed or empty. */
public data class ChilldkgRecoverResult(val fault: ChilldkgFault, val secshare: ByteArray?, val thresholdPubkey: ByteArray, val pubshares: Array<ByteArray>, val hostpubkeys: Array<ByteArray>, val nParticipants: Int, val threshold: Int)

/**
 * Result of [Secp256k1.frostEnrollmentShareAgg]. Exactly one of [sigma] and [mismatchId] is set: on success
 * [sigma] holds the aggregated share to send to the target participant, and on a protocol fault [mismatchId]
 * holds the identifier - not the index - of the helper whose contribution was at fault.
 */
public data class FrostEnrollmentShareAggResult(val sigma: ByteArray?, val mismatchId: UInt?) {
    public val isOk: Boolean get() = sigma != null
}

public class Secp256k1Exception : RuntimeException {
    public constructor() : super()
    public constructor(message: String?) : super(message)
}