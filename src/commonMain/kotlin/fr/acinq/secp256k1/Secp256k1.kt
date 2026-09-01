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

public class Secp256k1Exception : RuntimeException {
    public constructor() : super()
    public constructor(message: String?) : super(message)
}