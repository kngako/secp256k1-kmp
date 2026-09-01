/*
 * Copyright 2013 Google Inc.
 * Copyright 2014-2016 the libsecp256k1 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.secp256k1

public object Secp256k1Jni : Secp256k1 {
    override fun verify(signature: ByteArray, message: ByteArray, pubkey: ByteArray): Boolean {
        require(signature.size == 64) { "signature must be 64 bytes" }
        require(message.size == 32) { "message must be 32 bytes" }
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_ecdsa_verify(Secp256k1Context.getContext(), signature, message, pubkey) == 1
    }

    override fun sign(message: ByteArray, privkey: ByteArray, ndata: ByteArray?): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(message.size == 32) { "message must be 32 bytes" }
        ndata?.let { require(it.size == 32) { "ndata must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_ecdsa_sign(Secp256k1Context.getContext(), message, privkey, ndata)
    }

    override fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean> {
        require(sig.size == 64) { "signature must be 64 bytes" }
        val sigout = ByteArray(64)
        val result = Secp256k1CFunctions.secp256k1_ecdsa_signature_normalize(Secp256k1Context.getContext(), sig, sigout)
        return Pair(sigout, result == 1)
    }

    override fun secKeyVerify(privkey: ByteArray): Boolean {
        if (privkey.size != 32) return false
        return Secp256k1CFunctions.secp256k1_ec_seckey_verify(Secp256k1Context.getContext(), privkey) == 1
    }

    override fun pubkeyCreate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_create(Secp256k1Context.getContext(), privkey)
    }

    override fun pubkeyParse(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_parse(Secp256k1Context.getContext(), pubkey)
    }

    override fun privKeyNegate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_seckey_negate(Secp256k1Context.getContext(), privkey)
    }

    override fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(tweak.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_seckey_tweak_add(Secp256k1Context.getContext(), privkey, tweak)
    }

    override fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(tweak.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_seckey_tweak_mul(Secp256k1Context.getContext(), privkey, tweak)
    }

    override fun pubKeyNegate(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_negate(Secp256k1Context.getContext(), pubkey)
    }

    override fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        require(tweak.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_tweak_add(Secp256k1Context.getContext(), pubkey, tweak)
    }

    override fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        require(tweak.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_tweak_mul(Secp256k1Context.getContext(), pubkey, tweak)
    }

    override fun pubKeyCombine(pubkeys: Array<ByteArray>): ByteArray {
        require(pubkeys.isNotEmpty()) { "pubkeys must not be empty" }
        pubkeys.forEach { require(it.size == 33 || it.size == 65) { "public key must be 33 or 65 bytes" } }
        return Secp256k1CFunctions.secp256k1_ec_pubkey_combine(Secp256k1Context.getContext(), pubkeys)
    }

    override fun ecdh(privkey: ByteArray, pubkey: ByteArray): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_ecdh(Secp256k1Context.getContext(), privkey, pubkey)
    }

    override fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        require(sig.size == 64) { "signature must be 64 bytes" }
        require(message.size == 32) { "message must be 32 bytes" }
        require(recid in 0..3) { "recovery id must be in 0..3" }
        return Secp256k1CFunctions.secp256k1_ecdsa_recover(Secp256k1Context.getContext(), sig, message, recid)
    }

    override fun compact2der(sig: ByteArray): ByteArray {
        require(sig.size == 64) { "signature must be 64 bytes" }
        return Secp256k1CFunctions.secp256k1_compact_to_der(Secp256k1Context.getContext(), sig)
    }

    override fun der2compact(sig: ByteArray): ByteArray {
        require(sig.size in 8..73) { "invalid DER signature size" }
        return Secp256k1CFunctions.secp256k1_der_to_compact(Secp256k1Context.getContext(), sig)
    }

    override fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean {
        require(signature.size == 64) { "signature must be 64 bytes" }
        require(data.size == 32) { "data must be 32 bytes" }
        require(pub.size == 32) { "x-only public key must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_schnorrsig_verify(Secp256k1Context.getContext(), signature, data, pub) == 1
    }

    override fun signSchnorr(data: ByteArray, sec: ByteArray, auxrand32: ByteArray?): ByteArray {
        require(sec.size == 32) { "secret key must be 32 bytes" }
        require(data.size == 32) { "data must be 32 bytes" }
        auxrand32?.let { require(it.size == 32) { "auxiliary random data must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_schnorrsig_sign(Secp256k1Context.getContext(), data, sec, auxrand32)
    }

    override fun musigNonceGen(sessionRandom32: ByteArray, privkey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        require(sessionRandom32.size == 32) { "session random must be 32 bytes" }
        privkey?.let { require(it.size == 32) { "private key must be 32 bytes" } }
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        msg32?.let { require(it.size == 32) { "message must be 32 bytes" } }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" } }
        extraInput32?.let { require(it.size == 32) { "extra input must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_musig_nonce_gen(Secp256k1Context.getContext(), sessionRandom32, privkey, pubkey, msg32, keyaggCache, extraInput32)
    }

    override fun musigNonceGenCounter(nonRepeatingCounter: ULong, privkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        require(privkey.size == 32) { "private key must be 32 bytes" }
        msg32?.let { require(it.size == 32) { "message must be 32 bytes" } }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" } }
        extraInput32?.let { require(it.size == 32) { "extra input must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_musig_nonce_gen_counter(Secp256k1Context.getContext(), nonRepeatingCounter.toLong(), privkey, msg32, keyaggCache, extraInput32)
    }

    override fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray {
        require(pubnonces.isNotEmpty()) { "pubnonces must not be empty" }
        pubnonces.forEach { require(it.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" } }
        return Secp256k1CFunctions.secp256k1_musig_nonce_agg(Secp256k1Context.getContext(), pubnonces)
    }

    override fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray {
        require(pubkeys.isNotEmpty()) { "pubkeys must not be empty" }
        pubkeys.forEach { require(it.size == 33 || it.size == 65) { "public key must be 33 or 65 bytes" } }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" } }
        return Secp256k1CFunctions.secp256k1_musig_pubkey_agg(Secp256k1Context.getContext(), pubkeys, keyaggCache)
    }

    override fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(tweak32.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_musig_pubkey_ec_tweak_add(Secp256k1Context.getContext(), keyaggCache, tweak32)
    }

    override fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(tweak32.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_musig_pubkey_xonly_tweak_add(Secp256k1Context.getContext(), keyaggCache, tweak32)
    }

    override fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray {
        require(aggnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "aggregate nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
        require(msg32.size == 32) { "message must be 32 bytes" }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        return Secp256k1CFunctions.secp256k1_musig_nonce_process(Secp256k1Context.getContext(), aggnonce, msg32, keyaggCache)
    }

    override fun musigPartialSign(secnonce: ByteArray, privkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): ByteArray {
        require(secnonce.size == Secp256k1.MUSIG2_SECRET_NONCE_SIZE) { "secret nonce must be ${Secp256k1.MUSIG2_SECRET_NONCE_SIZE} bytes" }
        require(privkey.size == 32) { "private key must be 32 bytes" }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "invalid session size" }
        if (!musigNonceValidate(secnonce, pubkeyCreate(privkey))) throw Secp256k1Exception("invalid secret nonce")
        return Secp256k1CFunctions.secp256k1_musig_partial_sign(Secp256k1Context.getContext(), secnonce, privkey, keyaggCache, session)
    }

    override fun musigPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int {
        require(psig.size == 32) { "partial signature must be 32 bytes" }
        require(pubnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
        require(pubkey.size == 33 || pubkey.size == 65) { "public key must be 33 or 65 bytes" }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "invalid session size" }
        return Secp256k1CFunctions.secp256k1_musig_partial_sig_verify(Secp256k1Context.getContext(), psig, pubnonce, pubkey, keyaggCache, session)
    }

    override fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray {
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "invalid session size" }
        require(psigs.isNotEmpty()) { "partial signatures must not be empty" }
        psigs.forEach { require(it.size == 32) { "partial signature must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_musig_partial_sig_agg(Secp256k1Context.getContext(), session, psigs)
    }

    override fun musigPubkeyGet(keyaggCache: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        return Secp256k1CFunctions.secp256k1_musig_pubkey_get(Secp256k1Context.getContext(), keyaggCache)
    }

    override fun musigNonceParity(session: ByteArray): Int {
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "invalid session size" }
        return Secp256k1CFunctions.secp256k1_musig_nonce_parity(Secp256k1Context.getContext(), session)
    }

    override fun musigAdapt(preSig64: ByteArray, secAdaptor32: ByteArray, nonceParity: Int): ByteArray {
        require(preSig64.size == 64) { "pre-signature must be 64 bytes" }
        require(secAdaptor32.size == 32) { "adaptor secret must be 32 bytes" }
        require(nonceParity in 0..1) { "nonce parity must be 0 or 1" }
        return Secp256k1CFunctions.secp256k1_musig_adapt(Secp256k1Context.getContext(), preSig64, secAdaptor32, nonceParity)
    }

    override fun musigExtractAdaptor(sig64: ByteArray, preSig64: ByteArray, nonceParity: Int): ByteArray {
        require(sig64.size == 64) { "signature must be 64 bytes" }
        require(preSig64.size == 64) { "pre-signature must be 64 bytes" }
        require(nonceParity in 0..1) { "nonce parity must be 0 or 1" }
        return Secp256k1CFunctions.secp256k1_musig_extract_adaptor(Secp256k1Context.getContext(), sig64, preSig64, nonceParity)
    }

    override fun frostTrustedDealerKeygen(thresholdSeckey32: ByteArray, nParticipants: Int, threshold: Int): Triple<ByteArray, Array<ByteArray>, Array<ByteArray>> {
        require(thresholdSeckey32.size == 32) { "threshold secret key must be 32 bytes" }
        require(nParticipants in 1..Secp256k1.FROST_MAX_PARTICIPANTS) { "invalid number of participants" }
        require(threshold in 1..nParticipants) { "invalid threshold" }
        val result = Secp256k1CFunctions.secp256k1_frost_trusted_dealer_keygen(Secp256k1Context.getContext(), thresholdSeckey32, nParticipants, threshold)
        val thresholdPubkey = result.copyOfRange(0, 65)
        val secshares = (0 until nParticipants).map { result.copyOfRange(65 + 32 * it, 65 + 32 * (it + 1)) }.toTypedArray()
        val pubshares = (0 until nParticipants).map { result.copyOfRange(65 + 32 * nParticipants + 65 * it, 65 + 32 * nParticipants + 65 * (it + 1)) }.toTypedArray()
        return Triple(thresholdPubkey, secshares, pubshares)
    }

    override fun frostThresholdInfoValidate(thresholdPubkey: ByteArray, pubshares: Array<ByteArray>, threshold: Int): Boolean {
        require(pubshares.isNotEmpty()) { "public shares must not be empty" }
        pubshares.forEach { require(it.size == 33 || it.size == 65) { "public share must be 33 or 65 bytes" } }
        require(threshold in 1..pubshares.size) { "invalid threshold" }
        return Secp256k1CFunctions.secp256k1_frost_threshold_info_validate(Secp256k1Context.getContext(), thresholdPubkey, pubshares, threshold) == 1
    }

    override fun frostTweakCacheInit(thresholdPubkey: ByteArray): ByteArray {
        require(thresholdPubkey.size == 33 || thresholdPubkey.size == 65) { "threshold public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_frost_tweak_cache_init(Secp256k1Context.getContext(), thresholdPubkey)
    }

    override fun frostTweakedPubkeyGet(tweakCache: ByteArray): ByteArray {
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE) { "invalid tweak cache size" }
        return Secp256k1CFunctions.secp256k1_frost_tweaked_pubkey_get(Secp256k1Context.getContext(), tweakCache)
    }

    override fun frostPubkeyXonlyTweakAdd(tweakCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE) { "invalid tweak cache size" }
        require(tweak32.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_frost_pubkey_xonly_tweak_add(Secp256k1Context.getContext(), tweakCache, tweak32)
    }

    override fun frostPubkeyEcTweakAdd(tweakCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE) { "invalid tweak cache size" }
        require(tweak32.size == 32) { "tweak must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_frost_pubkey_ec_tweak_add(Secp256k1Context.getContext(), tweakCache, tweak32)
    }

    override fun frostNonceGen(sessionRandom32: ByteArray, secshare32: ByteArray?, pubshare: ByteArray?, thresholdPubkey32: ByteArray?, msg: ByteArray?, extraInput: ByteArray?): ByteArray {
        require(sessionRandom32.size == 32) { "session random must be 32 bytes" }
        secshare32?.let { require(it.size == 32) { "secret share must be 32 bytes" } }
        pubshare?.let { require(it.size == 33 || it.size == 65) { "public share must be 33 or 65 bytes" } }
        thresholdPubkey32?.let { require(it.size == 32) { "threshold public key must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_frost_nonce_gen(Secp256k1Context.getContext(), sessionRandom32, secshare32, pubshare, thresholdPubkey32, msg, extraInput)
    }

    override fun frostNonceAgg(pubnonces: Array<ByteArray>): ByteArray {
        require(pubnonces.isNotEmpty()) { "pubnonces must not be empty" }
        pubnonces.forEach { require(it.size == Secp256k1.FROST_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.FROST_PUBLIC_NONCE_SIZE} bytes" } }
        return Secp256k1CFunctions.secp256k1_frost_nonce_agg(Secp256k1Context.getContext(), pubnonces)
    }

    override fun frostSessionInit(aggnonce: ByteArray, ids: UIntArray, pubshares: Array<ByteArray>?, nParticipants: Int, threshold: Int, tweakCache: ByteArray, msg: ByteArray): ByteArray {
        require(aggnonce.size == Secp256k1.FROST_PUBLIC_NONCE_SIZE) { "aggregate nonce must be ${Secp256k1.FROST_PUBLIC_NONCE_SIZE} bytes" }
        require(ids.isNotEmpty()) { "signer ids must not be empty" }
        require(ids.toSet().size == ids.size) { "signer ids must be unique" }
        pubshares?.let {
            require(it.size == ids.size) { "public shares count must match signer ids count" }
            it.forEach { share -> require(share.size == 33 || share.size == 65) { "public share must be 33 or 65 bytes" } }
        }
        require(nParticipants in 1..Secp256k1.FROST_MAX_PARTICIPANTS) { "invalid number of participants" }
        require(ids.all { it < nParticipants.toUInt() }) { "signer ids must be smaller than the number of participants" }
        require(threshold in 1..nParticipants) { "invalid threshold" }
        require(ids.size in threshold..nParticipants) { "invalid number of signers" }
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE) { "invalid tweak cache size" }
        return Secp256k1CFunctions.secp256k1_frost_session_init(Secp256k1Context.getContext(), aggnonce, ids.map { it.toInt() }.toIntArray(), pubshares, nParticipants, threshold, tweakCache, msg)
    }

    override fun frostSign(secnonce: ByteArray, secshare32: ByteArray, session: ByteArray, ids: UIntArray, pubshares: Array<ByteArray>?, myId: UInt): ByteArray {
        require(secnonce.size == Secp256k1.FROST_SECRET_NONCE_SIZE) { "secret nonce must be ${Secp256k1.FROST_SECRET_NONCE_SIZE} bytes" }
        require(secshare32.size == 32) { "secret share must be 32 bytes" }
        require(session.size == Secp256k1.FROST_SESSION_SIZE) { "invalid session size" }
        require(ids.isNotEmpty()) { "signer ids must not be empty" }
        require(myId in ids) { "signer id must be one of the session's signer ids" }
        pubshares?.let { require(it.size == ids.size) { "public shares count must match signer ids count" } }
        return Secp256k1CFunctions.secp256k1_frost_sign(Secp256k1Context.getContext(), secnonce, secshare32, session, ids.map { it.toInt() }.toIntArray(), pubshares, myId.toInt())
    }

    override fun frostDeterministicSign(secshare32: ByteArray, myId: UInt, aggOtherNonce: ByteArray?, ids: UIntArray, pubshares: Array<ByteArray>?, nParticipants: Int, threshold: Int, tweakCache: ByteArray, msg: ByteArray, auxRand32: ByteArray?): Pair<ByteArray, ByteArray> {
        require(secshare32.size == 32) { "secret share must be 32 bytes" }
        require(ids.isNotEmpty()) { "signer ids must not be empty" }
        require(myId in ids) { "signer id must be one of the session's signer ids" }
        aggOtherNonce?.let { require(it.size == Secp256k1.FROST_PUBLIC_NONCE_SIZE) { "aggregate nonce must be ${Secp256k1.FROST_PUBLIC_NONCE_SIZE} bytes" } }
        pubshares?.let { require(it.size == ids.size) { "public shares count must match signer ids count" } }
        require(nParticipants in 1..Secp256k1.FROST_MAX_PARTICIPANTS) { "invalid number of participants" }
        require(threshold in 1..nParticipants) { "invalid threshold" }
        require(ids.size in threshold..nParticipants) { "invalid number of signers" }
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE) { "invalid tweak cache size" }
        auxRand32?.let { require(it.size == 32) { "auxiliary random data must be 32 bytes" } }
        val result = Secp256k1CFunctions.secp256k1_frost_deterministic_sign(Secp256k1Context.getContext(), secshare32, myId.toInt(), aggOtherNonce, ids.map { it.toInt() }.toIntArray(), pubshares, nParticipants, threshold, tweakCache, msg, auxRand32)
        return Pair(result.copyOfRange(0, 32), result.copyOfRange(32, 32 + Secp256k1.FROST_PUBLIC_NONCE_SIZE))
    }

    override fun frostPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubshare: ByteArray, session: ByteArray, ids: UIntArray, signerIndex: Int): Int {
        require(psig.size == 32) { "partial signature must be 32 bytes" }
        require(pubnonce.size == Secp256k1.FROST_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.FROST_PUBLIC_NONCE_SIZE} bytes" }
        require(pubshare.size == 33 || pubshare.size == 65) { "public share must be 33 or 65 bytes" }
        require(session.size == Secp256k1.FROST_SESSION_SIZE) { "invalid session size" }
        require(ids.isNotEmpty()) { "signer ids must not be empty" }
        require(signerIndex in ids.indices) { "invalid signer index" }
        return Secp256k1CFunctions.secp256k1_frost_partial_sig_verify(Secp256k1Context.getContext(), psig, pubnonce, pubshare, session, ids.map { it.toInt() }.toIntArray(), signerIndex)
    }

    override fun frostPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray {
        require(session.size == Secp256k1.FROST_SESSION_SIZE) { "invalid session size" }
        require(psigs.isNotEmpty()) { "partial signatures must not be empty" }
        psigs.forEach { require(it.size == 32) { "partial signature must be 32 bytes" } }
        return Secp256k1CFunctions.secp256k1_frost_partial_sig_agg(Secp256k1Context.getContext(), session, psigs)
    }

    private fun chilldkgFault(code: Int, faultIndex: IntArray): ChilldkgFault = ChilldkgFault(code, faultIndex[0].let { if (it == -1) null else it.toUInt() })

    override fun chilldkgHostpubkeyGen(hostseckey32: ByteArray): ByteArray {
        require(hostseckey32.size == 32) { "host secret key must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_chilldkg_hostpubkey_gen(Secp256k1Context.getContext(), hostseckey32)
    }

    override fun chilldkgParamsHash(hostpubkeys33: Array<ByteArray>, threshold: Int): ByteArray {
        require(hostpubkeys33.isNotEmpty()) { "host public keys must not be empty" }
        hostpubkeys33.forEach { require(it.size == 33) { "host public key must be 33 bytes" } }
        require(threshold in 1..hostpubkeys33.size) { "invalid threshold" }
        return Secp256k1CFunctions.secp256k1_chilldkg_params_hash(Secp256k1Context.getContext(), hostpubkeys33, threshold)
    }

    override fun chilldkgParticipantStep1(hostseckey32: ByteArray, hostpubkeys33: Array<ByteArray>, threshold: Int, random32: ByteArray): Pair<ByteArray, ByteArray> {
        require(hostseckey32.size == 32) { "host secret key must be 32 bytes" }
        require(random32.size == 32) { "randomness must be 32 bytes" }
        require(hostpubkeys33.isNotEmpty()) { "host public keys must not be empty" }
        hostpubkeys33.forEach { require(it.size == 33) { "host public key must be 33 bytes" } }
        require(threshold in 1..hostpubkeys33.size) { "invalid threshold" }
        val state1 = ByteArray(Secp256k1.CHILLDKG_PARTICIPANT_STATE1_SIZE)
        val pmsg1 = Secp256k1CFunctions.secp256k1_chilldkg_participant_step1(Secp256k1Context.getContext(), hostseckey32, hostpubkeys33, threshold, random32, state1)
        return Pair(state1, pmsg1)
    }

    override fun chilldkgCoordinatorStep1(pmsgs1: Array<ByteArray>, hostpubkeys33: Array<ByteArray>, threshold: Int): ChilldkgCoordinatorStep1Result {
        require(pmsgs1.isNotEmpty()) { "participant messages must not be empty" }
        require(pmsgs1.size == hostpubkeys33.size) { "participant messages count must match host public keys count" }
        hostpubkeys33.forEach { require(it.size == 33) { "host public key must be 33 bytes" } }
        require(threshold in 1..hostpubkeys33.size) { "invalid threshold" }
        val state = ByteArray(Secp256k1.CHILLDKG_COORDINATOR_STATE_SIZE)
        val cmsg1 = ByteArray(162 * hostpubkeys33.size + 33 * (threshold - 1))
        val faultIndex = IntArray(1)
        val fault = Secp256k1CFunctions.secp256k1_chilldkg_coordinator_step1(Secp256k1Context.getContext(), pmsgs1, hostpubkeys33, threshold, state, cmsg1, faultIndex)
        return ChilldkgCoordinatorStep1Result(chilldkgFault(fault, faultIndex), state, cmsg1)
    }

    override fun chilldkgParticipantStep2(hostseckey32: ByteArray, state1: ByteArray, cmsg1: ByteArray, auxRand32: ByteArray): ChilldkgParticipantStep2Result {
        require(hostseckey32.size == 32) { "host secret key must be 32 bytes" }
        require(state1.size == Secp256k1.CHILLDKG_PARTICIPANT_STATE1_SIZE) { "invalid participant state1 size" }
        require(cmsg1.isNotEmpty()) { "coordinator message must not be empty" }
        require(auxRand32.size == 32) { "auxiliary random data must be 32 bytes" }
        val state2 = ByteArray(Secp256k1.CHILLDKG_PARTICIPANT_STATE2_SIZE)
        val sig64 = ByteArray(64)
        val invData = ByteArray(Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE)
        val faultIndex = IntArray(1)
        val fault = Secp256k1CFunctions.secp256k1_chilldkg_participant_step2(Secp256k1Context.getContext(), hostseckey32, state1, cmsg1, auxRand32, state2, sig64, invData, faultIndex)
        return ChilldkgParticipantStep2Result(chilldkgFault(fault, faultIndex), state2, sig64, if (fault == ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR) invData else null)
    }

    override fun chilldkgCoordinatorFinalize(state: ByteArray, pmsgs2: Array<ByteArray>, threshold: Int): ChilldkgCoordinatorFinalizeResult {
        require(state.size == Secp256k1.CHILLDKG_COORDINATOR_STATE_SIZE) { "invalid coordinator state size" }
        require(pmsgs2.isNotEmpty()) { "participant messages must not be empty" }
        pmsgs2.forEach { require(it.size == 64) { "participant message must be 64 bytes" } }
        require(threshold in 1..pmsgs2.size) { "invalid threshold" }
        val n = pmsgs2.size
        val cmsg2 = ByteArray(64 * n)
        val thresholdPubkey = ByteArray(33)
        val pubshares = ByteArray(33 * n)
        val recovery = ByteArray(4 + 33 * threshold + 162 * n)
        val faultIndex = IntArray(1)
        val fault = Secp256k1CFunctions.secp256k1_chilldkg_coordinator_finalize(Secp256k1Context.getContext(), state, pmsgs2, threshold, cmsg2, thresholdPubkey, pubshares, recovery, faultIndex)
        return ChilldkgCoordinatorFinalizeResult(chilldkgFault(fault, faultIndex), cmsg2, thresholdPubkey, pubshares.toList().chunked(33) { it.toByteArray() }.toTypedArray(), recovery)
    }

    override fun chilldkgParticipantFinalize(state2: ByteArray, cmsg2: ByteArray, nParticipants: Int, threshold: Int): ChilldkgParticipantFinalizeResult {
        require(state2.size == Secp256k1.CHILLDKG_PARTICIPANT_STATE2_SIZE) { "invalid participant state2 size" }
        require(nParticipants in 1..Secp256k1.CHILLDKG_MAX_PARTICIPANTS) { "invalid number of participants" }
        require(threshold in 1..nParticipants) { "invalid threshold" }
        require(cmsg2.size == 64 * nParticipants) { "invalid certificate size" }
        val secshare = ByteArray(32)
        val thresholdPubkey = ByteArray(33)
        val pubshares = ByteArray(33 * nParticipants)
        val recovery = ByteArray(4 + 33 * threshold + 162 * nParticipants)
        val faultIndex = IntArray(1)
        val fault = Secp256k1CFunctions.secp256k1_chilldkg_participant_finalize(Secp256k1Context.getContext(), state2, cmsg2, threshold, secshare, thresholdPubkey, pubshares, recovery, faultIndex)
        return ChilldkgParticipantFinalizeResult(chilldkgFault(fault, faultIndex), secshare, thresholdPubkey, pubshares.toList().chunked(33) { it.toByteArray() }.toTypedArray(), recovery)
    }

    private fun chilldkgRecover(hostseckey32: ByteArray?, recovery: ByteArray): ChilldkgRecoverResult {
        hostseckey32?.let { require(it.size == 32) { "host secret key must be 32 bytes" } }
        require(recovery.isNotEmpty()) { "recovery data must not be empty" }
        val secshare = ByteArray(32)
        val thresholdPubkey = ByteArray(33)
        val pubshares = ByteArray(33 * Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
        val hostpubkeys = ByteArray(33 * Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
        val nAndThreshold = IntArray(2)
        val faultIndex = IntArray(1) { -1 }
        val fault = if (hostseckey32 != null) {
            Secp256k1CFunctions.secp256k1_chilldkg_participant_recover(Secp256k1Context.getContext(), hostseckey32, recovery, secshare, thresholdPubkey, pubshares, hostpubkeys, nAndThreshold, faultIndex)
        } else {
            Secp256k1CFunctions.secp256k1_chilldkg_coordinator_recover(Secp256k1Context.getContext(), recovery, thresholdPubkey, pubshares, hostpubkeys, nAndThreshold)
        }
        val n = nAndThreshold[0].coerceIn(0, Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
        val pubshareList = pubshares.copyOf(33 * n).toList().chunked(33) { it.toByteArray() }.toTypedArray()
        val hostpubkeyList = hostpubkeys.copyOf(33 * n).toList().chunked(33) { it.toByteArray() }.toTypedArray()
        return ChilldkgRecoverResult(chilldkgFault(fault, faultIndex), hostseckey32?.let { secshare }, thresholdPubkey, pubshareList, hostpubkeyList, n, nAndThreshold[1])
    }

    override fun chilldkgParticipantRecover(hostseckey32: ByteArray, recovery: ByteArray): ChilldkgRecoverResult = chilldkgRecover(hostseckey32, recovery)

    override fun chilldkgCoordinatorRecover(recovery: ByteArray): ChilldkgRecoverResult = chilldkgRecover(null, recovery)

    override fun chilldkgRecoveryAckSign(hostseckey32: ByteArray, hostpubkeys33: Array<ByteArray>, threshold: Int, recovery: ByteArray, auxRand32: ByteArray): ByteArray {
        require(hostseckey32.size == 32) { "host secret key must be 32 bytes" }
        require(auxRand32.size == 32) { "auxiliary random data must be 32 bytes" }
        require(hostpubkeys33.isNotEmpty()) { "host public keys must not be empty" }
        hostpubkeys33.forEach { require(it.size == 33) { "host public key must be 33 bytes" } }
        require(threshold in 1..hostpubkeys33.size) { "invalid threshold" }
        require(recovery.isNotEmpty()) { "recovery data must not be empty" }
        return Secp256k1CFunctions.secp256k1_chilldkg_recovery_ack_sign(Secp256k1Context.getContext(), hostseckey32, hostpubkeys33, threshold, recovery, auxRand32)
    }

    override fun chilldkgRecoveryAcksVerify(hostpubkeys33: Array<ByteArray>, threshold: Int, recovery: ByteArray, ackSigs64: Array<ByteArray>): ChilldkgFault {
        require(hostpubkeys33.isNotEmpty()) { "host public keys must not be empty" }
        hostpubkeys33.forEach { require(it.size == 33) { "host public key must be 33 bytes" } }
        require(threshold in 1..hostpubkeys33.size) { "invalid threshold" }
        require(recovery.isNotEmpty()) { "recovery data must not be empty" }
        require(ackSigs64.size == hostpubkeys33.size) { "acknowledgment signatures count must match host public keys count" }
        ackSigs64.forEach { require(it.size == 64) { "acknowledgment signature must be 64 bytes" } }
        val faultIndex = IntArray(1)
        val fault = Secp256k1CFunctions.secp256k1_chilldkg_recovery_acks_verify(Secp256k1Context.getContext(), hostpubkeys33, threshold, recovery, ackSigs64, faultIndex)
        return chilldkgFault(fault, faultIndex)
    }

    override fun chilldkgCoordinatorInvestigate(pmsgs1: Array<ByteArray>, hostpubkeys33: Array<ByteArray>, threshold: Int, participantId: UInt): Pair<ChilldkgFault, ByteArray> {
        require(pmsgs1.isNotEmpty()) { "participant messages must not be empty" }
        require(pmsgs1.size == hostpubkeys33.size) { "participant messages count must match host public keys count" }
        hostpubkeys33.forEach { require(it.size == 33) { "host public key must be 33 bytes" } }
        require(threshold in 1..hostpubkeys33.size) { "invalid threshold" }
        require(participantId < hostpubkeys33.size.toUInt()) { "invalid participant id" }
        val cinv = ByteArray(65 * hostpubkeys33.size)
        val faultIndex = IntArray(1)
        val fault = Secp256k1CFunctions.secp256k1_chilldkg_coordinator_investigate(Secp256k1Context.getContext(), pmsgs1, hostpubkeys33, threshold, participantId.toInt(), cinv, faultIndex)
        return Pair(chilldkgFault(fault, faultIndex), cinv)
    }

    override fun chilldkgParticipantInvestigate(investigationData: ByteArray, cinv: ByteArray): ChilldkgFault {
        require(investigationData.size == Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE) { "invalid investigation data size" }
        require(cinv.isNotEmpty()) { "investigation message must not be empty" }
        val faultIndex = IntArray(1)
        val fault = Secp256k1CFunctions.secp256k1_chilldkg_participant_investigate(Secp256k1Context.getContext(), investigationData, cinv, faultIndex)
        return chilldkgFault(fault, faultIndex)
    }

    override fun icebergSharesGen(n: Int, t: Int, seed32: ByteArray): Array<ByteArray> {
        require(n in 1..Secp256k1.ICEBERG_MAX_PARTICIPANTS) { "invalid number of participants" }
        require(t in 1..(n + 1) / 2) { "invalid threshold" }
        require(seed32.size == 32) { "seed must be 32 bytes" }
        val flat = Secp256k1CFunctions.secp256k1_iceberg_shares_gen(Secp256k1Context.getContext(), n, t, seed32)
        val shareLen = flat.size / n
        return (0 until n).map { flat.copyOfRange(shareLen * it, shareLen * (it + 1)) }.toTypedArray()
    }

    override fun icebergShareCacheCreate(share: ByteArray): ByteArray {
        require(share.isNotEmpty()) { "share must not be empty" }
        return Secp256k1CFunctions.secp256k1_iceberg_share_cache_create(Secp256k1Context.getContext(), share)
    }

    override fun icebergPubshareGen(share: ByteArray, cache: ByteArray?): ByteArray {
        require(share.isNotEmpty()) { "share must not be empty" }
        cache?.let { require(it.size == Secp256k1.ICEBERG_SHARE_CACHE_SIZE) { "invalid share cache size" } }
        return Secp256k1CFunctions.secp256k1_iceberg_pubshare_gen(Secp256k1Context.getContext(), share, cache)
    }

    override fun icebergPubkeyAgg(pubshares: Array<ByteArray>, n: Int, t: Int): ByteArray {
        require(pubshares.isNotEmpty()) { "public shares must not be empty" }
        pubshares.forEach { require(it.size == Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE) { "public share must be ${Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE} bytes" } }
        return Secp256k1CFunctions.secp256k1_iceberg_pubkey_agg(Secp256k1Context.getContext(), pubshares, n, t)
    }

    override fun icebergNonceGen(share: ByteArray, cache: ByteArray?, sid32: ByteArray): ByteArray {
        require(share.isNotEmpty()) { "share must not be empty" }
        cache?.let { require(it.size == Secp256k1.ICEBERG_SHARE_CACHE_SIZE) { "invalid share cache size" } }
        require(sid32.size == 32) { "session label must be 32 bytes" }
        return Secp256k1CFunctions.secp256k1_iceberg_nonce_gen(Secp256k1Context.getContext(), share, cache, sid32)
    }

    override fun icebergNonceAgg(pubnonces: Array<ByteArray>, n: Int, t: Int, groupPubkey: ByteArray): ByteArray {
        require(pubnonces.isNotEmpty()) { "public nonces must not be empty" }
        pubnonces.forEach { require(it.size == Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE} bytes" } }
        require(groupPubkey.size == 33 || groupPubkey.size == 65) { "group public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_iceberg_nonce_agg(Secp256k1Context.getContext(), pubnonces, n, t, groupPubkey)
    }

    override fun icebergKeyaggCheck(keyaggCache: ByteArray, pubkeys: Array<ByteArray>, groupPubkey: ByteArray): Boolean {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(pubkeys.isNotEmpty()) { "public keys must not be empty" }
        pubkeys.forEach { require(it.size == 33 || it.size == 65) { "public key must be 33 or 65 bytes" } }
        require(groupPubkey.size == 33 || groupPubkey.size == 65) { "group public key must be 33 or 65 bytes" }
        return Secp256k1CFunctions.secp256k1_iceberg_keyagg_check(Secp256k1Context.getContext(), keyaggCache, pubkeys, groupPubkey) == 1
    }

    override fun icebergPartialSign(share: ByteArray, cache: ByteArray?, sid32: ByteArray, pubnonces: Array<ByteArray>, groupPubkey: ByteArray, keyaggCache: ByteArray, msg32: ByteArray, cosignerAggnonce: ByteArray): ByteArray {
        require(share.isNotEmpty()) { "share must not be empty" }
        cache?.let { require(it.size == Secp256k1.ICEBERG_SHARE_CACHE_SIZE) { "invalid share cache size" } }
        require(sid32.size == 32) { "session label must be 32 bytes" }
        require(pubnonces.isNotEmpty()) { "public nonces must not be empty" }
        pubnonces.forEach { require(it.size == Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE} bytes" } }
        require(groupPubkey.size == 33 || groupPubkey.size == 65) { "group public key must be 33 or 65 bytes" }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(msg32.size == 32) { "message must be 32 bytes" }
        require(cosignerAggnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "cosigner aggregate nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
        return Secp256k1CFunctions.secp256k1_iceberg_partial_sign(Secp256k1Context.getContext(), share, cache, sid32, pubnonces, groupPubkey, keyaggCache, msg32, cosignerAggnonce)
    }

    override fun icebergPartialSigVerify(psig: ByteArray, pubshare: ByteArray, pubnonces: Array<ByteArray>, n: Int, t: Int, groupPubkey: ByteArray, keyaggCache: ByteArray, msg32: ByteArray, cosignerAggnonce: ByteArray): Int {
        require(psig.size == Secp256k1.ICEBERG_PARTIAL_SIG_SIZE) { "signature share must be ${Secp256k1.ICEBERG_PARTIAL_SIG_SIZE} bytes" }
        require(pubshare.size == Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE) { "public share must be ${Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE} bytes" }
        require(pubnonces.isNotEmpty()) { "public nonces must not be empty" }
        pubnonces.forEach { require(it.size == Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE} bytes" } }
        require(groupPubkey.size == 33 || groupPubkey.size == 65) { "group public key must be 33 or 65 bytes" }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "invalid keyagg cache size" }
        require(msg32.size == 32) { "message must be 32 bytes" }
        require(cosignerAggnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "cosigner aggregate nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
        return Secp256k1CFunctions.secp256k1_iceberg_partial_sig_verify(Secp256k1Context.getContext(), psig, pubshare, pubnonces, n, t, groupPubkey, keyaggCache, msg32, cosignerAggnonce)
    }

    override fun icebergPartialSigAgg(psigs: Array<ByteArray>, n: Int, t: Int): ByteArray {
        require(psigs.isNotEmpty()) { "signature shares must not be empty" }
        psigs.forEach { require(it.size == Secp256k1.ICEBERG_PARTIAL_SIG_SIZE) { "signature share must be ${Secp256k1.ICEBERG_PARTIAL_SIG_SIZE} bytes" } }
        return Secp256k1CFunctions.secp256k1_iceberg_partial_sig_agg(Secp256k1Context.getContext(), psigs, n, t)
    }
}
