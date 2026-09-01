package fr.acinq.secp256k1

import kotlinx.cinterop.*
import platform.posix.memcpy
import platform.posix.size_tVar
import secp256k1.*

private fun ByteArray.checkMagic(magic: ByteArray, name: String) {
    if (size < magic.size || !magic.indices.all { this[it] == magic[it] }) throw Secp256k1Exception("invalid $name")
}

/**
 * Installed on the context in place of libsecp256k1's default illegal-argument callback, which
 * aborts the process. Returning from here makes the libsecp256k1 call fail with 0, which the
 * bindings below already turn into a [Secp256k1Exception]. It is deliberately stateless: the
 * callback and its data pointer live on the context, which is shared by every thread, so recording
 * anything here would race. The [checkMagic] checks are the primary defence and this is the
 * backstop for anything they miss.
 */
@OptIn(ExperimentalForeignApi::class)
private fun illegalArgumentCallback(message: CPointer<ByteVar>?, data: COpaquePointer?) {
}

@OptIn(ExperimentalUnsignedTypes::class, ExperimentalForeignApi::class)
public object Secp256k1Native : Secp256k1 {

    private val ctx: CPointer<secp256k1_context> by lazy {
        val context = secp256k1_context_create((SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_SIGN or SECP256K1_FLAGS_BIT_CONTEXT_VERIFY).toUInt())
            ?: error("Could not create secp256k1 context")
        // secp256k1_context_set_illegal_callback needs exclusive access to the context. `lazy` is
        // synchronized by default, so this runs once before any thread can observe `ctx`.
        secp256k1_context_set_illegal_callback(context, staticCFunction(::illegalArgumentCallback), null)
        context
    }

    private fun Int.requireSuccess(message: String): Int = if (this != 1) throw Secp256k1Exception(message) else this

    private fun MemScope.allocSignature(input: ByteArray): secp256k1_ecdsa_signature {
        require(input.size == 64){ "signature size must be 64 bytes"}
        val sig = alloc<secp256k1_ecdsa_signature>()
        val nativeBytes = toNat(input)

        val result = secp256k1_ecdsa_signature_parse_compact(ctx, sig.ptr, nativeBytes)
        result.requireSuccess("cannot parse signature sig = ${Hex.encode(input)}")
        return sig
    }

    private fun MemScope.serializeSignature(signature: secp256k1_ecdsa_signature): ByteArray {
        val natOutput = allocArray<UByteVar>(64)
        secp256k1_ecdsa_signature_serialize_compact(ctx, natOutput, signature.ptr).requireSuccess("secp256k1_ecdsa_signature_serialize_compact() failed")
        return natOutput.readBytes(64)
    }

    private fun MemScope.allocPublicKey(pubkey: ByteArray): secp256k1_pubkey {
        val natPub = toNat(pubkey)
        val pub = alloc<secp256k1_pubkey>()
        secp256k1_ec_pubkey_parse(ctx, pub.ptr, natPub, pubkey.size.convert()).requireSuccess("secp256k1_ec_pubkey_parse() failed")
        return pub
    }

    private fun MemScope.allocPublicNonce(pubnonce: ByteArray): secp256k1_musig_pubnonce {
        val nat = toNat(pubnonce)
        val nPubnonce = alloc<secp256k1_musig_pubnonce>()
        secp256k1_musig_pubnonce_parse(ctx, nPubnonce.ptr, nat).requireSuccess("secp256k1_musig_pubnonce_parse() failed")
        return nPubnonce
    }

    private fun MemScope.allocPartialSig(psig: ByteArray): secp256k1_musig_partial_sig {
        val nat = toNat(psig)
        val nPsig = alloc<secp256k1_musig_partial_sig>()
        secp256k1_musig_partial_sig_parse(ctx, nPsig.ptr, nat).requireSuccess("secp256k1_musig_partial_sig_parse() failed")
        return nPsig
    }

    private fun MemScope.serializePubkey(pubkey: secp256k1_pubkey): ByteArray {
        val serialized = allocArray<UByteVar>(65)
        val outputLen = alloc<size_tVar>()
        outputLen.value = 65.convert()
        secp256k1_ec_pubkey_serialize(ctx, serialized, outputLen.ptr, pubkey.ptr, SECP256K1_EC_UNCOMPRESSED.convert()).requireSuccess("secp256k1_ec_pubkey_serialize() failed")
        return serialized.readBytes(outputLen.value.convert())
    }

    private fun MemScope.serializeXonlyPubkey(pubkey: secp256k1_xonly_pubkey): ByteArray {
        val serialized = allocArray<UByteVar>(32)
        secp256k1_xonly_pubkey_serialize(ctx, serialized, pubkey.ptr).requireSuccess("secp256k1_xonly_pubkey_serialize() failed")
        return serialized.readBytes(32)
    }

    private fun MemScope.serializePubnonce(pubnonce: secp256k1_musig_pubnonce): ByteArray {
        val serialized = allocArray<UByteVar>(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        secp256k1_musig_pubnonce_serialize(ctx, serialized, pubnonce.ptr).requireSuccess("secp256k1_musig_pubnonce_serialize() failed")
        return serialized.readBytes(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
    }

    private fun MemScope.serializeAggnonce(aggnonce: secp256k1_musig_aggnonce): ByteArray {
        val serialized = allocArray<UByteVar>(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        secp256k1_musig_aggnonce_serialize(ctx, serialized, aggnonce.ptr).requireSuccess("secp256k1_musig_aggnonce_serialize() failed")
        return serialized.readBytes(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
    }

    private fun DeferScope.toNat(bytes: ByteArray): CPointer<UByteVar> {
        val ubytes = bytes.asUByteArray()
        val pinned = ubytes.pin()
        this.defer { pinned.unpin() }
        return pinned.addressOf(0)
    }

    /**
     * Same as [toNat], but supports empty byte arrays: the BIP-FROST reference distinguishes an absent value
     * (null pointer) from an empty one (non-null pointer with size 0), so empty arrays must not be collapsed to
     * null. Pinning an empty array would fail, so we allocate a dummy 1-byte buffer instead (it is never read
     * since the size passed alongside is 0).
     */
    private fun MemScope.toNatAllowEmpty(bytes: ByteArray): CPointer<UByteVar> {
        return if (bytes.isEmpty()) allocArray<UByteVar>(1) else toNat(bytes)
    }

    public override fun verify(signature: ByteArray, message: ByteArray, pubkey: ByteArray): Boolean {
        require(message.size == 32)
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nMessage = toNat(message)
            val nSig = allocSignature(signature)
            return secp256k1_ecdsa_verify(ctx, nSig.ptr, nMessage, nPubkey.ptr) == 1
        }
    }

    public override fun sign(message: ByteArray, privkey: ByteArray, ndata: ByteArray?): ByteArray {
        require(privkey.size == 32)
        require(message.size == 32)
        ndata?.let { require(it.size == 32) }
        memScoped {
            val nPrivkey = toNat(privkey)
            val nMessage = toNat(message)
            val nNdata = ndata?.let { toNat(it) }
            val nSig = alloc<secp256k1_ecdsa_signature>()
            secp256k1_ecdsa_sign(ctx, nSig.ptr, nMessage, nPrivkey, null, nNdata).requireSuccess("secp256k1_ecdsa_sign() failed")
            return serializeSignature(nSig)
        }
    }

    public override fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean> {
        memScoped {
            val nSig = allocSignature(sig)
            val isHighS = secp256k1_ecdsa_signature_normalize(ctx, nSig.ptr, nSig.ptr)
            return Pair(serializeSignature(nSig), isHighS == 1)
        }
    }

    public override fun secKeyVerify(privkey: ByteArray): Boolean {
        if (privkey.size != 32) return false
        memScoped {
            val nPrivkey = toNat(privkey)
            return secp256k1_ec_seckey_verify(ctx, nPrivkey) == 1
        }
    }

    public override fun pubkeyCreate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val nPrivkey = toNat(privkey)
            val nPubkey = alloc<secp256k1_pubkey>()
            secp256k1_ec_pubkey_create(ctx, nPubkey.ptr, nPrivkey).requireSuccess("secp256k1_ec_pubkey_create() failed")
            return serializePubkey(nPubkey)
        }
    }

    public override fun pubkeyParse(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            return serializePubkey(nPubkey)
        }
    }

    public override fun privKeyNegate(privkey: ByteArray): ByteArray {
        require(privkey.size == 32)
        memScoped {
            val negated = privkey.copyOf()
            val negPriv = toNat(negated)
            secp256k1_ec_seckey_negate(ctx, negPriv).requireSuccess("secp256k1_ec_seckey_negate() failed")
            return negated
        }
    }

    public override fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32)
        require(tweak.size == 32)
        memScoped {
            val added = privkey.copyOf()
            val natAdd = toNat(added)
            val natTweak = toNat(tweak)
            secp256k1_ec_seckey_tweak_add(ctx, natAdd, natTweak).requireSuccess("secp256k1_ec_seckey_tweak_add() failed")
            return added
        }
    }

    public override fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray {
        require(privkey.size == 32)
        require(tweak.size == 32)
        memScoped {
            val multiplied = privkey.copyOf()
            val natMul = toNat(multiplied)
            val natTweak = toNat(tweak)
            secp256k1_ec_seckey_tweak_mul(ctx, natMul, natTweak).requireSuccess("secp256k1_ec_seckey_tweak_mul() failed")
            return multiplied
        }
    }

    public override fun pubKeyNegate(pubkey: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            secp256k1_ec_pubkey_negate(ctx, nPubkey.ptr).requireSuccess("secp256k1_ec_pubkey_negate() failed")
            return serializePubkey(nPubkey)
        }
    }

    public override fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        require(tweak.size == 32)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nTweak = toNat(tweak)
            secp256k1_ec_pubkey_tweak_add(ctx, nPubkey.ptr, nTweak).requireSuccess("secp256k1_ec_pubkey_tweak_add() failed")
            return serializePubkey(nPubkey)
        }
    }

    public override fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        require(pubkey.size == 33 || pubkey.size == 65)
        require(tweak.size == 32)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nTweak = toNat(tweak)
            secp256k1_ec_pubkey_tweak_mul(ctx, nPubkey.ptr, nTweak).requireSuccess("secp256k1_ec_pubkey_tweak_mul() failed")
            return serializePubkey(nPubkey)
        }
    }

    public override fun pubKeyCombine(pubkeys: Array<ByteArray>): ByteArray {
        require(pubkeys.isNotEmpty())
        pubkeys.forEach { require(it.size == 33 || it.size == 65) }
        memScoped {
            val nPubkeys = pubkeys.map { allocPublicKey(it).ptr }
            val combined = alloc<secp256k1_pubkey>()
            secp256k1_ec_pubkey_combine(ctx, combined.ptr, nPubkeys.toCValues(), pubkeys.size.convert()).requireSuccess("secp256k1_ec_pubkey_combine() failed")
            return serializePubkey(combined)
        }
    }

    public override fun ecdh(privkey: ByteArray, pubkey: ByteArray): ByteArray {
        require(privkey.size == 32)
        require(pubkey.size == 33 || pubkey.size == 65)
        memScoped {
            val nPubkey = allocPublicKey(pubkey)
            val nPrivkey = toNat(privkey)
            val output = allocArray<UByteVar>(32)
            secp256k1_ecdh(ctx, output, nPubkey.ptr, nPrivkey, null, null).requireSuccess("secp256k1_ecdh() failed")
            return output.readBytes(32)
        }
    }

    public override fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        require(sig.size == 64)
        require(message.size == 32)
        require(recid in 0..3)
        memScoped {
            val nSig = toNat(sig)
            val rSig = alloc<secp256k1_ecdsa_recoverable_signature>()
            secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, rSig.ptr, nSig, recid).requireSuccess("secp256k1_ecdsa_recoverable_signature_parse_compact() failed")
            val nMessage = toNat(message)
            val pubkey = alloc<secp256k1_pubkey>()
            secp256k1_ecdsa_recover(ctx, pubkey.ptr, rSig.ptr, nMessage).requireSuccess("secp256k1_ecdsa_recover() failed")
            return serializePubkey(pubkey)
        }
    }

    public override fun compact2der(sig: ByteArray): ByteArray {
        memScoped {
            val nSig = allocSignature(sig)
            val natOutput = allocArray<UByteVar>(73)
            val len = alloc<size_tVar>()
            len.value = 73.convert()
            secp256k1_ecdsa_signature_serialize_der(ctx, natOutput, len.ptr, nSig.ptr).requireSuccess("secp256k1_ecdsa_signature_serialize_der() failed")
            return natOutput.readBytes(len.value.toInt())
        }
    }

    override fun der2compact(sig: ByteArray): ByteArray {
        require(sig.size in 8..73)
        memScoped {
            val nSig = alloc<secp256k1_ecdsa_signature>()
            val nativeBytes = toNat(sig)
            secp256k1_ecdsa_signature_parse_der(ctx, nSig.ptr, nativeBytes, sig.size.convert()).requireSuccess("secp256k1_ecdsa_signature_parse_der() failed")

            val natOutput = allocArray<UByteVar>(64)
            secp256k1_ecdsa_signature_serialize_compact(ctx, natOutput, nSig.ptr).requireSuccess("secp256k1_ecdsa_signature_serialize_compact() failed")
            return natOutput.readBytes(64)
        }
    }

    override fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean {
        require(signature.size == 64)
        require(data.size == 32)
        require(pub.size == 32)
        memScoped {
            val nPub = toNat(pub)
            val pubkey = alloc<secp256k1_xonly_pubkey>()
            secp256k1_xonly_pubkey_parse(ctx, pubkey.ptr, nPub).requireSuccess("secp256k1_xonly_pubkey_parse() failed")
            val nData = toNat(data)
            val nSig = toNat(signature)
            return secp256k1_schnorrsig_verify(ctx, nSig, nData, 32u, pubkey.ptr) == 1
        }
    }

    override fun signSchnorr(data: ByteArray, sec: ByteArray, auxrand32: ByteArray?): ByteArray {
        require(sec.size == 32)
        require(data.size == 32)
        auxrand32?.let { require(it.size == 32) }
        memScoped {
            val nSec = toNat(sec)
            val nData = toNat(data)
            val nAuxrand32 = auxrand32?.let { toNat(it) }
            val nSig = allocArray<UByteVar>(64)
            val keypair = alloc<secp256k1_keypair>()
            secp256k1_keypair_create(ctx, keypair.ptr, nSec).requireSuccess("secp256k1_keypair_create() failed")
            secp256k1_schnorrsig_sign32(ctx, nSig, nData, keypair.ptr, nAuxrand32).requireSuccess("secp256k1_ecdsa_sign() failed")
            return nSig.readBytes(64)
        }
    }

    override fun musigNonceGen(sessionRandom32: ByteArray, privkey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        require(sessionRandom32.size == 32)
        privkey?.let { require(it.size == 32) }
        msg32?.let { require(it.size == 32) }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) }
        keyaggCache?.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        extraInput32?.let { require(it.size == 32) }

        val nonce = memScoped {
            val secnonce = alloc<secp256k1_musig_secnonce>()
            val pubnonce = alloc<secp256k1_musig_pubnonce>()
            val nPubkey = allocPublicKey(pubkey)
            val nKeyAggCache = keyaggCache?.let {
                val n = alloc<secp256k1_musig_keyagg_cache>()
                memcpy(n.ptr, toNat(it), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
                n
            }
            // we make a native copy of sessionRandom32, which will be zeroed by secp256k1_musig_nonce_gen
            val sessionRand32 = allocArray<UByteVar>(32)
            memcpy(sessionRand32.pointed.ptr, toNat(sessionRandom32), 32u)
            secp256k1_musig_nonce_gen(
                ctx,
                secnonce.ptr,
                pubnonce.ptr,
                sessionRand32,
                privkey?.let { toNat(it) },
                nPubkey.ptr,
                msg32?.let { toNat(it) },
                nKeyAggCache?.ptr,
                extraInput32?.let { toNat(it) }).requireSuccess("secp256k1_musig_nonce_gen() failed")
            val nPubnonce = allocArray<UByteVar>(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
            secp256k1_musig_pubnonce_serialize(ctx, nPubnonce, pubnonce.ptr).requireSuccess("secp256k1_musig_pubnonce_serialize failed")
            secnonce.ptr.readBytes(Secp256k1.MUSIG2_SECRET_NONCE_SIZE) + nPubnonce.readBytes(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        }
        return nonce
    }

    override fun musigNonceGenCounter(nonRepeatingCounter: ULong, privkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        require(privkey.size ==32)
        msg32?.let { require(it.size == 32) }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) }
        keyaggCache?.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        extraInput32?.let { require(it.size == 32) }
        val nonce = memScoped {
            val secnonce = alloc<secp256k1_musig_secnonce>()
            val pubnonce = alloc<secp256k1_musig_pubnonce>()
            val nKeypair = alloc<secp256k1_keypair>()
            secp256k1_keypair_create(ctx, nKeypair.ptr, toNat(privkey)).requireSuccess("secp256k1_keypair_create() failed")
            val nKeyAggCache = keyaggCache?.let {
                val n = alloc<secp256k1_musig_keyagg_cache>()
                memcpy(n.ptr, toNat(it), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
                n
            }
            secp256k1_musig_nonce_gen_counter(ctx, secnonce.ptr, pubnonce.ptr, nonRepeatingCounter, nKeypair.ptr, msg32?.let { toNat(it) },nKeyAggCache?.ptr, extraInput32?.let { toNat(it) }).requireSuccess("secp256k1_musig_nonce_gen_counter() failed")
            val nPubnonce = allocArray<UByteVar>(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
            secp256k1_musig_pubnonce_serialize(ctx, nPubnonce, pubnonce.ptr).requireSuccess("secp256k1_musig_pubnonce_serialize failed")
            secnonce.ptr.readBytes(Secp256k1.MUSIG2_SECRET_NONCE_SIZE) + nPubnonce.readBytes(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        }
        return nonce
    }

    override fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray {
        require(pubnonces.isNotEmpty())
        pubnonces.forEach { require(it.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) }
        memScoped {
            val nPubnonces = pubnonces.map { allocPublicNonce(it).ptr }
            val combined = alloc<secp256k1_musig_aggnonce>()
            secp256k1_musig_nonce_agg(ctx, combined.ptr, nPubnonces.toCValues(), pubnonces.size.convert()).requireSuccess("secp256k1_musig_nonce_agg() failed")
            return serializeAggnonce(combined)
        }
    }

    override fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray {
        require(pubkeys.isNotEmpty())
        pubkeys.forEach { require(it.size == 33 || it.size == 65) }
        keyaggCache?.let { require(it.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) }
        memScoped {
            val nPubkeys = pubkeys.map { allocPublicKey(it).ptr }
            val combined = alloc<secp256k1_xonly_pubkey>()
            val nKeyAggCache = keyaggCache?.let {
                val n = alloc<secp256k1_musig_keyagg_cache>()
                memcpy(n.ptr, toNat(it), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
                n
            }
            secp256k1_musig_pubkey_agg(ctx, combined.ptr, nKeyAggCache?.ptr, nPubkeys.toCValues(), pubkeys.size.convert()).requireSuccess("secp256k1_musig_nonce_agg() failed")
            val agg = serializeXonlyPubkey(combined)
            keyaggCache?.let { blob -> nKeyAggCache?.let { memcpy(toNat(blob), it.ptr, Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong()) } }
            return agg
        }
    }

    override fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(tweak32.size == 32)
        keyaggCache.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        memScoped {
            val nKeyAggCache = alloc<secp256k1_musig_keyagg_cache>()
            memcpy(nKeyAggCache.ptr, toNat(keyaggCache), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
            val nPubkey = alloc<secp256k1_pubkey>()
            secp256k1_musig_pubkey_ec_tweak_add(ctx, nPubkey.ptr, nKeyAggCache.ptr, toNat(tweak32)).requireSuccess("secp256k1_musig_pubkey_ec_tweak_add() failed")
            memcpy(toNat(keyaggCache), nKeyAggCache.ptr, Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
            return serializePubkey(nPubkey)
        }
    }

    override fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(tweak32.size == 32)
        keyaggCache.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        memScoped {
            val nKeyAggCache = alloc<secp256k1_musig_keyagg_cache>()
            memcpy(nKeyAggCache.ptr, toNat(keyaggCache), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
            val nPubkey = alloc<secp256k1_pubkey>()
            secp256k1_musig_pubkey_xonly_tweak_add(ctx, nPubkey.ptr, nKeyAggCache.ptr, toNat(tweak32)).requireSuccess("secp256k1_musig_pubkey_xonly_tweak_add() failed")
            memcpy(toNat(keyaggCache), nKeyAggCache.ptr, Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
            return serializePubkey(nPubkey)
        }
    }

    override fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray {
        require(aggnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(msg32.size == 32)
        keyaggCache.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        memScoped {
            val nKeyAggCache = alloc<secp256k1_musig_keyagg_cache>()
            memcpy(nKeyAggCache.ptr, toNat(keyaggCache), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
            val nSession = alloc<secp256k1_musig_session>()
            val nAggnonce = alloc<secp256k1_musig_aggnonce>()
            secp256k1_musig_aggnonce_parse(ctx, nAggnonce.ptr, toNat(aggnonce)).requireSuccess("secp256k1_musig_aggnonce_parse() failed")
            secp256k1_musig_nonce_process(ctx, nSession.ptr, nAggnonce.ptr, toNat(msg32), nKeyAggCache.ptr, null).requireSuccess("secp256k1_musig_nonce_process() failed")
            val session = ByteArray(Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE)
            memcpy(toNat(session), nSession.ptr, Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE.toULong())
            return session
        }
    }

    override fun musigPartialSign(secnonce: ByteArray, privkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): ByteArray {
        require(secnonce.size == Secp256k1.MUSIG2_SECRET_NONCE_SIZE)
        require(privkey.size == 32)
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE)
        keyaggCache.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        session.checkMagic(Secp256k1.MUSIG_SESSION_MAGIC, "session")
        if (!musigNonceValidate(secnonce, pubkeyCreate(privkey))) throw Secp256k1Exception("invalid secret nonce")

        memScoped {
            val nSecnonce = alloc<secp256k1_musig_secnonce>()
            memcpy(nSecnonce.ptr, toNat(secnonce), Secp256k1.MUSIG2_SECRET_NONCE_SIZE.toULong())
            val nKeypair = alloc<secp256k1_keypair>()
            secp256k1_keypair_create(ctx, nKeypair.ptr, toNat(privkey)).requireSuccess("secp256k1_keypair_create() failed")
            val nPsig = alloc<secp256k1_musig_partial_sig>()
            val nKeyAggCache = alloc<secp256k1_musig_keyagg_cache>()
            memcpy(nKeyAggCache.ptr, toNat(keyaggCache), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
            val nSession = alloc<secp256k1_musig_session>()
            memcpy(nSession.ptr, toNat(session), Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE.toULong())
            secp256k1_musig_partial_sign(ctx, nPsig.ptr, nSecnonce.ptr, nKeypair.ptr, nKeyAggCache.ptr, nSession.ptr).requireSuccess("secp256k1_musig_partial_sign failed")
            val psig = ByteArray(32)
            secp256k1_musig_partial_sig_serialize(ctx, toNat(psig), nPsig.ptr).requireSuccess("secp256k1_musig_partial_sig_serialize() failed")
            return psig
        }
    }

    override fun musigPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int {
        require(psig.size == 32)
        require(pubnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        require(pubkey.size == 33 || pubkey.size == 65)
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE)
        keyaggCache.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        session.checkMagic(Secp256k1.MUSIG_SESSION_MAGIC, "session")

        memScoped {
            val nPSig = allocPartialSig(psig)
            val nPubnonce = allocPublicNonce(pubnonce)
            val nPubkey = allocPublicKey(pubkey)
            val nKeyAggCache = alloc<secp256k1_musig_keyagg_cache>()
            memcpy(nKeyAggCache.ptr, toNat(keyaggCache), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
            val nSession = alloc<secp256k1_musig_session>()
            memcpy(nSession.ptr, toNat(session), Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE.toULong())
            return secp256k1_musig_partial_sig_verify(ctx, nPSig.ptr, nPubnonce.ptr, nPubkey.ptr, nKeyAggCache.ptr, nSession.ptr)
        }
    }

    override fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray {
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE)
        require(psigs.isNotEmpty())
        psigs.forEach { require(it.size == 32) }
        session.checkMagic(Secp256k1.MUSIG_SESSION_MAGIC, "session")
        memScoped {
            val nSession = alloc<secp256k1_musig_session>()
            memcpy(nSession.ptr, toNat(session), Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE.toULong())
            val nPsigs = psigs.map { allocPartialSig(it).ptr }
            val sig64 = ByteArray(64)
            secp256k1_musig_partial_sig_agg(ctx, toNat(sig64), nSession.ptr, nPsigs.toCValues(), psigs.size.convert()).requireSuccess("secp256k1_musig_partial_sig_agg() failed")
            return sig64
        }
    }

    override fun musigPubkeyGet(keyaggCache: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        keyaggCache.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        memScoped {
            val nKeyAggCache = alloc<secp256k1_musig_keyagg_cache>()
            memcpy(nKeyAggCache.ptr, toNat(keyaggCache), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
            val nPubkey = alloc<secp256k1_pubkey>()
            secp256k1_musig_pubkey_get(ctx, nPubkey.ptr, nKeyAggCache.ptr).requireSuccess("secp256k1_musig_pubkey_get() failed")
            return serializePubkey(nPubkey)
        }
    }

    override fun musigNonceParity(session: ByteArray): Int {
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE)
        session.checkMagic(Secp256k1.MUSIG_SESSION_MAGIC, "session")
        memScoped {
            val nSession = alloc<secp256k1_musig_session>()
            memcpy(nSession.ptr, toNat(session), Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE.toULong())
            val nParity = alloc<IntVar>()
            secp256k1_musig_nonce_parity(ctx, nParity.ptr, nSession.ptr).requireSuccess("secp256k1_musig_nonce_parity() failed")
            return nParity.value
        }
    }

    override fun musigAdapt(preSig64: ByteArray, secAdaptor32: ByteArray, nonceParity: Int): ByteArray {
        require(preSig64.size == 64)
        require(secAdaptor32.size == 32)
        require(nonceParity in 0..1)
        memScoped {
            val nSig64 = allocArray<UByteVar>(64)
            secp256k1_musig_adapt(ctx, nSig64, toNat(preSig64), toNat(secAdaptor32), nonceParity).requireSuccess("secp256k1_musig_adapt() failed")
            return nSig64.readBytes(64)
        }
    }

    override fun musigExtractAdaptor(sig64: ByteArray, preSig64: ByteArray, nonceParity: Int): ByteArray {
        require(sig64.size == 64)
        require(preSig64.size == 64)
        require(nonceParity in 0..1)
        memScoped {
            val nSecAdaptor32 = allocArray<UByteVar>(32)
            secp256k1_musig_extract_adaptor(ctx, nSecAdaptor32, toNat(sig64), toNat(preSig64), nonceParity).requireSuccess("secp256k1_musig_extract_adaptor() failed")
            return nSecAdaptor32.readBytes(32)
        }
    }

    private fun MemScope.allocFrostPubnonce(pubnonce: ByteArray): secp256k1_frost_pubnonce {
        val nat = toNat(pubnonce)
        val nPubnonce = alloc<secp256k1_frost_pubnonce>()
        secp256k1_frost_pubnonce_parse(ctx, nPubnonce.ptr, nat).requireSuccess("secp256k1_frost_pubnonce_parse() failed")
        return nPubnonce
    }

    private fun MemScope.allocFrostPartialSig(psig: ByteArray): secp256k1_frost_partial_sig {
        val nat = toNat(psig)
        val nPsig = alloc<secp256k1_frost_partial_sig>()
        secp256k1_frost_partial_sig_parse(ctx, nPsig.ptr, nat).requireSuccess("secp256k1_frost_partial_sig_parse() failed")
        return nPsig
    }

    private fun MemScope.allocFrostTweakCache(tweakCache: ByteArray): secp256k1_frost_tweak_cache {
        tweakCache.checkMagic(Secp256k1.FROST_TWEAK_CACHE_MAGIC, "tweak cache")
        val nCache = alloc<secp256k1_frost_tweak_cache>()
        memcpy(nCache.ptr, toNat(tweakCache), Secp256k1.FROST_TWEAK_CACHE_SIZE.toULong())
        return nCache
    }

    private fun MemScope.allocFrostSession(session: ByteArray): secp256k1_frost_session {
        session.checkMagic(Secp256k1.FROST_SESSION_MAGIC, "session")
        val nSession = alloc<secp256k1_frost_session>()
        memcpy(nSession.ptr, toNat(session), Secp256k1.FROST_SESSION_SIZE.toULong())
        return nSession
    }

    private fun MemScope.allocPubshares(pubshares: Array<ByteArray>?): CPointer<secp256k1_pubkey>? =
        pubshares?.let { shares ->
            shares.forEach { require(it.size == 33 || it.size == 65) }
            val nShares = allocArray<secp256k1_pubkey>(shares.size)
            shares.forEachIndexed { i, share ->
                secp256k1_ec_pubkey_parse(ctx, nShares[i].ptr, toNat(share), share.size.convert()).requireSuccess("secp256k1_ec_pubkey_parse() failed")
            }
            nShares
        }

    override fun frostTrustedDealerKeygen(thresholdSeckey32: ByteArray, nParticipants: Int, threshold: Int): Triple<ByteArray, Array<ByteArray>, Array<ByteArray>> {
        require(thresholdSeckey32.size == 32)
        require(nParticipants in 1..Secp256k1.FROST_MAX_PARTICIPANTS)
        require(threshold in 1..nParticipants)
        memScoped {
            val nSecshares = allocArray<UByteVar>(32 * nParticipants)
            val nThreshPk = alloc<secp256k1_pubkey>()
            val nPubshares = allocArray<secp256k1_pubkey>(nParticipants)
            secp256k1_frost_trusted_dealer_keygen(ctx, nSecshares, nThreshPk.ptr, nPubshares, nParticipants.convert(), threshold.toUInt(), toNat(thresholdSeckey32)).requireSuccess("secp256k1_frost_trusted_dealer_keygen() failed")
            val secshares = nSecshares.readBytes(32 * nParticipants).toList().chunked(32) { it.toByteArray() }.toTypedArray()
            val pubshares = (0 until nParticipants).map { serializePubkey(nPubshares[it]) }.toTypedArray()
            return Triple(serializePubkey(nThreshPk), secshares, pubshares)
        }
    }

    override fun frostThresholdInfoValidate(thresholdPubkey: ByteArray, pubshares: Array<ByteArray>, threshold: Int): Boolean {
        require(pubshares.isNotEmpty())
        pubshares.forEach { require(it.size == 33 || it.size == 65) }
        require(threshold in 1..pubshares.size)
        memScoped {
            val nThreshPk = allocPublicKey(thresholdPubkey)
            val nPubshares = allocPubshares(pubshares)
            return secp256k1_frost_threshold_info_validate(ctx, nThreshPk.ptr, nPubshares, pubshares.size.convert(), threshold.toUInt()) == 1
        }
    }

    override fun frostTweakCacheInit(thresholdPubkey: ByteArray): ByteArray {
        require(thresholdPubkey.size == 33 || thresholdPubkey.size == 65)
        memScoped {
            val nThreshPk = allocPublicKey(thresholdPubkey)
            val nCache = alloc<secp256k1_frost_tweak_cache>()
            secp256k1_frost_tweak_cache_init(ctx, nCache.ptr, nThreshPk.ptr).requireSuccess("secp256k1_frost_tweak_cache_init() failed")
            return nCache.ptr.readBytes(Secp256k1.FROST_TWEAK_CACHE_SIZE)
        }
    }

    override fun frostTweakedPubkeyGet(tweakCache: ByteArray): ByteArray {
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE)
        memScoped {
            val nCache = allocFrostTweakCache(tweakCache)
            val nTweakedPk = alloc<secp256k1_xonly_pubkey>()
            secp256k1_frost_tweaked_pubkey_get(ctx, nTweakedPk.ptr, nCache.ptr).requireSuccess("secp256k1_frost_tweaked_pubkey_get() failed")
            return serializeXonlyPubkey(nTweakedPk)
        }
    }

    private fun frostPubkeyTweakAdd(tweakCache: ByteArray, tweak32: ByteArray, xonly: Boolean): ByteArray {
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE)
        require(tweak32.size == 32)
        memScoped {
            val nCache = allocFrostTweakCache(tweakCache)
            val nTweakedPk = alloc<secp256k1_xonly_pubkey>()
            val result = if (xonly) {
                secp256k1_frost_pubkey_xonly_tweak_add(ctx, nTweakedPk.ptr, nCache.ptr, toNat(tweak32))
            } else {
                secp256k1_frost_pubkey_ec_tweak_add(ctx, nTweakedPk.ptr, nCache.ptr, toNat(tweak32))
            }
            result.requireSuccess("secp256k1_frost_pubkey_tweak_add() failed")
            memcpy(toNat(tweakCache), nCache.ptr, Secp256k1.FROST_TWEAK_CACHE_SIZE.toULong())
            return serializeXonlyPubkey(nTweakedPk)
        }
    }

    override fun frostPubkeyXonlyTweakAdd(tweakCache: ByteArray, tweak32: ByteArray): ByteArray = frostPubkeyTweakAdd(tweakCache, tweak32, xonly = true)

    override fun frostPubkeyEcTweakAdd(tweakCache: ByteArray, tweak32: ByteArray): ByteArray = frostPubkeyTweakAdd(tweakCache, tweak32, xonly = false)

    override fun frostNonceGen(sessionRandom32: ByteArray, secshare32: ByteArray?, pubshare: ByteArray?, thresholdPubkey32: ByteArray?, msg: ByteArray?, extraInput: ByteArray?): ByteArray {
        require(sessionRandom32.size == 32)
        secshare32?.let { require(it.size == 32) }
        thresholdPubkey32?.let { require(it.size == 32) }
        memScoped {
            val nSecnonce = alloc<secp256k1_frost_secnonce>()
            val nPubnonce = alloc<secp256k1_frost_pubnonce>()
            val nPubshare = pubshare?.let { allocPublicKey(it) }
            // we make a native copy of sessionRandom32, which will be zeroed by secp256k1_frost_nonce_gen
            val sessionRand32 = allocArray<UByteVar>(32)
            memcpy(sessionRand32.pointed.ptr, toNat(sessionRandom32), 32u)
            secp256k1_frost_nonce_gen(
                ctx,
                nSecnonce.ptr,
                nPubnonce.ptr,
                sessionRand32,
                secshare32?.let { toNat(it) },
                nPubshare?.ptr,
                thresholdPubkey32?.let { toNat(it) },
                msg?.let { toNatAllowEmpty(it) },
                msg?.size?.convert() ?: 0uL,
                extraInput?.let { toNatAllowEmpty(it) },
                extraInput?.size?.convert() ?: 0uL
            ).requireSuccess("secp256k1_frost_nonce_gen() failed")
            val nPubnonceSerialized = allocArray<UByteVar>(Secp256k1.FROST_PUBLIC_NONCE_SIZE)
            secp256k1_frost_pubnonce_serialize(ctx, nPubnonceSerialized, nPubnonce.ptr).requireSuccess("secp256k1_frost_pubnonce_serialize failed")
            return nSecnonce.ptr.readBytes(Secp256k1.FROST_SECRET_NONCE_SIZE) + nPubnonceSerialized.readBytes(Secp256k1.FROST_PUBLIC_NONCE_SIZE)
        }
    }

    override fun frostNonceAgg(pubnonces: Array<ByteArray>): ByteArray {
        require(pubnonces.isNotEmpty())
        pubnonces.forEach { require(it.size == Secp256k1.FROST_PUBLIC_NONCE_SIZE) }
        memScoped {
            val nPubnonces = pubnonces.map { allocFrostPubnonce(it).ptr }
            val nErrorIndex = alloc<size_tVar>()
            val combined = alloc<secp256k1_frost_aggnonce>()
            secp256k1_frost_nonce_agg(ctx, combined.ptr, nErrorIndex.ptr, nPubnonces.toCValues(), pubnonces.size.convert()).requireSuccess("secp256k1_frost_nonce_agg() failed")
            val serialized = allocArray<UByteVar>(Secp256k1.FROST_PUBLIC_NONCE_SIZE)
            secp256k1_frost_aggnonce_serialize(ctx, serialized, combined.ptr).requireSuccess("secp256k1_frost_aggnonce_serialize() failed")
            return serialized.readBytes(Secp256k1.FROST_PUBLIC_NONCE_SIZE)
        }
    }

    override fun frostSessionInit(aggnonce: ByteArray, ids: UIntArray, pubshares: Array<ByteArray>?, nParticipants: Int, threshold: Int, tweakCache: ByteArray, msg: ByteArray): ByteArray {
        require(aggnonce.size == Secp256k1.FROST_PUBLIC_NONCE_SIZE)
        require(ids.isNotEmpty())
        require(ids.all { it < nParticipants.toUInt() })
        require(ids.toSet().size == ids.size) { "signer ids must be unique" }
        pubshares?.let { require(it.size == ids.size) }
        require(nParticipants in 1..Secp256k1.FROST_MAX_PARTICIPANTS)
        require(threshold in 1..nParticipants)
        require(ids.size in threshold..nParticipants)
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE)
        memScoped {
            val nAggnonce = alloc<secp256k1_frost_aggnonce>()
            secp256k1_frost_aggnonce_parse(ctx, nAggnonce.ptr, toNat(aggnonce)).requireSuccess("secp256k1_frost_aggnonce_parse() failed")
            val nPubshares = allocPubshares(pubshares)
            val nCache = allocFrostTweakCache(tweakCache)
            val nSession = alloc<secp256k1_frost_session>()
            secp256k1_frost_session_init(
                ctx,
                nSession.ptr,
                nAggnonce.ptr,
                ids.toCValues(),
                nPubshares,
                ids.size.convert(),
                nParticipants.convert(),
                threshold.toUInt(),
                nCache.ptr,
                toNatAllowEmpty(msg),
                msg.size.convert()
            ).requireSuccess("secp256k1_frost_session_init() failed")
            return nSession.ptr.readBytes(Secp256k1.FROST_SESSION_SIZE)
        }
    }

    override fun frostSign(secnonce: ByteArray, secshare32: ByteArray, session: ByteArray, ids: UIntArray, pubshares: Array<ByteArray>?, myId: UInt): ByteArray {
        require(secnonce.size == Secp256k1.FROST_SECRET_NONCE_SIZE)
        require(secshare32.size == 32)
        require(ids.isNotEmpty())
        require(myId in ids) { "signer id must be one of the session's signer ids" }
        pubshares?.let { require(it.size == ids.size) }
        secnonce.checkMagic(Secp256k1.FROST_SECNONCE_MAGIC, "secret nonce")
        memScoped {
            val nSecnonce = alloc<secp256k1_frost_secnonce>()
            memcpy(nSecnonce.ptr, toNat(secnonce), Secp256k1.FROST_SECRET_NONCE_SIZE.toULong())
            val nSession = allocFrostSession(session)
            val nPubshares = allocPubshares(pubshares)
            val nPsig = alloc<secp256k1_frost_partial_sig>()
            secp256k1_frost_sign(ctx, nPsig.ptr, nSecnonce.ptr, toNat(secshare32), nSession.ptr, ids.toCValues(), nPubshares, ids.size.convert(), myId).requireSuccess("secp256k1_frost_sign() failed")
            val psig = ByteArray(32)
            secp256k1_frost_partial_sig_serialize(ctx, toNat(psig), nPsig.ptr).requireSuccess("secp256k1_frost_partial_sig_serialize() failed")
            return psig
        }
    }

    override fun frostDeterministicSign(secshare32: ByteArray, myId: UInt, aggOtherNonce: ByteArray?, ids: UIntArray, pubshares: Array<ByteArray>?, nParticipants: Int, threshold: Int, tweakCache: ByteArray, msg: ByteArray, auxRand32: ByteArray?): Pair<ByteArray, ByteArray> {
        require(secshare32.size == 32)
        require(ids.isNotEmpty())
        require(myId in ids) { "signer id must be one of the session's signer ids" }
        aggOtherNonce?.let { require(it.size == Secp256k1.FROST_PUBLIC_NONCE_SIZE) }
        pubshares?.let { require(it.size == ids.size) }
        require(nParticipants in 1..Secp256k1.FROST_MAX_PARTICIPANTS)
        require(threshold in 1..nParticipants)
        require(ids.size in threshold..nParticipants)
        require(tweakCache.size == Secp256k1.FROST_TWEAK_CACHE_SIZE)
        auxRand32?.let { require(it.size == 32) }
        memScoped {
            val nAggOtherNonce = aggOtherNonce?.let {
                val n = alloc<secp256k1_frost_aggnonce>()
                secp256k1_frost_aggnonce_parse(ctx, n.ptr, toNat(it)).requireSuccess("secp256k1_frost_aggnonce_parse() failed")
                n
            }
            val nPubshares = allocPubshares(pubshares)
            val nCache = allocFrostTweakCache(tweakCache)
            val nPsig = alloc<secp256k1_frost_partial_sig>()
            val nPubnonce = alloc<secp256k1_frost_pubnonce>()
            secp256k1_frost_deterministic_sign(
                ctx,
                nPsig.ptr,
                nPubnonce.ptr,
                toNat(secshare32),
                myId,
                nAggOtherNonce?.ptr,
                ids.toCValues(),
                nPubshares,
                ids.size.convert(),
                nParticipants.convert(),
                threshold.toUInt(),
                nCache.ptr,
                toNatAllowEmpty(msg),
                msg.size.convert(),
                auxRand32?.let { toNat(it) }
            ).requireSuccess("secp256k1_frost_deterministic_sign() failed")
            val psig = ByteArray(32)
            secp256k1_frost_partial_sig_serialize(ctx, toNat(psig), nPsig.ptr).requireSuccess("secp256k1_frost_partial_sig_serialize() failed")
            val pubnonce = allocArray<UByteVar>(Secp256k1.FROST_PUBLIC_NONCE_SIZE)
            secp256k1_frost_pubnonce_serialize(ctx, pubnonce, nPubnonce.ptr).requireSuccess("secp256k1_frost_pubnonce_serialize() failed")
            return Pair(psig, pubnonce.readBytes(Secp256k1.FROST_PUBLIC_NONCE_SIZE))
        }
    }

    override fun frostPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubshare: ByteArray, session: ByteArray, ids: UIntArray, signerIndex: Int): Int {
        require(psig.size == 32)
        require(pubnonce.size == Secp256k1.FROST_PUBLIC_NONCE_SIZE)
        require(pubshare.size == 33 || pubshare.size == 65)
        require(ids.isNotEmpty())
        require(signerIndex in ids.indices)
        memScoped {
            val nPsig = allocFrostPartialSig(psig)
            val nPubnonce = allocFrostPubnonce(pubnonce)
            val nPubshare = allocPublicKey(pubshare)
            val nSession = allocFrostSession(session)
            return secp256k1_frost_partial_sig_verify(ctx, nPsig.ptr, nPubnonce.ptr, nPubshare.ptr, nSession.ptr, ids.toCValues(), ids.size.convert(), signerIndex.convert())
        }
    }

    override fun frostPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray {
        require(psigs.isNotEmpty())
        psigs.forEach { require(it.size == 32) }
        memScoped {
            val nSession = allocFrostSession(session)
            val nPsigs = psigs.map { allocFrostPartialSig(it).ptr }
            val nErrorIndex = alloc<size_tVar>()
            val sig64 = ByteArray(64)
            secp256k1_frost_partial_sig_agg(ctx, toNat(sig64), nErrorIndex.ptr, nSession.ptr, nPsigs.toCValues(), psigs.size.convert()).requireSuccess("secp256k1_frost_partial_sig_agg() failed")
            return sig64
        }
    }

    private fun MemScope.flatHostpubkeys33(hostpubkeys33: Array<ByteArray>): CPointer<UByteVar> {
        require(hostpubkeys33.isNotEmpty())
        hostpubkeys33.forEach { require(it.size == 33) { "host public key must be 33 bytes" } }
        val flat = ByteArray(33 * hostpubkeys33.size)
        hostpubkeys33.forEachIndexed { i, pk -> pk.copyInto(flat, 33 * i) }
        return toNat(flat)
    }

    private fun chilldkgFault(code: Int, faultIndex: UInt): ChilldkgFault =
        ChilldkgFault(code, if (faultIndex == UInt.MAX_VALUE) null else faultIndex)

    private fun MemScope.allocChilldkgState1(state1: ByteArray): secp256k1_chilldkg_participant_state1 {
        state1.checkMagic(Secp256k1.CHILLDKG_PARTICIPANT_STATE1_MAGIC, "participant state1")
        val nState = alloc<secp256k1_chilldkg_participant_state1>()
        memcpy(nState.ptr, toNat(state1), Secp256k1.CHILLDKG_PARTICIPANT_STATE1_SIZE.toULong())
        return nState
    }

    private fun MemScope.allocChilldkgState2(state2: ByteArray): secp256k1_chilldkg_participant_state2 {
        state2.checkMagic(Secp256k1.CHILLDKG_PARTICIPANT_STATE2_MAGIC, "participant state2")
        val nState = alloc<secp256k1_chilldkg_participant_state2>()
        memcpy(nState.ptr, toNat(state2), Secp256k1.CHILLDKG_PARTICIPANT_STATE2_SIZE.toULong())
        return nState
    }

    private fun MemScope.allocChilldkgCoordinatorState(state: ByteArray): secp256k1_chilldkg_coordinator_state {
        state.checkMagic(Secp256k1.CHILLDKG_COORDINATOR_STATE_MAGIC, "coordinator state")
        val nState = alloc<secp256k1_chilldkg_coordinator_state>()
        memcpy(nState.ptr, toNat(state), Secp256k1.CHILLDKG_COORDINATOR_STATE_SIZE.toULong())
        return nState
    }

    private fun MemScope.allocChilldkgInvData(invData: ByteArray): secp256k1_chilldkg_participant_inv_data {
        invData.checkMagic(Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_MAGIC, "investigation data")
        val nInvData = alloc<secp256k1_chilldkg_participant_inv_data>()
        memcpy(nInvData.ptr, toNat(invData), Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE.toULong())
        return nInvData
    }

    override fun chilldkgHostpubkeyGen(hostseckey32: ByteArray): ByteArray {
        require(hostseckey32.size == 32)
        memScoped {
            val nHostpubkey = allocArray<UByteVar>(33)
            secp256k1_chilldkg_hostpubkey_gen(ctx, nHostpubkey, toNat(hostseckey32)).requireSuccess("secp256k1_chilldkg_hostpubkey_gen() failed")
            return nHostpubkey.readBytes(33)
        }
    }

    override fun chilldkgParamsHash(hostpubkeys33: Array<ByteArray>, threshold: Int): ByteArray {
        require(threshold in 1..hostpubkeys33.size)
        memScoped {
            val nHostpubkeys = flatHostpubkeys33(hostpubkeys33)
            val nHash = allocArray<UByteVar>(32)
            secp256k1_chilldkg_params_hash(ctx, nHash, nHostpubkeys, hostpubkeys33.size.convert(), threshold.toUInt()).requireSuccess("secp256k1_chilldkg_params_hash() failed")
            return nHash.readBytes(32)
        }
    }

    override fun chilldkgParticipantStep1(hostseckey32: ByteArray, hostpubkeys33: Array<ByteArray>, threshold: Int, random32: ByteArray): Pair<ByteArray, ByteArray> {
        require(hostseckey32.size == 32)
        require(random32.size == 32)
        require(threshold in 1..hostpubkeys33.size)
        require(hostpubkeys33.size <= Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
        memScoped {
            val nHostpubkeys = flatHostpubkeys33(hostpubkeys33)
            val pmsg1Len = secp256k1_chilldkg_participant_msg1_len(hostpubkeys33.size.convert(), threshold.toUInt()).toInt()
            val nState1 = alloc<secp256k1_chilldkg_participant_state1>()
            val nPmsg1 = allocArray<UByteVar>(pmsg1Len)
            secp256k1_chilldkg_participant_step1(ctx, nState1.ptr, nPmsg1, toNat(hostseckey32), nHostpubkeys, hostpubkeys33.size.convert(), threshold.toUInt(), toNat(random32)).requireSuccess("secp256k1_chilldkg_participant_step1() failed")
            return Pair(nState1.ptr.readBytes(Secp256k1.CHILLDKG_PARTICIPANT_STATE1_SIZE), nPmsg1.readBytes(pmsg1Len))
        }
    }

    override fun chilldkgCoordinatorStep1(pmsgs1: Array<ByteArray>, hostpubkeys33: Array<ByteArray>, threshold: Int): ChilldkgCoordinatorStep1Result {
        require(pmsgs1.isNotEmpty())
        require(pmsgs1.size == hostpubkeys33.size) { "participant messages count must match host public keys count" }
        require(threshold in 1..hostpubkeys33.size)
        require(hostpubkeys33.size <= Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
        memScoped {
            val nHostpubkeys = flatHostpubkeys33(hostpubkeys33)
            val nPmsgs1 = pmsgs1.map { toNat(it) }.toCValues()
            val cmsg1Len = secp256k1_chilldkg_coordinator_msg1_len(hostpubkeys33.size.convert(), threshold.toUInt()).toInt()
            val nState = alloc<secp256k1_chilldkg_coordinator_state>()
            val nCmsg1 = allocArray<UByteVar>(cmsg1Len)
            val nFaultIndex = alloc<UIntVar>()
            val fault = secp256k1_chilldkg_coordinator_step1(ctx, nState.ptr, nCmsg1, nFaultIndex.ptr, nPmsgs1, nHostpubkeys, hostpubkeys33.size.convert(), threshold.toUInt()).toInt()
            return ChilldkgCoordinatorStep1Result(chilldkgFault(fault, nFaultIndex.value), nState.ptr.readBytes(Secp256k1.CHILLDKG_COORDINATOR_STATE_SIZE), nCmsg1.readBytes(cmsg1Len))
        }
    }

    override fun chilldkgParticipantStep2(hostseckey32: ByteArray, state1: ByteArray, cmsg1: ByteArray, auxRand32: ByteArray): ChilldkgParticipantStep2Result {
        require(hostseckey32.size == 32)
        require(state1.size == Secp256k1.CHILLDKG_PARTICIPANT_STATE1_SIZE)
        require(auxRand32.size == 32)
        memScoped {
            val nState1 = allocChilldkgState1(state1)
            val nState2 = alloc<secp256k1_chilldkg_participant_state2>()
            val nSig64 = allocArray<UByteVar>(64)
            val nFaultIndex = alloc<UIntVar>()
            val nInvData = alloc<secp256k1_chilldkg_participant_inv_data>()
            val fault = secp256k1_chilldkg_participant_step2(ctx, nState2.ptr, nSig64, nFaultIndex.ptr, nInvData.ptr, nState1.ptr, toNat(hostseckey32), toNat(cmsg1), toNat(auxRand32)).toInt()
            val invData = if (fault == ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR) nInvData.ptr.readBytes(Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE) else null
            return ChilldkgParticipantStep2Result(chilldkgFault(fault, nFaultIndex.value), nState2.ptr.readBytes(Secp256k1.CHILLDKG_PARTICIPANT_STATE2_SIZE), nSig64.readBytes(64), invData)
        }
    }

    override fun chilldkgCoordinatorFinalize(state: ByteArray, pmsgs2: Array<ByteArray>, threshold: Int): ChilldkgCoordinatorFinalizeResult {
        require(state.size == Secp256k1.CHILLDKG_COORDINATOR_STATE_SIZE)
        require(pmsgs2.isNotEmpty())
        pmsgs2.forEach { require(it.size == 64) { "participant message must be 64 bytes" } }
        require(threshold in 1..pmsgs2.size)
        memScoped {
            val nState = allocChilldkgCoordinatorState(state)
            val nPmsgs2 = pmsgs2.map { toNat(it) }.toCValues()
            val n = pmsgs2.size
            val cmsg2Len = secp256k1_chilldkg_coordinator_msg2_len(n.convert()).toInt()
            val recoveryLen = secp256k1_chilldkg_recovery_data_len(n.convert(), threshold.toUInt()).toInt()
            val nCmsg2 = allocArray<UByteVar>(cmsg2Len)
            val nThreshPk = allocArray<UByteVar>(33)
            val nPubshares = allocArray<UByteVar>(33 * n)
            val nRecovery = allocArray<UByteVar>(recoveryLen)
            val nFaultIndex = alloc<UIntVar>()
            val fault = secp256k1_chilldkg_coordinator_finalize(ctx, nCmsg2, nThreshPk, nPubshares, nRecovery, nFaultIndex.ptr, nState.ptr, nPmsgs2).toInt()
            val pubshares = nPubshares.readBytes(33 * n).toList().chunked(33) { it.toByteArray() }.toTypedArray()
            return ChilldkgCoordinatorFinalizeResult(chilldkgFault(fault, nFaultIndex.value), nCmsg2.readBytes(cmsg2Len), nThreshPk.readBytes(33), pubshares, nRecovery.readBytes(recoveryLen))
        }
    }

    override fun chilldkgParticipantFinalize(state2: ByteArray, cmsg2: ByteArray, nParticipants: Int, threshold: Int): ChilldkgParticipantFinalizeResult {
        require(state2.size == Secp256k1.CHILLDKG_PARTICIPANT_STATE2_SIZE)
        require(nParticipants in 1..Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
        require(threshold in 1..nParticipants)
        require(cmsg2.size == 64 * nParticipants) { "invalid certificate size" }
        memScoped {
            val nState2 = allocChilldkgState2(state2)
            val recoveryLen = secp256k1_chilldkg_recovery_data_len(nParticipants.convert(), threshold.toUInt()).toInt()
            val nSecshare = allocArray<UByteVar>(32)
            val nThreshPk = allocArray<UByteVar>(33)
            val nPubshares = allocArray<UByteVar>(33 * nParticipants)
            val nRecovery = allocArray<UByteVar>(recoveryLen)
            val nFaultIndex = alloc<UIntVar>()
            val fault = secp256k1_chilldkg_participant_finalize(ctx, nSecshare, nThreshPk, nPubshares, nRecovery, nFaultIndex.ptr, nState2.ptr, toNat(cmsg2)).toInt()
            val pubshares = nPubshares.readBytes(33 * nParticipants).toList().chunked(33) { it.toByteArray() }.toTypedArray()
            return ChilldkgParticipantFinalizeResult(chilldkgFault(fault, nFaultIndex.value), nSecshare.readBytes(32), nThreshPk.readBytes(33), pubshares, nRecovery.readBytes(recoveryLen))
        }
    }

    private fun chilldkgRecover(hostseckey32: ByteArray?, recovery: ByteArray): ChilldkgRecoverResult {
        hostseckey32?.let { require(it.size == 32) }
        require(recovery.isNotEmpty())
        memScoped {
            val nSecshare = allocArray<UByteVar>(32)
            val nThreshPk = allocArray<UByteVar>(33)
            val nPubshares = allocArray<UByteVar>(33 * Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
            val nHostpubkeys = allocArray<UByteVar>(33 * Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
            val nParticipants = alloc<size_tVar>()
            val nThreshold = alloc<UIntVar>()
            val nFaultIndex = alloc<UIntVar>()
            nFaultIndex.value = UInt.MAX_VALUE
            val fault = if (hostseckey32 != null) {
                secp256k1_chilldkg_participant_recover(ctx, nSecshare, nThreshPk, nPubshares, nHostpubkeys, nParticipants.ptr, nThreshold.ptr, nFaultIndex.ptr, toNat(hostseckey32), toNat(recovery), recovery.size.convert()).toInt()
            } else {
                secp256k1_chilldkg_coordinator_recover(ctx, nThreshPk, nPubshares, nHostpubkeys, nParticipants.ptr, nThreshold.ptr, toNat(recovery), recovery.size.convert()).toInt()
            }
            val n = nParticipants.value.toInt().coerceAtMost(Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
            val pubshares = nPubshares.readBytes(33 * n).toList().chunked(33) { it.toByteArray() }.toTypedArray()
            val hostpubkeys = nHostpubkeys.readBytes(33 * n).toList().chunked(33) { it.toByteArray() }.toTypedArray()
            return ChilldkgRecoverResult(chilldkgFault(fault, nFaultIndex.value), hostseckey32?.let { nSecshare.readBytes(32) }, nThreshPk.readBytes(33), pubshares, hostpubkeys, n, nThreshold.value.toInt())
        }
    }

    override fun chilldkgParticipantRecover(hostseckey32: ByteArray, recovery: ByteArray): ChilldkgRecoverResult = chilldkgRecover(hostseckey32, recovery)

    override fun chilldkgCoordinatorRecover(recovery: ByteArray): ChilldkgRecoverResult = chilldkgRecover(null, recovery)

    override fun chilldkgRecoveryAckSign(hostseckey32: ByteArray, hostpubkeys33: Array<ByteArray>, threshold: Int, recovery: ByteArray, auxRand32: ByteArray): ByteArray {
        require(hostseckey32.size == 32)
        require(auxRand32.size == 32)
        require(threshold in 1..hostpubkeys33.size)
        require(recovery.isNotEmpty())
        memScoped {
            val nHostpubkeys = flatHostpubkeys33(hostpubkeys33)
            val nSig64 = allocArray<UByteVar>(64)
            secp256k1_chilldkg_recovery_ack_sign(ctx, nSig64, toNat(hostseckey32), nHostpubkeys, hostpubkeys33.size.convert(), threshold.toUInt(), toNat(recovery), recovery.size.convert(), toNat(auxRand32)).requireSuccess("secp256k1_chilldkg_recovery_ack_sign() failed")
            return nSig64.readBytes(64)
        }
    }

    override fun chilldkgRecoveryAcksVerify(hostpubkeys33: Array<ByteArray>, threshold: Int, recovery: ByteArray, ackSigs64: Array<ByteArray>): ChilldkgFault {
        require(threshold in 1..hostpubkeys33.size)
        require(recovery.isNotEmpty())
        require(ackSigs64.size == hostpubkeys33.size) { "acknowledgment signatures count must match host public keys count" }
        ackSigs64.forEach { require(it.size == 64) { "acknowledgment signature must be 64 bytes" } }
        memScoped {
            val nHostpubkeys = flatHostpubkeys33(hostpubkeys33)
            val nAcks = ackSigs64.map { toNat(it) }.toCValues()
            val nFaultIndex = alloc<UIntVar>()
            val fault = secp256k1_chilldkg_recovery_acks_verify(ctx, nFaultIndex.ptr, nHostpubkeys, hostpubkeys33.size.convert(), threshold.toUInt(), toNat(recovery), recovery.size.convert(), nAcks).toInt()
            return chilldkgFault(fault, nFaultIndex.value)
        }
    }

    override fun chilldkgCoordinatorInvestigate(pmsgs1: Array<ByteArray>, hostpubkeys33: Array<ByteArray>, threshold: Int, participantId: UInt): Pair<ChilldkgFault, ByteArray> {
        require(pmsgs1.isNotEmpty())
        require(pmsgs1.size == hostpubkeys33.size) { "participant messages count must match host public keys count" }
        require(threshold in 1..hostpubkeys33.size)
        require(hostpubkeys33.size <= Secp256k1.CHILLDKG_MAX_PARTICIPANTS)
        require(participantId < hostpubkeys33.size.toUInt())
        memScoped {
            val nHostpubkeys = flatHostpubkeys33(hostpubkeys33)
            val nPmsgs1 = pmsgs1.map { toNat(it) }.toCValues()
            val cinvLen = secp256k1_chilldkg_investigation_msg_len(hostpubkeys33.size.convert()).toInt()
            val nCinv = allocArray<UByteVar>(cinvLen)
            val nFaultIndex = alloc<UIntVar>()
            val fault = secp256k1_chilldkg_coordinator_investigate(ctx, nCinv, nFaultIndex.ptr, nPmsgs1, nHostpubkeys, hostpubkeys33.size.convert(), threshold.toUInt(), participantId).toInt()
            return Pair(chilldkgFault(fault, nFaultIndex.value), nCinv.readBytes(cinvLen))
        }
    }

    override fun chilldkgParticipantInvestigate(investigationData: ByteArray, cinv: ByteArray): ChilldkgFault {
        require(investigationData.size == Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE)
        require(cinv.isNotEmpty())
        memScoped {
            val nInvData = allocChilldkgInvData(investigationData)
            val nFaultIndex = alloc<UIntVar>()
            val fault = secp256k1_chilldkg_participant_investigate(ctx, nFaultIndex.ptr, nInvData.ptr, toNat(cinv)).toInt()
            return chilldkgFault(fault, nFaultIndex.value)
        }
    }

    private fun MemScope.allocIcebergShare(share: ByteArray): secp256k1_iceberg_share {
        val nShare = alloc<secp256k1_iceberg_share>()
        secp256k1_iceberg_share_parse(ctx, nShare.ptr, toNat(share), share.size.convert()).requireSuccess("secp256k1_iceberg_share_parse() failed")
        return nShare
    }

    private fun MemScope.allocIcebergCache(cache: ByteArray): secp256k1_iceberg_share_cache {
        cache.checkMagic(Secp256k1.ICEBERG_SHARE_CACHE_MAGIC, "share cache")
        val nCache = alloc<secp256k1_iceberg_share_cache>()
        memcpy(nCache.ptr, toNat(cache), Secp256k1.ICEBERG_SHARE_CACHE_SIZE.toULong())
        return nCache
    }

    private fun MemScope.allocIcebergPubshare(pubshare: ByteArray): secp256k1_iceberg_pubshare {
        val nPubshare = alloc<secp256k1_iceberg_pubshare>()
        secp256k1_iceberg_pubshare_parse(ctx, nPubshare.ptr, toNat(pubshare)).requireSuccess("secp256k1_iceberg_pubshare_parse() failed")
        return nPubshare
    }

    private fun MemScope.allocIcebergPubnonce(pubnonce: ByteArray): secp256k1_iceberg_pubnonce {
        val nPubnonce = alloc<secp256k1_iceberg_pubnonce>()
        secp256k1_iceberg_pubnonce_parse(ctx, nPubnonce.ptr, toNat(pubnonce)).requireSuccess("secp256k1_iceberg_pubnonce_parse() failed")
        return nPubnonce
    }

    private fun MemScope.allocIcebergPartialSig(psig: ByteArray): secp256k1_iceberg_partial_sig {
        val nPsig = alloc<secp256k1_iceberg_partial_sig>()
        secp256k1_iceberg_partial_sig_parse(ctx, nPsig.ptr, toNat(psig)).requireSuccess("secp256k1_iceberg_partial_sig_parse() failed")
        return nPsig
    }

    private fun MemScope.allocMusigKeyaggCache(keyaggCache: ByteArray): secp256k1_musig_keyagg_cache {
        keyaggCache.checkMagic(Secp256k1.MUSIG_KEYAGG_CACHE_MAGIC, "keyagg cache")
        val nKeyAggCache = alloc<secp256k1_musig_keyagg_cache>()
        memcpy(nKeyAggCache.ptr, toNat(keyaggCache), Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE.toULong())
        return nKeyAggCache
    }

    private fun MemScope.allocMusigAggnonce(aggnonce: ByteArray): secp256k1_musig_aggnonce {
        val nAggnonce = alloc<secp256k1_musig_aggnonce>()
        secp256k1_musig_aggnonce_parse(ctx, nAggnonce.ptr, toNat(aggnonce)).requireSuccess("secp256k1_musig_aggnonce_parse() failed")
        return nAggnonce
    }

    override fun icebergSharesGen(n: Int, t: Int, seed32: ByteArray): Array<ByteArray> {
        require(n in 1..Secp256k1.ICEBERG_MAX_PARTICIPANTS)
        require(t in 1..(n + 1) / 2) { "invalid threshold" }
        require(seed32.size == 32)
        memScoped {
            val nShares = allocArray<secp256k1_iceberg_share>(n)
            val nSharePtrs = (0 until n).map { nShares[it].ptr }.toCValues()
            secp256k1_iceberg_shares_gen(ctx, nSharePtrs, n.toUInt(), t.toUInt(), toNat(seed32)).requireSuccess("secp256k1_iceberg_shares_gen() failed")
            return (0 until n).map { i ->
                val out = allocArray<UByteVar>(Secp256k1.ICEBERG_SHARE_MAX_SIZE)
                val outLen = alloc<size_tVar>()
                outLen.value = Secp256k1.ICEBERG_SHARE_MAX_SIZE.convert()
                secp256k1_iceberg_share_serialize(ctx, out, outLen.ptr, nShares[i].ptr).requireSuccess("secp256k1_iceberg_share_serialize() failed")
                out.readBytes(outLen.value.toInt())
            }.toTypedArray()
        }
    }

    override fun icebergShareCacheCreate(share: ByteArray): ByteArray {
        memScoped {
            val nShare = allocIcebergShare(share)
            val nCache = alloc<secp256k1_iceberg_share_cache>()
            secp256k1_iceberg_share_cache_create(ctx, nCache.ptr, nShare.ptr).requireSuccess("secp256k1_iceberg_share_cache_create() failed")
            return nCache.ptr.readBytes(Secp256k1.ICEBERG_SHARE_CACHE_SIZE)
        }
    }

    override fun icebergPubshareGen(share: ByteArray, cache: ByteArray?): ByteArray {
        cache?.let { require(it.size == Secp256k1.ICEBERG_SHARE_CACHE_SIZE) }
        memScoped {
            val nShare = allocIcebergShare(share)
            val nCache = cache?.let { allocIcebergCache(it) }
            val nPubshare = alloc<secp256k1_iceberg_pubshare>()
            secp256k1_iceberg_pubshare_gen(ctx, nPubshare.ptr, nShare.ptr, nCache?.ptr).requireSuccess("secp256k1_iceberg_pubshare_gen() failed")
            val out = allocArray<UByteVar>(Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE)
            secp256k1_iceberg_pubshare_serialize(ctx, out, nPubshare.ptr).requireSuccess("secp256k1_iceberg_pubshare_serialize() failed")
            return out.readBytes(Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE)
        }
    }

    override fun icebergPubkeyAgg(pubshares: Array<ByteArray>, n: Int, t: Int): ByteArray {
        require(pubshares.isNotEmpty())
        pubshares.forEach { require(it.size == Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE) { "public share must be ${Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE} bytes" } }
        memScoped {
            val nPubshares = pubshares.map { allocIcebergPubshare(it).ptr }.toCValues()
            val nGroupPk = alloc<secp256k1_pubkey>()
            secp256k1_iceberg_pubkey_agg(ctx, nGroupPk.ptr, nPubshares, pubshares.size.convert(), n.toUInt(), t.toUInt()).requireSuccess("secp256k1_iceberg_pubkey_agg() failed")
            return serializePubkey(nGroupPk)
        }
    }

    override fun icebergNonceGen(share: ByteArray, cache: ByteArray?, sid32: ByteArray): ByteArray {
        require(sid32.size == 32)
        cache?.let { require(it.size == Secp256k1.ICEBERG_SHARE_CACHE_SIZE) }
        memScoped {
            val nShare = allocIcebergShare(share)
            val nCache = cache?.let { allocIcebergCache(it) }
            val nPubnonce = alloc<secp256k1_iceberg_pubnonce>()
            secp256k1_iceberg_nonce_gen(ctx, nPubnonce.ptr, nShare.ptr, nCache?.ptr, toNat(sid32)).requireSuccess("secp256k1_iceberg_nonce_gen() failed")
            val out = allocArray<UByteVar>(Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE)
            secp256k1_iceberg_pubnonce_serialize(ctx, out, nPubnonce.ptr).requireSuccess("secp256k1_iceberg_pubnonce_serialize() failed")
            return out.readBytes(Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE)
        }
    }

    override fun icebergNonceAgg(pubnonces: Array<ByteArray>, n: Int, t: Int, groupPubkey: ByteArray): ByteArray {
        require(pubnonces.isNotEmpty())
        pubnonces.forEach { require(it.size == Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE} bytes" } }
        memScoped {
            val nPubnonces = pubnonces.map { allocIcebergPubnonce(it).ptr }.toCValues()
            val nGroupPk = allocPublicKey(groupPubkey)
            val nMusigPubnonce = alloc<secp256k1_musig_pubnonce>()
            secp256k1_iceberg_nonce_agg(ctx, nMusigPubnonce.ptr, null, nPubnonces, pubnonces.size.convert(), n.toUInt(), t.toUInt(), nGroupPk.ptr).requireSuccess("secp256k1_iceberg_nonce_agg() failed")
            val out = allocArray<UByteVar>(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
            secp256k1_musig_pubnonce_serialize(ctx, out, nMusigPubnonce.ptr).requireSuccess("secp256k1_musig_pubnonce_serialize() failed")
            return out.readBytes(Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        }
    }

    override fun icebergKeyaggCheck(keyaggCache: ByteArray, pubkeys: Array<ByteArray>, groupPubkey: ByteArray): Boolean {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(pubkeys.isNotEmpty())
        memScoped {
            val nKeyAggCache = allocMusigKeyaggCache(keyaggCache)
            val nPubkeys = pubkeys.map { allocPublicKey(it).ptr }.toCValues()
            val nGroupPk = allocPublicKey(groupPubkey)
            return secp256k1_iceberg_keyagg_check(ctx, nKeyAggCache.ptr, nPubkeys, pubkeys.size.convert(), nGroupPk.ptr) == 1
        }
    }

    override fun icebergPartialSign(share: ByteArray, cache: ByteArray?, sid32: ByteArray, pubnonces: Array<ByteArray>, groupPubkey: ByteArray, keyaggCache: ByteArray, msg32: ByteArray, cosignerAggnonce: ByteArray): ByteArray {
        require(sid32.size == 32)
        require(msg32.size == 32)
        cache?.let { require(it.size == Secp256k1.ICEBERG_SHARE_CACHE_SIZE) }
        require(pubnonces.isNotEmpty())
        pubnonces.forEach { require(it.size == Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE} bytes" } }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(cosignerAggnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        memScoped {
            val nShare = allocIcebergShare(share)
            val nCache = cache?.let { allocIcebergCache(it) }
            val nPubnonces = pubnonces.map { allocIcebergPubnonce(it).ptr }.toCValues()
            val nGroupPk = allocPublicKey(groupPubkey)
            val nKeyAggCache = allocMusigKeyaggCache(keyaggCache)
            val nCosignerAggnonce = allocMusigAggnonce(cosignerAggnonce)
            val nPsig = alloc<secp256k1_iceberg_partial_sig>()
            secp256k1_iceberg_partial_sign(ctx, nPsig.ptr, nShare.ptr, nCache?.ptr, toNat(sid32), nPubnonces, pubnonces.size.convert(), nGroupPk.ptr, nKeyAggCache.ptr, toNat(msg32), nCosignerAggnonce.ptr).requireSuccess("secp256k1_iceberg_partial_sign() failed")
            val out = allocArray<UByteVar>(Secp256k1.ICEBERG_PARTIAL_SIG_SIZE)
            secp256k1_iceberg_partial_sig_serialize(ctx, out, nPsig.ptr).requireSuccess("secp256k1_iceberg_partial_sig_serialize() failed")
            return out.readBytes(Secp256k1.ICEBERG_PARTIAL_SIG_SIZE)
        }
    }

    override fun icebergPartialSigVerify(psig: ByteArray, pubshare: ByteArray, pubnonces: Array<ByteArray>, n: Int, t: Int, groupPubkey: ByteArray, keyaggCache: ByteArray, msg32: ByteArray, cosignerAggnonce: ByteArray): Int {
        require(psig.size == Secp256k1.ICEBERG_PARTIAL_SIG_SIZE)
        require(pubshare.size == Secp256k1.ICEBERG_PUBLIC_SHARE_SIZE)
        require(pubnonces.isNotEmpty())
        pubnonces.forEach { require(it.size == Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE) { "public nonce must be ${Secp256k1.ICEBERG_PUBLIC_NONCE_SIZE} bytes" } }
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(msg32.size == 32)
        require(cosignerAggnonce.size == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        memScoped {
            val nPsig = allocIcebergPartialSig(psig)
            val nPubshare = allocIcebergPubshare(pubshare)
            val nPubnonces = pubnonces.map { allocIcebergPubnonce(it).ptr }.toCValues()
            val nGroupPk = allocPublicKey(groupPubkey)
            val nKeyAggCache = allocMusigKeyaggCache(keyaggCache)
            val nCosignerAggnonce = allocMusigAggnonce(cosignerAggnonce)
            return secp256k1_iceberg_partial_sig_verify(ctx, nPsig.ptr, nPubshare.ptr, nPubnonces, pubnonces.size.convert(), n.toUInt(), t.toUInt(), nGroupPk.ptr, nKeyAggCache.ptr, toNat(msg32), nCosignerAggnonce.ptr)
        }
    }

    override fun icebergPartialSigAgg(psigs: Array<ByteArray>, n: Int, t: Int): ByteArray {
        require(psigs.isNotEmpty())
        psigs.forEach { require(it.size == Secp256k1.ICEBERG_PARTIAL_SIG_SIZE) { "signature share must be ${Secp256k1.ICEBERG_PARTIAL_SIG_SIZE} bytes" } }
        memScoped {
            val nPsigs = psigs.map { allocIcebergPartialSig(it).ptr }.toCValues()
            val nMusigPsig = alloc<secp256k1_musig_partial_sig>()
            secp256k1_iceberg_partial_sig_agg(ctx, nMusigPsig.ptr, nPsigs, psigs.size.convert(), n.toUInt(), t.toUInt()).requireSuccess("secp256k1_iceberg_partial_sig_agg() failed")
            val out = ByteArray(32)
            secp256k1_musig_partial_sig_serialize(ctx, toNat(out), nMusigPsig.ptr).requireSuccess("secp256k1_musig_partial_sig_serialize() failed")
            return out
        }
    }
}

internal actual fun getSecpk256k1(): Secp256k1 = Secp256k1Native
