package fr.acinq.secp256k1

import kotlinx.serialization.json.*
import kotlin.test.*

/**
 * BIP 445 FROST signing known-answer vectors, from the reference implementation at
 * https://github.com/siv2r/bip-frost-signing (python/vectors).
 *
 * These are the only cross-implementation checks the FROST bindings have: every other FROST test in
 * this repo is a round trip against the same C library it is testing, which cannot catch a value
 * that is self-consistently wrong. The same vectors drive the C module's own suite through
 * src/modules/frost/vectors.h, so a disagreement here is a marshalling fault in these bindings
 * rather than in libsecp256k1.
 *
 * Note in particular the nonce generation cases: the reference distinguishes an empty message from
 * an omitted one, which is the exact hazard that broke the native bindings once already (07f7dcc).
 */
@OptIn(ExperimentalUnsignedTypes::class)
class FrostVectorsTest {
    /**
     * A partial signature that is not smaller than the curve order cannot be represented at all:
     * frost_partial_sig_parse rejects it, so these bindings raise where the BIP 445 reference merely
     * returns false. Both reject the signature; they differ only in how. The submodule's own vector
     * generator (tools/test_vectors_frost_generate.py) skips such cases for exactly this reason, so
     * rather than dropping them the tests below assert the rejection they actually produce.
     */
    private val curveOrder = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

    private fun outOfRange(psig: ByteArray): Boolean {
        if (psig.size != 32) return false
        for (i in 0 until 32) {
            val a = psig[i].toInt() and 0xff
            val b = curveOrder[i].toInt() and 0xff
            if (a != b) return a > b
        }
        return true // exactly the order
    }

    /** Test vectors carry the two nonce scalars only; libsecp256k1 prefixes its 4-byte magic. */
    private fun secnonceFromVector(hex: String): ByteArray {
        val scalars = Hex.decode(hex)
        require(scalars.size == 64) { "secret nonce from test vector should be 64 bytes" }
        return Hex.decode("5CCFB999") + scalars
    }

    private fun JsonElement.hex(name: String): ByteArray = Hex.decode(jsonObject[name]!!.jsonPrimitive.content)
    private fun JsonElement.hexOrNull(name: String): ByteArray? = jsonObject[name]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) }
    private fun JsonElement.int(name: String): Int = jsonObject[name]!!.jsonPrimitive.int
    private fun JsonElement.ints(name: String): List<Int> = jsonObject[name]!!.jsonArray.map { it.jsonPrimitive.int }
    /** pubshare_indices is null where the vector exercises the optional-pubshares path. */
    private fun JsonElement.intsOrNull(name: String): List<Int>? = jsonObject[name]?.takeIf { it !is JsonNull }?.jsonArray?.map { it.jsonPrimitive.int }
    private fun JsonElement.ids(name: String): UIntArray = jsonObject[name]!!.jsonArray.map { it.jsonPrimitive.int.toUInt() }.toUIntArray()
    private fun JsonElement.strs(name: String): List<ByteArray> = jsonObject[name]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
    private fun JsonElement.bools(name: String): List<Boolean> = jsonObject[name]!!.jsonArray.map { it.jsonPrimitive.boolean }
    private fun JsonElement.cases(name: String): List<JsonElement> = jsonObject[name]?.jsonArray?.toList() ?: emptyList()

    @Test
    fun nonceGenVectors() {
        val tests = readResourceAsJson("frost/nonce_gen_vectors.json")
        var n = 0
        tests.cases("valid_tests").forEach { t ->
            // msg is nullable and may also be present but empty: those are different derivations.
            val out = Secp256k1.frostNonceGen(
                t.hex("rand"),
                t.hexOrNull("secshare"),
                t.hexOrNull("pubshare"),
                t.hexOrNull("thresh_pk_xonly"),
                t.hexOrNull("msg"),
                t.hexOrNull("extra_in"),
            )
            val expected = t.jsonObject["expected"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
            // frostNonceGen returns the 68-byte secnonce (magic included) then the 66-byte pubnonce.
            assertContentEquals(expected[0], out.copyOfRange(4, 4 + 64), "tc${t.int("tc_id")} secnonce")
            assertContentEquals(expected[1], out.copyOfRange(68, out.size), "tc${t.int("tc_id")} pubnonce")
            n++
        }
        assertEquals(5, n)
    }

    @Test
    fun nonceAggVectors() {
        val tests = readResourceAsJson("frost/nonce_agg_vectors.json")
        val pubnonces = tests.strs("pubnonces")
        tests.cases("valid_tests").forEach { t ->
            val agg = Secp256k1.frostNonceAgg(t.ints("pubnonce_indices").map { pubnonces[it] }.toTypedArray())
            assertContentEquals(t.hex("expected"), agg, "tc${t.int("tc_id")}")
        }
        tests.cases("error_tests").forEach { t ->
            // Every error case here is an invalid pubnonce contribution, which must not be accepted.
            assertFails("tc${t.int("tc_id")}") {
                Secp256k1.frostNonceAgg(t.ints("pubnonce_indices").map { pubnonces[it] }.toTypedArray())
            }
        }
    }

    @Test
    fun signVerifyVectors() {
        val tests = readResourceAsJson("frost/sign_verify_vectors.json")
        var valid = 0; var signErr = 0; var verifyFail = 0; var verifyErr = 0
        tests.jsonObject["test_groups"]!!.jsonArray.forEach { g ->
            val threshPk = g.hex("thresh_pk")
            val pubshares = g.strs("pubshares")
            val pubnonces = g.strs("pubnonces")
            val secshares = g.strs("secshares")
            val secnonces = g.jsonObject["secnonces"]!!.jsonArray.map { secnonceFromVector(it.jsonPrimitive.content) }
            val n = g.int("n"); val t = g.int("t")

            g.cases("valid_tests").forEach { c ->
                val ids = c.ids("ids")
                val signerPubshares = c.intsOrNull("pubshare_indices")?.map { pubshares[it] }?.toTypedArray()
                val session = Secp256k1.frostSessionInit(c.hex("aggnonce"), ids, signerPubshares, n, t, Secp256k1.frostTweakCacheInit(threshPk), c.hex("msg"))
                val psig = Secp256k1.frostSign(secnonces[c.int("secnonce_index")], secshares[c.int("secshare_index")], session, ids, signerPubshares, c.int("my_id").toUInt())
                assertContentEquals(c.hex("expected"), psig, "${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}")
                valid++
            }

            g.cases("sign_error_tests").forEach { c ->
                assertFails("${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}") {
                    val ids = c.ids("ids")
                    val signerPubshares = c.intsOrNull("pubshare_indices")?.map { pubshares[it] }?.toTypedArray()
                    val session = Secp256k1.frostSessionInit(c.hex("aggnonce"), ids, signerPubshares, n, t, Secp256k1.frostTweakCacheInit(threshPk), c.hex("msg"))
                    Secp256k1.frostSign(secnonces[c.int("secnonce_index")], secshares[c.int("secshare_index")], session, ids, signerPubshares, c.int("my_id").toUInt())
                }
                signErr++
            }

            // The verify cases give no aggnonce: it is aggregated from the listed public nonces.
            g.cases("verify_fail_tests").forEach { c ->
                val ids = c.ids("ids")
                val signerPubshares = c.ints("pubshare_indices").map { pubshares[it] }.toTypedArray()
                val signerPubnonces = c.ints("pubnonce_indices").map { pubnonces[it] }
                val aggnonce = Secp256k1.frostNonceAgg(signerPubnonces.toTypedArray())
                val session = Secp256k1.frostSessionInit(aggnonce, ids, signerPubshares, n, t, Secp256k1.frostTweakCacheInit(threshPk), c.hex("msg"))
                val i = c.int("signer_index")
                val psig = c.hex("psig")
                val label = "${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}"
                if (outOfRange(psig)) {
                    // Unrepresentable rather than merely wrong: rejected at parse time.
                    assertFails(label) { Secp256k1.frostPartialSigVerify(psig, signerPubnonces[i], signerPubshares[i], session, ids, i) }
                } else {
                    // A well-formed but wrong partial signature: verification must return 0, not raise.
                    assertEquals(0, Secp256k1.frostPartialSigVerify(psig, signerPubnonces[i], signerPubshares[i], session, ids, i), label)
                }
                verifyFail++
            }

            g.cases("verify_error_tests").forEach { c ->
                // Malformed input rather than a wrong signature: these must be rejected outright.
                assertFails("${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}") {
                    val ids = c.ids("ids")
                    val signerPubshares = c.ints("pubshare_indices").map { pubshares[it] }.toTypedArray()
                    val signerPubnonces = c.ints("pubnonce_indices").map { pubnonces[it] }
                    val aggnonce = Secp256k1.frostNonceAgg(signerPubnonces.toTypedArray())
                    val session = Secp256k1.frostSessionInit(aggnonce, ids, signerPubshares, n, t, Secp256k1.frostTweakCacheInit(threshPk), c.hex("msg"))
                    val i = c.int("signer_index")
                    Secp256k1.frostPartialSigVerify(c.hex("psig"), signerPubnonces[i], signerPubshares[i], session, ids, i)
                }
                verifyErr++
            }
        }
        assertEquals(29, valid); assertEquals(52, signErr); assertEquals(12, verifyFail); assertEquals(8, verifyErr)
    }

    /** Applies the vector's tweaks to a fresh cache, in order; each is either x-only or plain EC. */
    private fun tweakedCache(threshPk: ByteArray, tweaks: List<ByteArray>, indices: List<Int>, isXonly: List<Boolean>): ByteArray {
        val cache = Secp256k1.frostTweakCacheInit(threshPk)
        // The cache is updated IN PLACE; the return value is the tweaked key, not a new cache.
        indices.forEachIndexed { k, ti ->
            if (isXonly[k]) Secp256k1.frostPubkeyXonlyTweakAdd(cache, tweaks[ti]) else Secp256k1.frostPubkeyEcTweakAdd(cache, tweaks[ti])
        }
        return cache
    }

    @Test
    fun tweakVectors() {
        val tests = readResourceAsJson("frost/tweak_vectors.json")
        var valid = 0; var errors = 0
        tests.jsonObject["test_groups"]!!.jsonArray.forEach { g ->
            val threshPk = g.hex("thresh_pk")
            val pubshares = g.strs("pubshares")
            val secshares = g.strs("secshares")
            val tweaks = g.strs("tweaks")
            val secnonces = g.jsonObject["secnonces"]!!.jsonArray.map { secnonceFromVector(it.jsonPrimitive.content) }
            val n = g.int("n"); val t = g.int("t")

            g.cases("valid_tests").forEach { c ->
                val ids = c.ids("ids")
                val signerPubshares = c.intsOrNull("pubshare_indices")?.map { pubshares[it] }?.toTypedArray()
                val cache = tweakedCache(threshPk, tweaks, c.ints("tweak_indices"), c.bools("is_xonly"))
                val session = Secp256k1.frostSessionInit(c.hex("aggnonce"), ids, signerPubshares, n, t, cache, c.hex("msg"))
                val psig = Secp256k1.frostSign(secnonces[c.int("secnonce_index")], secshares[c.int("secshare_index")], session, ids, signerPubshares, c.int("my_id").toUInt())
                assertContentEquals(c.hex("expected"), psig, "${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}")
                valid++
            }

            g.cases("error_tests").forEach { c ->
                // Applying the tweak is itself the failing step in most of these.
                assertFails("${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}") {
                    val ids = c.ids("ids")
                    val signerPubshares = c.intsOrNull("pubshare_indices")?.map { pubshares[it] }?.toTypedArray()
                    val cache = tweakedCache(threshPk, tweaks, c.ints("tweak_indices"), c.bools("is_xonly"))
                    val session = Secp256k1.frostSessionInit(c.hex("aggnonce"), ids, signerPubshares, n, t, cache, c.hex("msg"))
                    Secp256k1.frostSign(secnonces[c.int("secnonce_index")], secshares[c.int("secshare_index")], session, ids, signerPubshares, c.int("my_id").toUInt())
                }
                errors++
            }
        }
        assertEquals(28, valid); assertEquals(16, errors)
    }

    @Test
    fun sigAggVectors() {
        val tests = readResourceAsJson("frost/sig_agg_vectors.json")
        var valid = 0; var errors = 0
        tests.jsonObject["test_groups"]!!.jsonArray.forEach { g ->
            val threshPk = g.hex("thresh_pk")
            val pubshares = g.strs("pubshares")
            val tweaks = g.strs("tweaks")
            val n = g.int("n"); val t = g.int("t")

            g.cases("valid_tests").forEach { c ->
                val ids = c.ids("ids")
                val signerPubshares = c.intsOrNull("pubshare_indices")?.map { pubshares[it] }?.toTypedArray()
                val cache = tweakedCache(threshPk, tweaks, c.ints("tweak_indices"), c.bools("is_xonly"))
                val session = Secp256k1.frostSessionInit(c.hex("aggnonce"), ids, signerPubshares, n, t, cache, c.hex("msg"))
                val sig = Secp256k1.frostPartialSigAgg(session, c.strs("psigs").toTypedArray())
                assertContentEquals(c.hex("expected"), sig, "${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}")
                valid++
            }

            g.cases("error_tests").forEach { c ->
                assertFails("${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}") {
                    val ids = c.ids("ids")
                    val signerPubshares = c.intsOrNull("pubshare_indices")?.map { pubshares[it] }?.toTypedArray()
                    val cache = tweakedCache(threshPk, tweaks, c.ints("tweak_indices"), c.bools("is_xonly"))
                    val session = Secp256k1.frostSessionInit(c.hex("aggnonce"), ids, signerPubshares, n, t, cache, c.hex("msg"))
                    Secp256k1.frostPartialSigAgg(session, c.strs("psigs").toTypedArray())
                }
                errors++
            }
        }
        assertEquals(18, valid); assertEquals(8, errors)
    }

    @Test
    fun deterministicSignVectors() {
        val tests = readResourceAsJson("frost/det_sign_vectors.json")
        var valid = 0; var errors = 0
        tests.jsonObject["test_groups"]!!.jsonArray.forEach { g ->
            val threshPk = g.hex("thresh_pk")
            val pubshares = g.strs("pubshares")
            val secshares = g.strs("secshares")
            val n = g.int("n"); val t = g.int("t")

            g.cases("valid_tests").forEach { c ->
                val ids = c.ids("ids")
                val signerPubshares = c.intsOrNull("pubshare_indices")?.map { pubshares[it] }?.toTypedArray()
                // Tweaks are given inline here rather than by index into a group-level table.
                val caseTweaks = c.strs("tweaks")
                val cache = tweakedCache(threshPk, caseTweaks, caseTweaks.indices.toList(), c.bools("is_xonly"))
                val (psig, pubnonce) = Secp256k1.frostDeterministicSign(
                    secshares[c.int("secshare_index")], c.int("my_id").toUInt(), c.hexOrNull("aggothernonce"),
                    ids, signerPubshares, n, t, cache, c.hex("msg"), c.hexOrNull("aux_rand"),
                )
                val expected = c.jsonObject["expected"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
                val label = "${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}"
                assertContentEquals(expected[0], pubnonce, "$label pubnonce")
                assertContentEquals(expected[1], psig, "$label psig")
                valid++
            }

            g.cases("error_tests").forEach { c ->
                assertFails("${g.jsonObject["tg_id"]} tc${c.int("tc_id")}: ${c.jsonObject["comment"]}") {
                    val ids = c.ids("ids")
                    val signerPubshares = c.intsOrNull("pubshare_indices")?.map { pubshares[it] }?.toTypedArray()
                    val caseTweaks = c.strs("tweaks")
                    val cache = tweakedCache(threshPk, caseTweaks, caseTweaks.indices.toList(), c.bools("is_xonly"))
                    Secp256k1.frostDeterministicSign(
                        secshares[c.int("secshare_index")], c.int("my_id").toUInt(), c.hexOrNull("aggothernonce"),
                        ids, signerPubshares, n, t, cache, c.hex("msg"), c.hexOrNull("aux_rand"),
                    )
                }
                errors++
            }
        }
        assertEquals(37, valid); assertEquals(48, errors)
    }
}
