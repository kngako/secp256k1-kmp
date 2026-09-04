package fr.acinq.secp256k1

import kotlinx.serialization.json.*
import kotlin.test.*

/**
 * ChillDKG known-answer vectors, from the bip-frost-dkg reference implementation at
 * https://github.com/BlockstreamResearch/bip-frost-dkg (vectors/).
 *
 * Same purpose as [FrostVectorsTest]: every other ChillDKG test in this repo is a round trip
 * against the same C library it is testing, which cannot catch a self-consistently wrong value.
 * These vectors come from an implementation sharing no code with libsecp256k1, and are the same
 * ones the C module's own suite runs via src/modules/chilldkg/vectors.h.
 *
 * The schema differs from the BIP 445 files: camelCase throughout, and the protocol is stateful,
 * so groups supply the inputs (hostseckey, random, auxRand) needed to re-derive a session rather
 * than the opaque state blobs themselves, whose layout is libsecp256k1's and not the reference's.
 */
class ChilldkgVectorsTest {
    private fun JsonElement.hex(name: String): ByteArray = Hex.decode(jsonObject[name]!!.jsonPrimitive.content)
    private fun JsonElement.int(name: String): Int = jsonObject[name]!!.jsonPrimitive.int
    private fun JsonElement.strs(name: String): List<ByteArray> = jsonObject[name]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
    private fun JsonElement.cases(name: String): List<JsonElement> = jsonObject[name]?.jsonArray?.toList() ?: emptyList()
    /**
     * assertContentEquals compares list ELEMENTS with equals(), which for ByteArray is reference
     * identity, so it passes vacuously on nothing and fails on everything here. Compare contents.
     */
    private fun assertArraysEqual(expected: List<ByteArray>, actual: List<ByteArray>, label: String) {
        assertEquals(expected.size, actual.size, "$label size")
        expected.forEachIndexed { i, e -> assertContentEquals(e, actual[i], "$label[$i]") }
    }

    private fun JsonElement.label(): String = "tc${int("tcId")}: ${jsonObject["comment"]?.jsonPrimitive?.content}"

    @Test
    fun hostpubkeyGenVectors() {
        val tests = readResourceAsJson("chilldkg/hostpubkey_gen_vectors.json")
        var n = 0
        tests.cases("validTestCases").forEach { c ->
            assertContentEquals(c.hex("expectedHostpubkey"), Secp256k1.chilldkgHostpubkeyGen(c.hex("hostseckey")), c.label())
            n++
        }
        tests.cases("errorTestCases").forEach { c ->
            // A wrong length, an out-of-range key and a zeroed key must all be rejected.
            assertFails(c.label()) { Secp256k1.chilldkgHostpubkeyGen(c.hex("hostseckey")) }
            n++
        }
        assertEquals(tests.int("totalTests"), n)
    }

    @Test
    fun paramsHashVectors() {
        val tests = readResourceAsJson("chilldkg/params_hash_vectors.json")
        var n = 0
        tests.cases("validTestCases").forEach { c ->
            val p = c.jsonObject["params"]!!
            assertContentEquals(c.hex("expectedParamsHash"), Secp256k1.chilldkgParamsHash(p.strs("hostpubkeys").toTypedArray(), p.int("t")), c.label())
            n++
        }
        tests.cases("errorTestCases").forEach { c ->
            val p = c.jsonObject["params"]!!
            assertFails(c.label()) { Secp256k1.chilldkgParamsHash(p.strs("hostpubkeys").toTypedArray(), p.int("t")) }
            n++
        }
        assertEquals(tests.int("totalTests"), n)
    }

    /**
     * ChillDKG rejects in two different ways, and which one applies is not a property of the vector:
     * caller-side argument problems raise, while protocol faults are a normal return carrying a fault
     * code. An error vector is satisfied by either, so long as the step does not succeed.
     */
    private fun assertRejected(label: String, block: () -> ChilldkgFault) {
        val fault = try {
            block()
        } catch (e: Throwable) {
            return
        }
        assertFalse(fault.isOk, "$label: expected rejection, got fault=$fault")
    }

    @Test
    fun participantStep1Vectors() {
        val tests = readResourceAsJson("chilldkg/participant_step1_vectors.json")
        var n = 0
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { g ->
            g.cases("validTestCases").forEach { c ->
                val p = c.jsonObject["params"]!!
                // The state blob is libsecp256k1's own layout, so only the wire message is comparable.
                val (_, pmsg1) = Secp256k1.chilldkgParticipantStep1(c.hex("hostseckey"), p.strs("hostpubkeys").toTypedArray(), p.int("t"), c.hex("random"))
                assertContentEquals(c.hex("expectedPmsg1"), pmsg1, c.label())
                n++
            }
            g.cases("errorTestCases").forEach { c ->
                val p = c.jsonObject["params"]!!
                // Step 1 has no fault return: everything it rejects, it raises on.
                assertFails(c.label()) {
                    Secp256k1.chilldkgParticipantStep1(c.hex("hostseckey"), p.strs("hostpubkeys").toTypedArray(), p.int("t"), c.hex("random"))
                }
                n++
            }
        }
        assertEquals(tests.int("totalTests"), n)
    }

    @Test
    fun coordinatorStep1Vectors() {
        val tests = readResourceAsJson("chilldkg/coordinator_step1_vectors.json")
        var n = 0
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { g ->
            val pool = g.strs("pmsg1Pool")
            g.cases("validTestCases").forEach { c ->
                val p = c.jsonObject["params"]!!
                val pmsgs = c.jsonObject["pmsg1Indices"]!!.jsonArray.map { pool[it.jsonPrimitive.int] }.toTypedArray()
                val res = Secp256k1.chilldkgCoordinatorStep1(pmsgs, p.strs("hostpubkeys").toTypedArray(), p.int("t"))
                assertTrue(res.fault.isOk, "${c.label()}: fault=${res.fault}")
                assertContentEquals(c.hex("expectedCmsg1"), res.cmsg1, c.label())
                n++
            }
            g.cases("errorTestCases").forEach { c ->
                val p = c.jsonObject["params"]!!
                assertRejected(c.label()) {
                    val pmsgs = c.jsonObject["pmsg1Indices"]!!.jsonArray.map { pool[it.jsonPrimitive.int] }.toTypedArray()
                    Secp256k1.chilldkgCoordinatorStep1(pmsgs, p.strs("hostpubkeys").toTypedArray(), p.int("t")).fault
                }
                n++
            }
        }
        assertEquals(tests.int("totalTests"), n)
    }

    /** Re-derives this participant's state1, which the vectors cannot carry: its layout is libsecp256k1's. */
    private fun state1For(g: JsonElement): ByteArray {
        val p = g.jsonObject["params"]!!
        return Secp256k1.chilldkgParticipantStep1(g.hex("hostseckey"), p.strs("hostpubkeys").toTypedArray(), p.int("t"), g.hex("random")).first
    }

    private fun assertDkgOutput(expected: JsonElement, secshare: ByteArray?, threshPk: ByteArray, pubshares: Array<ByteArray>, label: String) {
        val o = expected.jsonObject["dkgOutput"]!!
        o.jsonObject["secshare"]?.jsonPrimitive?.contentOrNull?.let { assertContentEquals(Hex.decode(it), secshare, "$label secshare") }
        assertContentEquals(o.hex("threshPk"), threshPk, "$label threshPk")
        assertArraysEqual(o.strs("pubshares"), pubshares.toList(), "$label pubshares")
    }

    @Test
    fun participantStep2Vectors() {
        val tests = readResourceAsJson("chilldkg/participant_step2_vectors.json")
        var n = 0
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { g ->
            val hostseckey = g.hex("hostseckey")
            g.cases("validTestCases").forEach { c ->
                val res = Secp256k1.chilldkgParticipantStep2(hostseckey, state1For(g), c.hex("cmsg1"), g.hex("auxRand"))
                assertTrue(res.fault.isOk, "${c.label()}: fault=${res.fault}")
                assertContentEquals(c.hex("expectedPmsg2"), res.sig64, c.label())
                n++
            }
            g.cases("errorTestCases").forEach { c ->
                // Error cases override auxRand, so it is taken from the case when present.
                // Cases may override auxRand or the host secret key; state1 stays the group's, so an
                // overridden key is a genuine mismatch against the one step1 ran with.
                val auxRand = c.jsonObject["auxRand"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) } ?: g.hex("auxRand")
                val key = c.jsonObject["hostseckey"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) } ?: hostseckey
                assertRejected(c.label()) { Secp256k1.chilldkgParticipantStep2(key, state1For(g), c.hex("cmsg1"), auxRand).fault }
                n++
            }
        }
        assertEquals(tests.int("totalTests"), n)
    }

    @Test
    fun participantFinalizeVectors() {
        val tests = readResourceAsJson("chilldkg/participant_finalize_vectors.json")
        var n = 0
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { g ->
            val p = g.jsonObject["params"]!!
            val nParticipants = p.strs("hostpubkeys").size
            val t = p.int("t")
            val state2 = Secp256k1.chilldkgParticipantStep2(g.hex("hostseckey"), state1For(g), g.hex("cmsg1"), g.hex("auxRand")).state2
            g.cases("validTestCases").forEach { c ->
                val res = Secp256k1.chilldkgParticipantFinalize(state2, c.hex("cmsg2"), nParticipants, t)
                assertTrue(res.fault.isOk, "${c.label()}: fault=${res.fault}")
                assertDkgOutput(c.jsonObject["expectedOutput"]!!, res.secshare, res.thresholdPubkey, res.pubshares, c.label())
                assertContentEquals(c.jsonObject["expectedOutput"]!!.hex("recoveryData"), res.recovery, "${c.label()} recovery")
                n++
            }
            g.cases("errorTestCases").forEach { c ->
                assertRejected(c.label()) { Secp256k1.chilldkgParticipantFinalize(state2, c.hex("cmsg2"), nParticipants, t).fault }
                n++
            }
        }
        assertEquals(tests.int("totalTests"), n)
    }

    @Test
    fun coordinatorFinalizeVectors() {
        val tests = readResourceAsJson("chilldkg/coordinator_finalize_vectors.json")
        var n = 0
        tests.jsonObject["testGroups"]!!.jsonArray.forEach { g ->
            val p = g.jsonObject["params"]!!
            val t = p.int("t")
            val pool = g.strs("pmsg2Pool")
            val state = Secp256k1.chilldkgCoordinatorStep1(g.strs("pmsgs1").toTypedArray(), p.strs("hostpubkeys").toTypedArray(), t).state
            g.cases("validTestCases").forEach { c ->
                val pmsgs2 = c.jsonObject["pmsg2Indices"]!!.jsonArray.map { pool[it.jsonPrimitive.int] }.toTypedArray()
                val res = Secp256k1.chilldkgCoordinatorFinalize(state, pmsgs2, t)
                assertTrue(res.fault.isOk, "${c.label()}: fault=${res.fault}")
                assertDkgOutput(c.jsonObject["expectedOutput"]!!, null, res.thresholdPubkey, res.pubshares, c.label())
                assertContentEquals(c.jsonObject["expectedOutput"]!!.hex("recoveryData"), res.recovery, "${c.label()} recovery")
                n++
            }
            g.cases("errorTestCases").forEach { c ->
                assertRejected(c.label()) {
                    val pmsgs2 = c.jsonObject["pmsg2Indices"]!!.jsonArray.map { pool[it.jsonPrimitive.int] }.toTypedArray()
                    Secp256k1.chilldkgCoordinatorFinalize(state, pmsgs2, t).fault
                }
                n++
            }
        }
        assertEquals(tests.int("totalTests"), n)
    }

    @Test
    fun recoverVectors() {
        val tests = readResourceAsJson("chilldkg/recover_vectors.json")
        var n = 0
        // A null host secret key is the coordinator, who has no secret share.
        fun recover(c: JsonElement): ChilldkgRecoverResult {
            val hostseckey = c.jsonObject["hostseckey"]?.jsonPrimitive?.contentOrNull
            return if (hostseckey == null) Secp256k1.chilldkgCoordinatorRecover(c.hex("recoveryData"))
            else Secp256k1.chilldkgParticipantRecover(Hex.decode(hostseckey), c.hex("recoveryData"))
        }
        tests.cases("validTestCases").forEach { c ->
            val res = recover(c)
            assertTrue(res.fault.isOk, "${c.label()}: fault=${res.fault}")
            assertDkgOutput(c.jsonObject["expectedOutput"]!!, res.secshare, res.thresholdPubkey, res.pubshares, c.label())
            val p = c.jsonObject["expectedOutput"]!!.jsonObject["params"]!!
            assertArraysEqual(p.strs("hostpubkeys"), res.hostpubkeys.toList(), "${c.label()} hostpubkeys")
            assertEquals(p.int("t"), res.threshold, "${c.label()} threshold")
            n++
        }
        tests.cases("errorTestCases").forEach { c ->
            assertRejected(c.label()) { recover(c).fault }
            n++
        }
        assertEquals(tests.int("totalTests"), n)
    }

    @Test
    fun investigateVectors() {
        var n = 0
        val coord = readResourceAsJson("chilldkg/coordinator_investigate_vectors.json")
        coord.jsonObject["testGroups"]!!.jsonArray.forEach { g ->
            val p = g.jsonObject["params"]!!
            val hostpubkeys = p.strs("hostpubkeys").toTypedArray()
            g.cases("validTestCases").forEach { c ->
                // One investigation message per participant, in participant order.
                val expected = c.strs("expectedCinvMsgs")
                expected.indices.forEach { i ->
                    val (fault, cinv) = Secp256k1.chilldkgCoordinatorInvestigate(g.strs("pmsgs1").toTypedArray(), hostpubkeys, p.int("t"), i.toUInt())
                    assertTrue(fault.isOk, "${c.label()} participant $i: fault=$fault")
                    assertContentEquals(expected[i], cinv, "${c.label()} participant $i")
                }
                n++
            }
        }
        assertEquals(coord.int("totalTests"), n)

        var m = 0
        val part = readResourceAsJson("chilldkg/participant_investigate_vectors.json")
        part.jsonObject["testGroups"]!!.jsonArray.forEach { g ->
            val pool = g.strs("cmsg1Pool")
            g.cases("errorTestCases").forEach { c ->
                // Investigation runs on the data step2 produced when it could not attribute the fault itself.
                val step2 = Secp256k1.chilldkgParticipantStep2(g.hex("hostseckey"), state1For(g), pool[c.int("cmsg1Index")], g.hex("auxRand"))
                val invData = step2.investigationData
                assertNotNull(invData, "${c.label()}: expected investigation data, fault=${step2.fault}")
                val fault = Secp256k1.chilldkgParticipantInvestigate(invData, c.hex("cinvMsg"))
                assertFalse(fault.isOk, "${c.label()}: expected a blamed party")
                m++
            }
        }
        assertEquals(part.int("totalTests"), m)
    }
}
