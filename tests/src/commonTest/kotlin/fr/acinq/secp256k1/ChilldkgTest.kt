package fr.acinq.secp256k1

import kotlin.test.*

class ChilldkgTest {
    private val hostseckeys = listOf(
        Hex.decode("EEC1CB7D1B7254C5CAB0D9C61AB02E643D464A59FE6C96A7EFE871F07C5AEF54"),
        Hex.decode("487356F98AA7A0DC5E0E0F61B4CDA5D1A5B4C59F1B1E5A70E0D55C11FE0A99A1"),
        Hex.decode("0B1E9E1C5FDC56B9E90201C0C14DE3A9FF4A0DF7B839D18A29E9087F612480B7")
    )
    private val msg = ByteArray(32) { 0x42 }

    /** Run a complete 2-of-3 ChillDKG session and return each participant's finalization result. */
    private fun runDkg(): Triple<Array<ByteArray>, List<ChilldkgParticipantFinalizeResult>, ChilldkgCoordinatorFinalizeResult> {
        val n = hostseckeys.size
        val threshold = 2
        val hostpubkeys = hostseckeys.map { Secp256k1.chilldkgHostpubkeyGen(it) }.toTypedArray()
        hostpubkeys.forEach { assertEquals(33, it.size) }

        // All participants agree on the session parameters.
        val paramsHash = Secp256k1.chilldkgParamsHash(hostpubkeys, threshold)
        assertEquals(32, paramsHash.size)
        assertContentEquals(paramsHash, Secp256k1.chilldkgParamsHash(hostpubkeys, threshold))

        // 1. every participant runs step1 and sends pmsg1 to the coordinator
        val step1 = hostseckeys.mapIndexed { i, hostseckey ->
            Secp256k1.chilldkgParticipantStep1(hostseckey, hostpubkeys, threshold, ByteArray(32) { (0xD0 + i).toByte() })
        }
        // 2. the coordinator aggregates the pmsg1s and broadcasts cmsg1
        val coordinatorStep1 = Secp256k1.chilldkgCoordinatorStep1(step1.map { it.second }.toTypedArray(), hostpubkeys, threshold)
        assertTrue(coordinatorStep1.fault.isOk)
        assertNull(coordinatorStep1.fault.participantIndex)
        // 3. every participant verifies cmsg1 and sends its CertEq signature (pmsg2) to the coordinator
        val step2 = hostseckeys.mapIndexed { i, hostseckey ->
            val result = Secp256k1.chilldkgParticipantStep2(hostseckey, step1[i].first, coordinatorStep1.cmsg1, ByteArray(32) { (0xE0 + i).toByte() })
            assertTrue(result.fault.isOk)
            assertNull(result.investigationData)
            result
        }
        // 4. the coordinator collects the signatures into the certificate and broadcasts it
        val coordinatorFinalize = Secp256k1.chilldkgCoordinatorFinalize(coordinatorStep1.state, step2.map { it.sig64 }.toTypedArray(), threshold)
        assertTrue(coordinatorFinalize.fault.isOk)
        assertEquals(64 * n, coordinatorFinalize.cmsg2.size)
        assertEquals(n, coordinatorFinalize.pubshares.size)
        // 5. every participant verifies the certificate and computes its DKG output
        val participantResults = (0 until n).map { i ->
            val result = Secp256k1.chilldkgParticipantFinalize(step2[i].state2, coordinatorFinalize.cmsg2, n, threshold)
            assertTrue(result.fault.isOk)
            result
        }
        // all participants and the coordinator agree on the DKG output
        participantResults.forEach {
            assertContentEquals(coordinatorFinalize.thresholdPubkey, it.thresholdPubkey)
            coordinatorFinalize.pubshares.zip(it.pubshares).forEach { (a, b) -> assertContentEquals(a, b) }
            assertContentEquals(coordinatorFinalize.recovery, it.recovery)
        }
        // each public share is the public key of the corresponding secret share
        participantResults.forEachIndexed { i, result ->
            assertContentEquals(result.pubshares[i], Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(result.secshare)))
        }
        return Triple(hostpubkeys, participantResults, coordinatorFinalize)
    }

    @Test
    fun dkgSession() {
        runDkg()
    }

    @Test
    fun dkgOutputCanSignWithFrost() {
        val (_, participantResults, _) = runDkg()
        val thresholdPubkey = participantResults[0].thresholdPubkey
        val pubshares = participantResults[0].pubshares

        // Use the DKG output for a FROST signing session with 2 of the 3 participants.
        val tweakCache = Secp256k1.frostTweakCacheInit(thresholdPubkey)
        val tweakedPubkey = Secp256k1.frostTweakedPubkeyGet(tweakCache)
        val ids = uintArrayOf(0u, 2u)
        val nonces = ids.mapIndexed { i, id ->
            Secp256k1.frostNonceGen(ByteArray(32) { (0xA0 + i).toByte() }, participantResults[id.toInt()].secshare, pubshares[id.toInt()], tweakedPubkey, msg, null)
        }
        val secnonces = nonces.map { it.copyOfRange(0, Secp256k1.FROST_SECRET_NONCE_SIZE) }
        val pubnonces = nonces.map { it.copyOfRange(Secp256k1.FROST_SECRET_NONCE_SIZE, Secp256k1.FROST_SECRET_NONCE_SIZE + Secp256k1.FROST_PUBLIC_NONCE_SIZE) }
        val aggnonce = Secp256k1.frostNonceAgg(pubnonces.toTypedArray())
        val signerPubshares = ids.map { pubshares[it.toInt()] }.toTypedArray()
        val session = Secp256k1.frostSessionInit(aggnonce, ids, signerPubshares, 3, 2, tweakCache, msg)
        val psigs = ids.mapIndexed { i, id -> Secp256k1.frostSign(secnonces[i], participantResults[id.toInt()].secshare, session, ids, signerPubshares, id) }
        psigs.forEachIndexed { i, psig ->
            assertEquals(1, Secp256k1.frostPartialSigVerify(psig, pubnonces[i], signerPubshares[i], session, ids, i))
        }
        val sig = Secp256k1.frostPartialSigAgg(session, psigs.toTypedArray())
        assertTrue(Secp256k1.verifySchnorr(sig, msg, tweakedPubkey))
    }

    @Test
    fun recoverDkgOutput() {
        val (hostpubkeys, participantResults, coordinatorFinalize) = runDkg()
        val recovery = participantResults[0].recovery

        // Each participant can recover its secret share and the session's public data from the recovery data.
        hostseckeys.forEachIndexed { i, hostseckey ->
            val recovered = Secp256k1.chilldkgParticipantRecover(hostseckey, recovery)
            assertTrue(recovered.fault.isOk)
            assertContentEquals(participantResults[i].secshare, recovered.secshare)
            assertContentEquals(participantResults[i].thresholdPubkey, recovered.thresholdPubkey)
            participantResults[i].pubshares.zip(recovered.pubshares).forEach { (a, b) -> assertContentEquals(a, b) }
            hostpubkeys.zip(recovered.hostpubkeys).forEach { (a, b) -> assertContentEquals(a, b) }
            assertEquals(3, recovered.nParticipants)
            assertEquals(2, recovered.threshold)
        }
        // A host secret key that does not belong to the session cannot recover anything.
        val outsider = Secp256k1.chilldkgParticipantRecover(ByteArray(32) { 0x66 }, recovery)
        assertEquals(ChilldkgFault.INVALID_INPUT, outsider.fault.code)

        // The coordinator can recover the public data, but has no secret share.
        val coordinatorRecovered = Secp256k1.chilldkgCoordinatorRecover(recovery)
        assertTrue(coordinatorRecovered.fault.isOk)
        assertNull(coordinatorRecovered.secshare)
        assertContentEquals(coordinatorFinalize.thresholdPubkey, coordinatorRecovered.thresholdPubkey)
        coordinatorFinalize.pubshares.zip(coordinatorRecovered.pubshares).forEach { (a, b) -> assertContentEquals(a, b) }
        assertEquals(3, coordinatorRecovered.nParticipants)
        assertEquals(2, coordinatorRecovered.threshold)
    }

    @Test
    fun recoveryAcknowledgments() {
        val (hostpubkeys, participantResults, _) = runDkg()
        val recovery = participantResults[0].recovery
        val acks = hostseckeys.mapIndexed { i, hostseckey ->
            Secp256k1.chilldkgRecoveryAckSign(hostseckey, hostpubkeys, 2, recovery, ByteArray(32) { (0xF0 + i).toByte() })
        }.toTypedArray()
        assertTrue(Secp256k1.chilldkgRecoveryAcksVerify(hostpubkeys, 2, recovery, acks).isOk)
        // An ack signed with the wrong key is rejected and blames the corresponding participant.
        val badAcks = acks.copyOf()
        badAcks[1] = Secp256k1.chilldkgRecoveryAckSign(hostseckeys[2], hostpubkeys, 2, recovery, ByteArray(32) { 0xF1.toByte() })
        val fault = Secp256k1.chilldkgRecoveryAcksVerify(hostpubkeys, 2, recovery, badAcks)
        assertEquals(ChilldkgFault.FAULTY_PARTICIPANT, fault.code)
        assertEquals(1u, fault.participantIndex)
    }

    @Test
    fun invalidInputs() {
        val hostpubkeys = hostseckeys.map { Secp256k1.chilldkgHostpubkeyGen(it) }.toTypedArray()
        // all-zero randomness is rejected
        assertFails { Secp256k1.chilldkgParticipantStep1(hostseckeys[0], hostpubkeys, 2, ByteArray(32)) }
        // invalid host secret key is rejected
        assertFails { Secp256k1.chilldkgHostpubkeyGen(ByteArray(32)) }
        assertFails { Secp256k1.chilldkgParamsHash(hostpubkeys, 4) }
        // duplicate host public keys are rejected
        assertFails { Secp256k1.chilldkgParamsHash(arrayOf(hostpubkeys[0], hostpubkeys[0]), 2) }

        // Using the wrong host secret key in step2 is a fault, not an exception.
        val (state1, _) = Secp256k1.chilldkgParticipantStep1(hostseckeys[0], hostpubkeys, 2, ByteArray(32) { 0xD0.toByte() })
        val step1 = hostseckeys.mapIndexed { i, hostseckey -> Secp256k1.chilldkgParticipantStep1(hostseckey, hostpubkeys, 2, ByteArray(32) { (0xD0 + i).toByte() }) }
        val coordinatorStep1 = Secp256k1.chilldkgCoordinatorStep1(step1.map { it.second }.toTypedArray(), hostpubkeys, 2)
        val step2 = Secp256k1.chilldkgParticipantStep2(hostseckeys[1], state1, coordinatorStep1.cmsg1, ByteArray(32) { 0xE0.toByte() })
        assertEquals(ChilldkgFault.INVALID_INPUT, step2.fault.code)

        // A tampered coordinator message is detected.
        val tamperedCmsg1 = coordinatorStep1.cmsg1.copyOf()
        tamperedCmsg1[10] = (tamperedCmsg1[10] + 1).toByte()
        val step2Tampered = Secp256k1.chilldkgParticipantStep2(hostseckeys[0], step1[0].first, tamperedCmsg1, ByteArray(32) { 0xE0.toByte() })
        assertFalse(step2Tampered.fault.isOk)
    }

    /**
     * The chilldkg session states are opaque blobs that libsecp256k1 tags with a magic prefix and validates with
     * ARG_CHECK, whose default handler aborts the process. Passing a blob that has the right size but does not
     * hold a state object must raise an exception instead of killing the process: if any of these cases regresses,
     * this test does not fail, it takes the whole test run down with SIGABRT.
     */
    @Test
    fun rejectMalformedOpaqueBlobs() {
        val badState1 = ByteArray(Secp256k1.CHILLDKG_PARTICIPANT_STATE1_SIZE)
        val badState2 = ByteArray(Secp256k1.CHILLDKG_PARTICIPANT_STATE2_SIZE)
        val badCoordinatorState = ByteArray(Secp256k1.CHILLDKG_COORDINATOR_STATE_SIZE)
        val badInvData = ByteArray(Secp256k1.CHILLDKG_PARTICIPANT_INVESTIGATION_DATA_SIZE)

        assertFails { Secp256k1.chilldkgParticipantStep2(hostseckeys[0], badState1, ByteArray(100), ByteArray(32) { 0xE0.toByte() }) }
        assertFails { Secp256k1.chilldkgParticipantFinalize(badState2, ByteArray(64 * 3), 3, 2) }
        assertFails { Secp256k1.chilldkgCoordinatorFinalize(badCoordinatorState, arrayOf(ByteArray(64), ByteArray(64), ByteArray(64)), 2) }
        assertFails { Secp256k1.chilldkgParticipantInvestigate(badInvData, ByteArray(65 * 3)) }
    }
}
