package fr.acinq.secp256k1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * The initial DKG driven one role at a time, through the step functions, against the fixed vectors that the
 * one-process [Secp256k1.confederationDkg] also reproduces. Every message crosses between roles as bytes.
 */
class ConfederationDistributedDkgTest {
    private val roles = 9

    private fun dealerSeed(role: Int): ByteArray = ByteArray(32).also {
        it[0] = 0xd0.toByte()
        it[31] = (role + 1).toByte()
    }

    private fun recoveryNonce(role: Int): ByteArray = ByteArray(32).also {
        it[0] = 0x42
        it[31] = (role + 1).toByte()
    }

    private fun group(role: Int): UInt = (role / 3).toUInt()
    private fun admin(role: Int): UInt = (role % 3).toUInt()

    private class Ceremony(
        val rpd: ByteArray,
        val sessionSeed: ByteArray,
        val sizes: ConfederationDkgMessageSizes,
        val dealings: List<ConfederationDkgDealing>,
        val broadcast: ByteArray,
    ) {
        val records: ByteArray get() = dealings.fold(ByteArray(0)) { acc, it -> acc + it.record }
        val ciphertexts: ByteArray get() = dealings.fold(ByteArray(0)) { acc, it -> acc + it.ciphertexts }
    }

    private fun dealAndBroadcast(): Ceremony {
        val vectors = confederationVectors()
        val rpd = Secp256k1.confederationRpdParse(vectors.confederationHex("rpd"))
        val sessionSeed = vectors.confederationHex("dkg_session_seed")
        val sizes = Secp256k1.confederationDkgMessageSizes(rpd)
        val dealings = (0 until roles).map { role ->
            Secp256k1.confederationDkgParticipantStep1(rpd, group(role), admin(role), confederationHostSecret(role), dealerSeed(role), sessionSeed)
        }
        val records = dealings.fold(ByteArray(0)) { acc, it -> acc + it.record }
        val ciphertexts = dealings.fold(ByteArray(0)) { acc, it -> acc + it.ciphertexts }
        val broadcast = assertIs<ConfederationStep.Done<ByteArray>>(Secp256k1.confederationDkgCoordinatorStep1(rpd, sessionSeed, records, ciphertexts)).value
        return Ceremony(rpd, sessionSeed, sizes, dealings, broadcast)
    }

    @Test
    fun messageSizesMatchTheVectors() {
        val vectors = confederationVectors()
        val rpd = Secp256k1.confederationRpdParse(vectors.confederationHex("rpd"))
        val sizes = Secp256k1.confederationDkgMessageSizes(rpd)
        assertEquals(ConfederationDkgMessageSizes(382, 288, 3798, 652, 320), sizes)
        assertEquals(vectors.confederationHex("dkg_fixed_record_0").size, sizes.record)
        assertEquals(vectors.confederationHex("dkg_fixed_broadcast").size, sizes.broadcast)
        assertEquals(vectors.confederationHex("dkg_fixed_authorizations").size, sizes.evidenceList)
    }

    @Test
    fun everyRoleRunsItsOwnStepsToTheVectorGenesis() {
        val vectors = confederationVectors()
        val ceremony = dealAndBroadcast()
        val rpd = ceremony.rpd

        // Step 1 reproduces the vectors, and a restart reproduces step 1.
        assertContentEquals(vectors.confederationHex("dkg_fixed_record_0"), ceremony.dealings[0].record)
        assertContentEquals(vectors.confederationHex("dkg_fixed_ciphertexts"), ceremony.ciphertexts)
        val again = Secp256k1.confederationDkgParticipantStep1(rpd, 0u, 0u, confederationHostSecret(0), dealerSeed(0), ceremony.sessionSeed)
        assertContentEquals(ceremony.dealings[0].record, again.record)
        assertContentEquals(ceremony.dealings[0].ciphertexts, again.ciphertexts)
        assertContentEquals(vectors.confederationHex("dkg_fixed_broadcast"), ceremony.broadcast)

        // Step 3: every role derives the KSD itself and authorizes the same genesis.
        val authorized = (0 until roles).map { role ->
            assertIs<ConfederationStep.Done<ConfederationDkgAuthorization>>(
                Secp256k1.confederationDkgParticipantStep2(rpd, group(role), admin(role), confederationHostSecret(role), ceremony.sessionSeed, ceremony.dealings[role].record, ceremony.broadcast)
            ).value
        }
        val transitionHash = vectors.confederationHex("dkg_fixed_transition_hash")
        authorized.forEach {
            assertContentEquals(transitionHash, it.transitionHash)
            assertContentEquals(vectors.confederationHex("dkg_fixed_ksd"), Secp256k1.confederationKsdSerialize(it.ksd, rpd))
        }
        val roleKsd = authorized[0].ksd
        val genesis = Secp256k1.confederationDkgGenesisPrepare(rpd, roleKsd)
        assertContentEquals(transitionHash, genesis.transitionHash)

        // Step 4: the authorization list.
        val authorizations = Secp256k1.confederationDkgEvidenceListWrite(rpd, Array(roles) { authorized[it].authorization })
        assertContentEquals(vectors.confederationHex("dkg_fixed_authorizations"), authorizations)
        assertNull(Secp256k1.confederationDkgVerifyEvidence(rpd, transitionHash, Secp256k1.CONFEDERATION_EVIDENCE_AUTHORIZE, authorizations))
        assertEquals(
            ConfederationFault(ConfederationFault.ROLE_OR_COORDINATOR, 0u),
            Secp256k1.confederationDkgVerifyEvidence(rpd, transitionHash, Secp256k1.CONFEDERATION_EVIDENCE_ACKNOWLEDGE, authorizations),
        )

        // Step 5: every role acknowledges.
        val acknowledgments = Array(roles) { role ->
            assertIs<ConfederationStep.Done<ByteArray>>(
                Secp256k1.confederationDkgParticipantAcknowledge(rpd, group(role), admin(role), confederationHostSecret(role), transitionHash, authorizations)
            ).value
        }
        val acknowledgmentList = Secp256k1.confederationDkgEvidenceListWrite(rpd, acknowledgments)
        assertContentEquals(vectors.confederationHex("dkg_fixed_acknowledgments"), acknowledgmentList)

        // Step 6: the coordinator's own KSD, and the certified genesis.
        val coordinatorKsd = Secp256k1.confederationDkgDeriveKsd(rpd, ceremony.broadcast)
        assertContentEquals(Secp256k1.confederationKsdSerialize(roleKsd, rpd), Secp256k1.confederationKsdSerialize(coordinatorKsd, rpd))
        val transition = assertIs<ConfederationStep.Done<ByteArray>>(
            Secp256k1.confederationDkgCoordinatorFinalize(rpd, coordinatorKsd, authorizations, acknowledgmentList)
        ).value
        assertContentEquals(vectors.confederationHex("dkg_fixed_transition"), Secp256k1.confederationTransitionSerialize(transition, null, null, rpd, coordinatorKsd))

        // Step 7: every role recomputes its share; the result is the one-process DKG's.
        val oneProcess = Secp256k1.confederationDkg(rpd, ceremony.sessionSeed, Array(roles) { confederationHostSecret(it) }, Array(roles) { dealerSeed(it) }, Array(roles) { recoveryNonce(it) })
        (0 until roles).forEach { role ->
            val result = Secp256k1.confederationDkgParticipantFinalize(transition, rpd, roleKsd, group(role), admin(role), confederationHostSecret(role), ceremony.dealings[role].record, ceremony.broadcast, recoveryNonce(role))
            assertContentEquals(oneProcess.shares[role], result.share)
            if (role == 0) assertContentEquals(vectors.confederationHex("dkg_fixed_recovery"), Secp256k1.confederationRecoverySerialize(result.recovery))
            assertEquals("ConfederationDkgShare(<secret>)", result.toString())
        }
    }

    @Test
    fun aBadDealerIsNamedByTheCoordinator() {
        val ceremony = dealAndBroadcast()
        val records = ceremony.records
        val recordLen = ceremony.sizes.record
        records[3 * recordLen + recordLen - 1] = (records[3 * recordLen + recordLen - 1].toInt() xor 1).toByte()
        val step = Secp256k1.confederationDkgCoordinatorStep1(ceremony.rpd, ceremony.sessionSeed, records, ceremony.ciphertexts)
        assertEquals(ConfederationFault(ConfederationFault.ROLE, 3u), assertIs<ConfederationStep.Faulted>(step).fault)
        assertNull(step.valueOrNull())
    }

    @Test
    fun aRoleRefusesABroadcastTheCoordinatorChanged() {
        val vectors = confederationVectors()
        val ceremony = dealAndBroadcast()
        val rpd = ceremony.rpd
        fun step2(role: Int, broadcast: ByteArray, sessionSeed: ByteArray = ceremony.sessionSeed, ownRecord: ByteArray = ceremony.dealings[role].record) =
            Secp256k1.confederationDkgParticipantStep2(rpd, group(role), admin(role), confederationHostSecret(role), sessionSeed, ownRecord, broadcast).faultOrNull()

        val otherSeed = ceremony.sessionSeed.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(ConfederationFault.COORDINATOR, step2(0, ceremony.broadcast, sessionSeed = otherSeed)?.code)
        assertEquals(ConfederationFault.COORDINATOR, step2(0, ceremony.broadcast, ownRecord = ceremony.dealings[1].record)?.code)

        val badRecord = vectors.confederationHex("dkg_fixed_broadcast_bad_record")
        assertEquals(ConfederationFault.COORDINATOR, step2(0, badRecord)?.code)
        assertEquals(ConfederationFault(ConfederationFault.UNKNOWN, 0u), step2(1, badRecord))
        val replaced = vectors.confederationHex("dkg_fixed_broadcast_replaced_own_record")
        assertEquals(ConfederationFault.COORDINATOR, step2(0, replaced)?.code)
        assertEquals(ConfederationFault.ROLE_OR_COORDINATOR, step2(1, replaced)?.code)
    }

    @Test
    fun anInvestigationNamesTheCoordinatorThatTamperedWithAShare() {
        val ceremony = dealAndBroadcast()
        val rpd = ceremony.rpd
        val tampered = ceremony.broadcast.copyOf().also {
            val index = it.size - roles * 32 + 31
            it[index] = (it[index].toInt() xor 1).toByte()
        }
        val step = Secp256k1.confederationDkgParticipantStep2(rpd, 0u, 0u, confederationHostSecret(0), ceremony.sessionSeed, ceremony.dealings[0].record, tampered)
        assertEquals(ConfederationFault.ROLE_OR_COORDINATOR, step.faultOrNull()?.code)

        val responses = (0 until roles).fold(ByteArray(0)) { acc, role ->
            acc + Secp256k1.confederationDkgInvestigationResponse(rpd, ceremony.sessionSeed, group(role), admin(role), ceremony.dealings[role].ciphertexts)
        }
        assertEquals(roles * ceremony.sizes.investigationResponse, responses.size)
        assertEquals(ConfederationFault.COORDINATOR, Secp256k1.confederationDkgInvestigate(rpd, 0u, 0u, confederationHostSecret(0), tampered, responses).code)
        assertEquals(ConfederationFault(ConfederationFault.NONE, null), Secp256k1.confederationDkgInvestigate(rpd, 0u, 0u, confederationHostSecret(0), ceremony.broadcast, responses))
    }

    @Test
    fun evidenceThatDoesNotVerifyNamesItsRole() {
        val ceremony = dealAndBroadcast()
        val rpd = ceremony.rpd
        val authorized = (0 until roles).map { role ->
            Secp256k1.confederationDkgParticipantStep2(rpd, group(role), admin(role), confederationHostSecret(role), ceremony.sessionSeed, ceremony.dealings[role].record, ceremony.broadcast).valueOrNull()!!
        }
        val transitionHash = authorized[0].transitionHash
        val authorizations = Secp256k1.confederationDkgEvidenceListWrite(rpd, Array(roles) { authorized[it].authorization })

        val flipped = authorizations.copyOf().also { it[4 + 72 * 7 + 8 + 3] = (it[4 + 72 * 7 + 8 + 3].toInt() xor 1).toByte() }
        assertEquals(ConfederationFault(ConfederationFault.ROLE_OR_COORDINATOR, 7u), Secp256k1.confederationDkgVerifyEvidence(rpd, transitionHash, Secp256k1.CONFEDERATION_EVIDENCE_AUTHORIZE, flipped))
        assertEquals(
            ConfederationFault(ConfederationFault.ROLE_OR_COORDINATOR, 7u),
            Secp256k1.confederationDkgParticipantAcknowledge(rpd, 0u, 0u, confederationHostSecret(0), transitionHash, flipped).faultOrNull(),
        )
        assertEquals(ConfederationFault.COORDINATOR, Secp256k1.confederationDkgVerifyEvidence(rpd, transitionHash, Secp256k1.CONFEDERATION_EVIDENCE_AUTHORIZE, authorizations.copyOf(authorizations.size - 72))?.code)

        val acknowledgments = Secp256k1.confederationDkgEvidenceListWrite(rpd, Array(roles) { role ->
            Secp256k1.confederationDkgParticipantAcknowledge(rpd, group(role), admin(role), confederationHostSecret(role), transitionHash, authorizations).valueOrNull()!!
        })
        val badAcknowledgments = acknowledgments.copyOf().also { it[4 + 72 * 4 + 8 + 20] = (it[4 + 72 * 4 + 8 + 20].toInt() xor 1).toByte() }
        val ksd = Secp256k1.confederationDkgDeriveKsd(rpd, ceremony.broadcast)
        assertEquals(ConfederationFault(ConfederationFault.ROLE, 4u), Secp256k1.confederationDkgCoordinatorFinalize(rpd, ksd, authorizations, badAcknowledgments).faultOrNull())
    }

    @Test
    fun malformedLocalInputRaises() {
        val ceremony = dealAndBroadcast()
        val rpd = ceremony.rpd
        // Another role's host key is this caller's mistake, not a fault of another party.
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationDkgParticipantStep1(rpd, 0u, 0u, confederationHostSecret(1), dealerSeed(0), ceremony.sessionSeed)
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationDkgParticipantStep1(rpd, 0u, 0u, ByteArray(31), dealerSeed(0), ceremony.sessionSeed)
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationDkgParticipantStep1(rpd, Secp256k1.CONFEDERATION_MAX_GROUPS.toUInt(), 0u, confederationHostSecret(0), dealerSeed(0), ceremony.sessionSeed)
        }
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.confederationDkgVerifyEvidence(rpd, ByteArray(32), 2, ByteArray(0))
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationDkgEvidenceListWrite(rpd, Array(roles - 1) { ByteArray(64) })
        }
        assertFailsWith<Secp256k1Exception> {
            Secp256k1.confederationDkgMessageSizes(ByteArray(Secp256k1.CONFEDERATION_RPD_SIZE))
        }
    }
}
