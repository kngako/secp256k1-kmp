package fr.acinq.secp256k1

import kotlin.test.*

/**
 * FROST share refresh through the bindings (secp256k1-zkp frost_refresh): a refresh gives every recipient a new
 * share of the same key, so the old shares stop combining with the new. The C module's own tests carry the
 * protocol's properties; these check that the bindings carry every byte across, in both backends, and that the
 * frozen vectors from the zkp generator come out the same here.
 */
@OptIn(ExperimentalUnsignedTypes::class)
class FrostRefreshTest {
    // ---- The second zkp vector: a 3-of-4 at generation 1, participant 2 withheld.
    private val vThreshPk = Hex.decode("03a840a6c0ee255166f4c5824df07b8874767516e25eee41a6649e6d45b3e7d2ed")
    private val vHostseckeys = arrayOf("8cb83e17269f9291afe0a37a53e86f73d6e53c5056176e5bee143ab461c95891", "1c3afe8c6510c2ad5bca7d19878553f4591ab21747c4fc144fee04dd2fe1d157", "aab4317d2bb11468f8ccee50803e191a4ee05f68b9f1634fdeddbfccab34a8d3", "fe0a91bd92da8372f2c60e88c617e4030e7b03988807eb9fd9c9b2a1e63c943c").map { Hex.decode(it) }
    private val vSecshares = arrayOf("a75e91eb33b9fcc45fd1d975b3b0ab8321bb2932c32160bdddc9b6c94a0c5a2d", "1bc01ac404c3765e9665af0f4bb79fbab0e65bb6e3eff8c3888390d6f9bb1a95", "d33d62b9f99faa29ae118d2ac08330ddc84968286373eb831ca1aed903630c10", "cdd669cd124e9825a6d573c812135eeef28694b9e31bf8851a7f53b5c697ac1c").map { Hex.decode(it) }
    private val vPubshares = arrayOf("02933037a922b8c56655a61ad428072baff9b962c7cb932bfbcc16305ee410578a", "03585d5d23455e6f5265f39d5658d984090424e245854bbfbe6c478708d6972d6e", "030115ebde241cb486f4c27933f7f750e75d4520d7c8a09342cfa1445e89948f49", "0235487df407ac850cc9c27834bb31e0a165f643aa1eefe28187fe13bd766548fb").map { Hex.decode(it) }
    private val vRefreshId = Hex.decode("8291741ce9149584f171ac176506f9608789b80e3f8f535608b1f76d14e62dee")
    private val vRandoms = arrayOf("1e8622057589344b90c901516163ded1f83dacf456e73b6fc9ac41b412f13b5e", "9857b83dc02ae9c48603068f184ca3700fd9d0fc035e635809f18b4d0b7ec03c", "423fb3b03c7e6dace4751a66b83b82b8b83f7bffbb9f118dde0886b96012ec87").map { Hex.decode(it) }
    private val vAuxRands = arrayOf("3021d7739940e7d67513327dbe6322a5150b7d0b1a3cc7556caf1c33ef7add15", "88296e97e644073271cc49a583f21ff3fd7f3d5c050ef53efee0f6e3165efc7d", "9512eb284f732663230e7a6e3aaa76da74547723da5127877e0e9442cbddda58").map { Hex.decode(it) }
    private val vParamsHash = "44b15928430e68b4f047cfdeb80738ea51ac08326874c9845ba315848add0212"
    private val vPmsgs1 = arrayOf("025bc214ccccc4907ab20c60be014d9585023eb2491002b3a7423848effbbdc43d0328d29069856feffc1bed72f2d93e238f75efbca35bb9003bf90323ea00a273600237814a5d3be41f0b7aa7a457ae10140926745e5442fa8c7e50dc50575f8b6ecd6780987ee644a2b7aebbd292999682360e2e4b845046c21f7da2ea19135781bcf8212959f300d6fd0ecd9af541437742e8ade2cf1bbc258f36910bb746d95602cc452201d2852a206d40c121b7e3757868208cb45769778131c9882be6212dfe", "02e3981fa1d5af3605ba9a4676401d97e0ada5a7c0a2bbeb43f440053bdd5d0393037f30e7c51713db15af1d39dcd73524a56295731d81a5fee615e7c07a9bbdef1d03099c2ea26ea440ca481c7d7485f82669088b022975f9ab2cb05c70e95baaf92abe2f329152ba082e56d4044df80f281bf5bf68edfea1e9f936414388500253573c138345ed93a36671d3eaf7976982302670eb42275ae5c8ff9d2134e7fde14fc3c0d5593dd705e0ef024385ffa7764db012314a4ff9611fbc85b184b90ea20f", "038fb57db627c6d8c12b89747b7f46c5fa03f7a58fb069b5dd6a80756a2010632402d613fd7df9330c8e02f8d12cf9a978a063d994c4e97f6839b3d766831bd200ba03e8fe091110d2ba44554a95dd25e699d3c46c72456cad8b52fece44c9ca12aa382ac18f6bd983ccb4d03878ef956021c93f2673a964011fd10fb62bee4b22c5b878ae23ce9967024a272080cf26461208f28e160acf12ca75e487e1ec29f52bb3695067fa058292c702dc806c650fec3363dcd8b8021592c1485056cb374df153").map { Hex.decode(it) }
    private val vCmsg1 = "0258925aa455b8c2a951fc00bb57713fef72096d7da808cbc75d485524247fbdec02f17e3042d99c4bbc3de915aedd978062ca1aa1d3c0a34e9486e0170bae1b98270237814a5d3be41f0b7aa7a457ae10140926745e5442fa8c7e50dc50575f8b6ecd03099c2ea26ea440ca481c7d7485f82669088b022975f9ab2cb05c70e95baaf92a03e8fe091110d2ba44554a95dd25e699d3c46c72456cad8b52fece44c9ca12aa3850715a7c1282779ad5c84fd02705cc1c88654b3503a12bae03c7fb02de46598aace2d06e79fb7cada7c206bbfef30b7d46fe073562e135925ae3b04b889621c3f9565f5515dec2c85f1f85141c9ad7fac160b9cffa2fcb2676cd31ef0647801f"
    private val vNewSecshares = arrayOf("e7de2cf94a0d8a999feca099ac7600fb0b1a779145045d6eb34a8433538f6e77", "795097138882c5fae18836caed482ef6a02332b674ee1df111f8e080e28d43ca", "0000000000000000000000000000000000000000000000000000000000000000", "fb3c7b39762e072568ce690e154c0e9742f92bc339f8f20fa738c660ef6c010a").map { Hex.decode(it) }
    private val vNewTable = "029693cdb15d32a9b5b3603eab87acc1fe85d265f12d8c15d4fa3f03d2dd032376031895e349ed4c95f264c58c110a6c7f34074ccaf247fb4fa70dad5481c3d6b3de031d255cd561a70361cd9a614354d447b2c844396fff8770173c2649253e97451403b02abda791cc28c64a09ded2bb22b69363a473aebdb85e49bbe4a397ba593e10"
    private val vSigs = arrayOf("7396d5f740b751b2f173f4bc83a62d4e6b05eeca5491a98cddd96ad8e97215cce04af4a74a833b55b532d10436530efe8543c5eb2f4bd3b2c02444416e3b4e0e", "69d23a03501ec75a45bc60453102acbe8c9621f71aa957e8adfa6b2702e5a946a185f86ddb9a00954140e80fb009a2d48127c7f1ea9ef3834e98d9f030d57400", "1460c972fbc81c97d78aeec390864e626a8321cb682891cbd37b697467e50f5b66853a4b85083146eabf38ed5f4fd6f348bbcd6429a83c4ad3d18156b70be0cb").map { Hex.decode(it) }
    private val vIds = uintArrayOf(0u, 1u, 3u)

    private fun hostpubkeys(seckeys: List<ByteArray>): Array<ByteArray> = seckeys.map { Secp256k1.chilldkgHostpubkeyGen(it) }.toTypedArray()

    @Test
    fun zkpVectorsComeOutTheSameThroughTheBindings() {
        val params = Secp256k1.frostRefreshParamsSerialize(vThreshPk, hostpubkeys(vHostseckeys), vPubshares.toTypedArray(), 3, 1u, vIds, vRefreshId)
        assertEquals(vParamsHash, Hex.encode(Secp256k1.frostRefreshParamsHash(params)))

        val pmsgs1 = vIds.mapIndexed { i, id -> Secp256k1.frostRefreshParticipantStep1(vHostseckeys[id.toInt()], params, id, vRandoms[i]) }
        pmsgs1.forEachIndexed { i, pmsg -> assertContentEquals(vPmsgs1[i], pmsg) }

        val coordinated = Secp256k1.frostRefreshCoordinatorStep1(pmsgs1.toTypedArray(), params)
        assertTrue(coordinated.fault.isOk)
        val cmsg1 = assertNotNull(coordinated.cmsg1)
        assertEquals(vCmsg1, Hex.encode(cmsg1))

        val sigs = vIds.mapIndexed { i, id ->
            val result = Secp256k1.frostRefreshParticipantStep2(vHostseckeys[id.toInt()], vSecshares[id.toInt()], params, id, cmsg1, vAuxRands[i])
            assertTrue(result.fault.isOk, "$result")
            assertContentEquals(vNewSecshares[id.toInt()], result.newSecshare)
            assertEquals(vNewTable, Hex.encode(assertNotNull(result.newPubshares).reduce { a, b -> a + b }))
            assertContentEquals(vSigs[i], result.sig64)
            assertNotNull(result.sig64)
        }
        assertTrue(Secp256k1.frostRefreshCoordinatorFinalize(params, cmsg1, sigs.toTypedArray()).fault.isOk)
    }

    // ---- A dealt group, end to end. ----

    private class Run(
        val n: Int,
        val t: Int,
        val ids: UIntArray,
        val hostseckeys: List<ByteArray>,
        val threshPk: ByteArray,
        val secshares: Array<ByteArray>,
        val params: ByteArray,
        val cmsg1: ByteArray,
        val newSecshares: Map<UInt, ByteArray>,
        val newTable: Array<ByteArray>,
        val sigs: List<ByteArray>,
    )

    private fun seckey(tag: Int, i: Int): ByteArray = ByteArray(32) { (tag * 17 + i * 5 + it + 1).toByte() }

    /** A dealt group, with its keys in the 33-byte form the refresh takes. */
    private fun deal(n: Int, t: Int): Triple<ByteArray, Array<ByteArray>, Array<ByteArray>> {
        val (threshPk, secshares, pubshares) = Secp256k1.frostTrustedDealerKeygen(seckey(1, 0), n, t)
        return Triple(Secp256k1.pubKeyCompress(threshPk), secshares, pubshares.map { Secp256k1.pubKeyCompress(it) }.toTypedArray())
    }

    private fun refresh(n: Int, t: Int, ids: UIntArray): Run {
        val (threshPk, secshares, pubshares) = deal(n, t)
        val hostseckeys = List(n) { seckey(2, it) }
        val params = Secp256k1.frostRefreshParamsSerialize(threshPk, hostpubkeys(hostseckeys), pubshares, t, 0u, ids, seckey(3, 0))
        val pmsgs1 = ids.mapIndexed { i, id -> Secp256k1.frostRefreshParticipantStep1(hostseckeys[id.toInt()], params, id, seckey(4, i)) }
        val cmsg1 = assertNotNull(Secp256k1.frostRefreshCoordinatorStep1(pmsgs1.toTypedArray(), params).cmsg1)
        val results = ids.mapIndexed { i, id -> id to Secp256k1.frostRefreshParticipantStep2(hostseckeys[id.toInt()], secshares[id.toInt()], params, id, cmsg1, seckey(5, i)) }
        results.forEach { (_, r) -> assertTrue(r.fault.isOk, "$r") }
        val table = assertNotNull(results.first().second.newPubshares)
        results.forEach { (_, r) -> assertTrue(table.indices.all { k -> table[k].contentEquals(r.newPubshares!![k]) }) }
        return Run(n, t, ids, hostseckeys, threshPk, secshares, params, cmsg1, results.associate { (id, r) -> id to r.newSecshare!! }, table, results.map { it.second.sig64!! })
    }

    @Test
    fun refreshKeepsTheKeyAndMovesEveryShare() {
        val run = refresh(3, 2, uintArrayOf(0u, 1u, 2u))
        // The new table lies on a polynomial whose constant term is the unchanged key.
        assertTrue(Secp256k1.frostThresholdInfoValidate(run.threshPk, run.newTable, run.t))
        run.newSecshares.forEach { (id, share) ->
            assertFalse(share.contentEquals(run.secshares[id.toInt()]))
            assertContentEquals(run.newTable[id.toInt()], Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(share)))
        }
    }

    @Test
    fun certificateAndRecoveryWithAWithheldParticipant() {
        val run = refresh(4, 2, uintArrayOf(0u, 2u, 3u))
        val cmsg2 = assertNotNull(Secp256k1.frostRefreshCoordinatorFinalize(run.params, run.cmsg1, run.sigs.toTypedArray()).output)
        val recovery = assertNotNull(Secp256k1.frostRefreshParticipantFinalize(run.params, run.cmsg1, cmsg2).output)

        run.ids.forEach { id ->
            val recovered = Secp256k1.frostRefreshParticipantRecover(run.hostseckeys[id.toInt()], run.secshares[id.toInt()], recovery)
            assertTrue(recovered.fault.isOk)
            assertEquals(id, recovered.participantId)
            assertContentEquals(run.newSecshares[id], recovered.newSecshare)
        }
        // Participant 1 was dealt nothing, and cannot recover what it never had...
        val withheld = Secp256k1.frostRefreshParticipantRecover(run.hostseckeys[1], run.secshares[1], recovery)
        assertEquals(ChilldkgFault.INVALID_INPUT, withheld.fault.code)
        assertNull(withheld.newSecshare)
        // ...but anyone learns the table, and the parameters it was made under.
        val public = Secp256k1.frostRefreshPublicRecover(recovery)
        assertTrue(public.fault.isOk)
        assertContentEquals(run.params, public.params)
        assertTrue(run.newTable.indices.all { run.newTable[it].contentEquals(public.newPubshares!![it]) })

        val tampered = recovery.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertEquals(ChilldkgFault.INVALID_INPUT, Secp256k1.frostRefreshPublicRecover(tampered).fault.code)
    }

    @Test
    fun faultsLandOnTheRightParty() {
        val run = refresh(3, 2, uintArrayOf(0u, 1u, 2u))
        val badSigs = run.sigs.mapIndexed { i, s -> if (i == 2) s.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() } else s }
        val finalized = Secp256k1.frostRefreshCoordinatorFinalize(run.params, run.cmsg1, badSigs.toTypedArray())
        assertEquals(ChilldkgFault.FAULTY_PARTICIPANT, finalized.fault.code)
        assertEquals(2u, finalized.fault.participantIndex)
        assertNull(finalized.output)

        // A ciphertext the coordinator altered: the recipient cannot square it with the commitments.
        val altered = run.cmsg1.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val step2 = Secp256k1.frostRefreshParticipantStep2(run.hostseckeys[2], run.secshares[2], run.params, 2u, altered, seckey(6, 0))
        assertEquals(ChilldkgFault.UNKNOWN_FAULTY_PARTICIPANT_OR_COORDINATOR, step2.fault.code)
        assertNull(step2.newSecshare)

        // The wrong share is the caller's error.
        val wrong = Secp256k1.frostRefreshParticipantStep2(run.hostseckeys[0], run.secshares[1], run.params, 0u, run.cmsg1, seckey(6, 1))
        assertEquals(ChilldkgFault.INVALID_INPUT, wrong.fault.code)
    }

    @Test
    fun malformedInputIsRefusedBeforeItReachesNativeCode() {
        val run = refresh(3, 2, uintArrayOf(0u, 1u, 2u))
        assertFailsWith<IllegalArgumentException> {
            Secp256k1.frostRefreshParticipantStep2(run.hostseckeys[0], run.secshares[0], run.params, 0u, run.cmsg1.copyOf(run.cmsg1.size - 1), seckey(7, 0))
        }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostRefreshCoordinatorStep1(arrayOf(ByteArray(10)), run.params) }
        assertFailsWith<IllegalArgumentException> { Secp256k1.frostRefreshParamsHash(ByteArray(5)) }
        // Fewer recipients than the threshold is not a session.
        val (threshPk, _, pubshares) = deal(3, 3)
        assertFails { Secp256k1.frostRefreshParamsSerialize(threshPk, hostpubkeys(run.hostseckeys), pubshares, 3, 0u, uintArrayOf(0u, 1u), seckey(3, 0)) }
        // A host key that is not the participant's.
        assertFails { Secp256k1.frostRefreshParticipantStep1(run.hostseckeys[1], run.params, 0u, seckey(8, 0)) }
    }
}
