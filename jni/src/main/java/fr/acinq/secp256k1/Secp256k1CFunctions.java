package fr.acinq.secp256k1;

public class Secp256k1CFunctions {
    /**
     * All flags' lower 8 bits indicate what they're for. Do not use directly.
     */
    public static int SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1);
    public static final int SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0);
    public static final int SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1);

    /**
     * The higher bits contain the actual data. Do not use directly.
     */
    public static final int SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8);
    public static final int SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9);
    public static final int SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8);

    /**
     * Flags to pass to secp256k1_context_create, secp256k1_context_preallocated_size, and
     * secp256k1_context_preallocated_create.
     */
    public static final int SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY);
    public static final int SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN);
    public static final int SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT);

    /**
     * Flag to pass to secp256k1_ec_pubkey_serialize.
     */
    public static final int SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION);
    public static final int SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION);

    /**
     * A musig2 public nonce is simply two elliptic curve points.
     */
    public static final int SECP256K1_MUSIG_PUBLIC_NONCE_SIZE = 66;

    /**
     * A musig2 private nonce is basically two scalars, but should be treated as an opaque blob.
     */
    public static final int SECP256K1_MUSIG_SECRET_NONCE_SIZE = 132;

    /**
     * When aggregating public keys, we cache information in an opaque blob (must not be interpreted).
     */
    public static final int SECP256K1_MUSIG_KEYAGG_CACHE_SIZE = 197;

    /**
     * When creating partial signatures and aggregating them, session data is kept in an opaque blob (must not be interpreted).
     */
    public static final int SECP256K1_MUSIG_SESSION_SIZE = 133;

    /**
     * A frost public nonce is simply two elliptic curve points.
     */
    public static final int SECP256K1_FROST_PUBLIC_NONCE_SIZE = 66;

    /**
     * A frost private nonce is basically two scalars, but should be treated as an opaque blob.
     */
    public static final int SECP256K1_FROST_SECRET_NONCE_SIZE = 68;

    /**
     * The frost tweak cache holds the threshold public key and the state of public key tweaking (must not be interpreted).
     */
    public static final int SECP256K1_FROST_TWEAK_CACHE_SIZE = 165;

    /**
     * When creating frost partial signatures and aggregating them, session data is kept in an opaque blob (must not be interpreted).
     */
    public static final int SECP256K1_FROST_SESSION_SIZE = 137;

    /**
     * Session state of a chilldkg participant after the first step (must not be interpreted).
     */
    public static final int SECP256K1_CHILLDKG_PARTICIPANT_STATE1_SIZE = 4306;

    /**
     * Session state of a chilldkg participant after the second step (must not be interpreted, must be kept secret).
     */
    public static final int SECP256K1_CHILLDKG_PARTICIPANT_STATE2_SIZE = 21073;

    /**
     * Investigation data of a chilldkg participant (must not be interpreted, must be kept secret).
     */
    public static final int SECP256K1_CHILLDKG_PARTICIPANT_INV_DATA_SIZE = 4205;

    /**
     * Session state of a chilldkg coordinator after the first step (must not be interpreted).
     */
    public static final int SECP256K1_CHILLDKG_COORDINATOR_STATE_SIZE = 21041;

    /**
     * Largest size of a serialized iceberg share.
     */
    public static final int SECP256K1_ICEBERG_SHARE_MAX_SIZE = 4036;

    /**
     * Size of the opaque iceberg share cache blob (has no serialized form).
     */
    public static final int SECP256K1_ICEBERG_SHARE_CACHE_SIZE = 4040;

    /**
     * Size of a serialized iceberg public key share.
     */
    public static final int SECP256K1_ICEBERG_PUBLIC_SHARE_SIZE = 34;

    /**
     * Size of a serialized iceberg nonce contribution.
     */
    public static final int SECP256K1_ICEBERG_PUBLIC_NONCE_SIZE = 67;

    /**
     * Size of a serialized iceberg signature share.
     */
    public static final int SECP256K1_ICEBERG_PARTIAL_SIG_SIZE = 33;

    public static native long secp256k1_context_create(int flags);

    public static native void secp256k1_context_destroy(long ctx);

    public static native int secp256k1_ec_seckey_verify(long ctx, byte[] seckey);

    public static native byte[] secp256k1_ec_pubkey_parse(long ctx, byte[] pubkey);

    public static native byte[] secp256k1_ec_pubkey_create(long ctx, byte[] seckey);

    public static native byte[] secp256k1_ecdsa_sign(long ctx, byte[] msg, byte[] seckey, byte[] ndata);

    public static native int secp256k1_ecdsa_verify(long ctx, byte[] sig, byte[] msg, byte[] pubkey);

    public static native int secp256k1_ecdsa_signature_normalize(long ctx, byte[] sigin, byte[] sigout);

    public static native byte[] secp256k1_ec_seckey_negate(long ctx, byte[] privkey);

    public static native byte[] secp256k1_ec_pubkey_negate(long ctx, byte[] pubkey);

    public static native byte[] secp256k1_ec_seckey_tweak_add(long ctx, byte[] seckey, byte[] tweak);

    public static native byte[] secp256k1_ec_pubkey_tweak_add(long ctx, byte[] pubkey, byte[] tweak);

    public static native byte[] secp256k1_ec_seckey_tweak_mul(long ctx, byte[] seckey, byte[] tweak);

    public static native byte[] secp256k1_ec_pubkey_tweak_mul(long ctx, byte[] pubkey, byte[] tweak);

    public static native byte[] secp256k1_ec_pubkey_combine(long ctx, byte[][] pubkeys);

    public static native byte[] secp256k1_ecdh(long ctx, byte[] seckey, byte[] pubkey);

    public static native byte[] secp256k1_ecdsa_recover(long ctx, byte[] sig, byte[] msg32, int recid);

    public static native byte[] secp256k1_compact_to_der(long ctx, byte[] sig);

    public static native byte[] secp256k1_der_to_compact(long ctx, byte[] sig);

    public static native byte[] secp256k1_schnorrsig_sign(long ctx, byte[] msg, byte[] seckey, byte[] aux_rand32);

    public static native int secp256k1_schnorrsig_verify(long ctx, byte[] sig, byte[] msg, byte[] pubkey);

    public static native byte[] secp256k1_musig_nonce_gen(long ctx, byte[] session_rand32, byte[] seckey, byte[] pubkey, byte[] msg32, byte[] keyagg_cache, byte[] extra_input32);

    public static native byte[] secp256k1_musig_nonce_gen_counter(long ctx, long nonrepeating_cnt, byte[] seckey, byte[] msg32, byte[] keyagg_cache, byte[] extra_input32);

    public static native byte[] secp256k1_musig_nonce_agg(long ctx, byte[][] nonces);

    public static native byte[] secp256k1_musig_pubkey_agg(long ctx, byte[][] pubkeys, byte[] keyagg_cache);

    public static native byte[] secp256k1_musig_pubkey_ec_tweak_add(long ctx, byte[] keyagg_cache, byte[] tweak32);

    public static native byte[] secp256k1_musig_pubkey_xonly_tweak_add(long ctx, byte[] keyagg_cache, byte[] tweak32);

    public static native byte[] secp256k1_musig_nonce_process(long ctx, byte[] aggnonce, byte[] msg32, byte[] keyagg_cache);

    public static native byte[] secp256k1_musig_partial_sign(long ctx, byte[] secnonce, byte[] privkey, byte[] keyagg_cache, byte[] session);

    public static native int secp256k1_musig_partial_sig_verify(long ctx, byte[] psig, byte[] pubnonce, byte[] pubkey, byte[] keyagg_cache, byte[] session);

    public static native byte[] secp256k1_musig_partial_sig_agg(long ctx, byte[] session, byte[][] psigs);

    public static native byte[] secp256k1_musig_pubkey_get(long ctx, byte[] keyagg_cache);

    public static native int secp256k1_musig_nonce_parity(long ctx, byte[] session);

    public static native byte[] secp256k1_musig_adapt(long ctx, byte[] pre_sig64, byte[] sec_adaptor32, int nonce_parity);

    public static native byte[] secp256k1_musig_extract_adaptor(long ctx, byte[] sig64, byte[] pre_sig64, int nonce_parity);

    /* Returns the flattened key material: threshold public key (65 bytes), followed by the n 32-byte
     * secret shares, followed by the n 65-byte public shares. */
    public static native byte[] secp256k1_frost_trusted_dealer_keygen(long ctx, byte[] threshold_seckey32, int n_participants, int threshold);

    public static native int secp256k1_frost_threshold_info_validate(long ctx, byte[] threshold_pk, byte[][] pubshares, int threshold);

    public static native byte[] secp256k1_frost_tweak_cache_init(long ctx, byte[] threshold_pk);

    public static native byte[] secp256k1_frost_tweaked_pubkey_get(long ctx, byte[] tweak_cache);

    public static native byte[] secp256k1_frost_pubkey_xonly_tweak_add(long ctx, byte[] tweak_cache, byte[] tweak32);

    public static native byte[] secp256k1_frost_pubkey_ec_tweak_add(long ctx, byte[] tweak_cache, byte[] tweak32);

    /* Returns the flattened nonce: secret nonce (68 bytes) followed by the public nonce (66 bytes). */
    public static native byte[] secp256k1_frost_nonce_gen(long ctx, byte[] session_secrand32, byte[] secshare32, byte[] pubshare, byte[] thresh_pk32, byte[] msg, byte[] extra_in);

    public static native byte[] secp256k1_frost_nonce_agg(long ctx, byte[][] pubnonces);

    /**
     * Nested FROST+MuSig2 ("prefractal"). Nonces and aggregate nonces cross this boundary in their 66-byte
     * serialised form and are parsed inside the glue; the tweak and keyagg caches cross as their opaque blobs.
     * Returns the group's musig2 public nonce and the unscaled frost aggregate nonce, concatenated.
     */
    public static native byte[] secp256k1_prefractal_nonce_agg(long ctx, byte[][] pubnonces, int[] ids, byte[] thresh_pk);

    public static native byte[] secp256k1_prefractal_sign(long ctx, byte[] secnonce, byte[] secshare32, int my_id, int[] ids, byte[][] pubshares, byte[] aggnonce, byte[] thresh_pk, byte[] tweak_cache, byte[] keyagg_cache, byte[] cosigner_aggnonce, byte[] msg32);

    public static native int secp256k1_prefractal_partial_sig_verify(long ctx, byte[] partial_sig, byte[] pubnonce, byte[] pubshare, int my_id, int[] ids, byte[] aggnonce, byte[] thresh_pk, byte[] tweak_cache, byte[] keyagg_cache, byte[] cosigner_aggnonce, byte[] msg32);

    public static native byte[] secp256k1_prefractal_partial_sig_agg(long ctx, byte[][] partial_sigs, byte[] tweak_cache);

    /**
     * FROST enrollment. Threshold public keys and public shares cross this boundary in either the 33-byte
     * compressed or the 65-byte uncompressed form and are parsed inside the glue; derived public keys are
     * returned uncompressed. The u-entry arrays are all aligned with `ids`.
     */
    public static native byte[] secp256k1_frost_enrollment_params_hash(long ctx, byte[] thresh_pk, int[] ids, int new_id, int n_participants, int threshold);

    /* Returns the flattened result: the u 32-byte enrollment shares followed by the 32-byte parameters hash. */
    public static native byte[] secp256k1_frost_enrollment_shares_gen(long ctx, byte[] session_secrand32, byte[] secshare32, byte[] thresh_pk, int[] ids, int my_id, int new_id, int n_participants, int threshold);

    /**
     * Returns the 32-byte aggregated share, and reports fault attribution through `mismatch_id`, a one-element
     * array set to the identifier of the helper at fault or to -1 when there is none. Invalid arguments raise a
     * Secp256k1Exception rather than being reported there.
     */
    public static native byte[] secp256k1_frost_enrollment_share_agg(long ctx, byte[][] all_shares32, byte[][] received_params_hashes32, byte[] thresh_pk, int[] ids, int my_id, int new_id, int n_participants, int threshold, int[] mismatch_id);

    public static native byte[] secp256k1_frost_enrollment_pubshare_derive(long ctx, byte[][] pubshares, int[] ids, int new_id, int n_participants, int threshold);

    /* `expected_params_hash32` and `expected_pubshare` are optional: pass null to skip the corresponding check. */
    public static native byte[] secp256k1_frost_enrollment_secshare_gen(long ctx, byte[][] sigmas32, byte[] thresh_pk, int[] ids, int new_id, int n_participants, int threshold, byte[] expected_params_hash32, byte[] expected_pubshare);

    /* Commitments stay as raw 33-byte entries: 33 zero bytes encode infinity for a zero coefficient. */
    public static native byte[] secp256k1_frost_enrollment_pubshare_derive_from_commitments(long ctx, byte[] thresh_pk, byte[][] commitments33, int new_id, int n_participants);

    public static native byte[] secp256k1_frost_enrollment_reduced_params_hash(long ctx, byte[] thresh_pk, int[] ids, int new_id, int n_participants, int threshold, byte[] session_id32);

    /* Returns the flattened result: the u triangular 32-byte shares followed by the 32-byte parameters hash. */
    public static native byte[] secp256k1_frost_enrollment_reduced_shares_gen(long ctx, byte[] session_secrand32, byte[] secshare32, byte[] thresh_pk, int[] ids, int my_id, int new_id, int n_participants, int threshold, byte[] session_id32);

    /* Uses the same sigma/mismatch_id result convention as full enrollment aggregation. */
    public static native byte[] secp256k1_frost_enrollment_reduced_share_agg(long ctx, byte[][] all_shares32, byte[][] received_params_hashes32, byte[] thresh_pk, int[] ids, int my_id, int new_id, int n_participants, int threshold, byte[] session_id32, int[] mismatch_id);

    /* Reduced round 2 requires one parameters hash per helper and a non-null expected public share. */
    public static native byte[] secp256k1_frost_enrollment_reduced_secshare_gen(long ctx, byte[][] sigmas32, byte[][] received_params_hashes32, byte[] thresh_pk, int[] ids, int new_id, int n_participants, int threshold, byte[] session_id32, byte[] expected_pubshare);

    public static native byte[] secp256k1_frost_session_init(long ctx, byte[] aggnonce, int[] ids, byte[][] pubshares, int n_participants, int threshold, byte[] tweak_cache, byte[] msg);

    public static native byte[] secp256k1_frost_sign(long ctx, byte[] secnonce, byte[] secshare32, byte[] session, int[] ids, byte[][] pubshares, int my_id);

    /* Returns the flattened result: partial signature (32 bytes) followed by the public nonce (66 bytes). */
    public static native byte[] secp256k1_frost_deterministic_sign(long ctx, byte[] secshare32, int my_id, byte[] aggothernonce, int[] ids, byte[][] pubshares, int n_participants, int threshold, byte[] tweak_cache, byte[] msg, byte[] aux_rand32);

    public static native int secp256k1_frost_partial_sig_verify(long ctx, byte[] psig, byte[] pubnonce, byte[] pubshare, byte[] session, int[] ids, int signer_index);

    public static native byte[] secp256k1_frost_partial_sig_agg(long ctx, byte[] session, byte[][] psigs);

    public static native byte[] secp256k1_chilldkg_hostpubkey_gen(long ctx, byte[] hostseckey32);

    public static native byte[] secp256k1_chilldkg_params_hash(long ctx, byte[][] hostpubkeys33, int threshold);

    /* Returns the participant's first message (pmsg1); state1Out is filled with the participant's session state. */
    public static native byte[] secp256k1_chilldkg_participant_step1(long ctx, byte[] hostseckey32, byte[][] hostpubkeys33, int threshold, byte[] random32, byte[] state1Out);

    /* Fault codes are returned as int; faultIndexOut[0] receives the (suspected) faulty participant's id, or -1. */
    public static native int secp256k1_chilldkg_coordinator_step1(long ctx, byte[][] pmsgs1, byte[][] hostpubkeys33, int threshold, byte[] stateOut, byte[] cmsg1Out, int[] faultIndexOut);

    public static native int secp256k1_chilldkg_participant_step2(long ctx, byte[] hostseckey32, byte[] state1, byte[] cmsg1, byte[] aux_rand32, byte[] state2Out, byte[] sig64Out, byte[] invDataOut, int[] faultIndexOut);

    public static native int secp256k1_chilldkg_coordinator_finalize(long ctx, byte[] state, byte[][] pmsgs2, int threshold, byte[] cmsg2Out, byte[] threshPk33Out, byte[] pubshares33Out, byte[] recoveryOut, int[] faultIndexOut);

    public static native int secp256k1_chilldkg_participant_finalize(long ctx, byte[] state2, byte[] cmsg2, int threshold, byte[] secshare32Out, byte[] threshPk33Out, byte[] pubshares33Out, byte[] recoveryOut, int[] faultIndexOut);

    /* pubshares33Out and hostpubkeys33Out must be able to hold 33 * 128 bytes each; the number of entries
     * actually filled is written to nAndThresholdOut[0], and the threshold to nAndThresholdOut[1]. */
    public static native int secp256k1_chilldkg_participant_recover(long ctx, byte[] hostseckey32, byte[] recovery, byte[] secshare32Out, byte[] threshPk33Out, byte[] pubshares33Out, byte[] hostpubkeys33Out, int[] nAndThresholdOut, int[] faultIndexOut);

    public static native int secp256k1_chilldkg_coordinator_recover(long ctx, byte[] recovery, byte[] threshPk33Out, byte[] pubshares33Out, byte[] hostpubkeys33Out, int[] nAndThresholdOut);

    public static native byte[] secp256k1_chilldkg_recovery_ack_sign(long ctx, byte[] hostseckey32, byte[][] hostpubkeys33, int threshold, byte[] recovery, byte[] aux_rand32);

    public static native int secp256k1_chilldkg_recovery_acks_verify(long ctx, byte[][] hostpubkeys33, int threshold, byte[] recovery, byte[][] ackSigs64, int[] faultIndexOut);

    public static native int secp256k1_chilldkg_coordinator_investigate(long ctx, byte[][] pmsgs1, byte[][] hostpubkeys33, int threshold, int participantId, byte[] cinvOut, int[] faultIndexOut);

    public static native int secp256k1_chilldkg_participant_investigate(long ctx, byte[] invData, byte[] cinv, int[] faultIndexOut);

    /* FROST share refresh. The session parameters cross the boundary as their serialization: params_serialize
     * validates and serializes them, and every other function parses them again. Fault codes are chilldkg's;
     * faultIndexOut[0] receives the faulty recipient's position, or -1. */
    public static native byte[] secp256k1_frost_refresh_params_serialize(long ctx, byte[] thresh_pk33, byte[][] hostpubkeys33, byte[][] pubshares33, int threshold, int generation, int[] recipient_ids, byte[] refresh_id32);

    public static native byte[] secp256k1_frost_refresh_params_hash(long ctx, byte[] params);

    public static native byte[] secp256k1_frost_refresh_participant_step1(long ctx, byte[] hostseckey32, byte[] params, int participant_id, byte[] random32);

    public static native int secp256k1_frost_refresh_coordinator_step1(long ctx, byte[][] pmsgs1, byte[] params, byte[] cmsg1Out, int[] faultIndexOut);

    public static native int secp256k1_frost_refresh_participant_step2(long ctx, byte[] hostseckey32, byte[] secshare32, byte[] params, int participant_id, byte[] cmsg1, byte[] aux_rand32, byte[] newSecshare32Out, byte[] newPubshares33Out, byte[] sig64Out, int[] faultIndexOut);

    public static native int secp256k1_frost_refresh_coordinator_finalize(long ctx, byte[] params, byte[] cmsg1, byte[][] pmsgs2, byte[] cmsg2Out, int[] faultIndexOut);

    public static native int secp256k1_frost_refresh_participant_finalize(long ctx, byte[] params, byte[] cmsg1, byte[] cmsg2, byte[] recoveryOut, int[] faultIndexOut);

    public static native int secp256k1_frost_refresh_participant_recover(long ctx, byte[] hostseckey32, byte[] secshare32, byte[] recovery, byte[] newSecshare32Out, byte[] newPubshares33Out, int[] participantIdOut);

    public static native int secp256k1_frost_refresh_public_recover(long ctx, byte[] recovery, byte[] paramsOut, byte[] newPubshares33Out);

    /* Returns the n serialized shares concatenated (all shares of a group serialize to the same length). */
    public static native byte[] secp256k1_iceberg_shares_gen(long ctx, int n, int t, byte[] seed32);

    public static native byte[] secp256k1_iceberg_share_cache_create(long ctx, byte[] share);

    public static native byte[] secp256k1_iceberg_pubshare_gen(long ctx, byte[] share, byte[] cache);

    public static native byte[] secp256k1_iceberg_pubkey_agg(long ctx, byte[][] pubshares, int n, int t);

    public static native byte[] secp256k1_iceberg_nonce_gen(long ctx, byte[] share, byte[] cache, byte[] sid32);

    public static native byte[] secp256k1_iceberg_nonce_agg(long ctx, byte[][] pubnonces, int n, int t, byte[] grouppk);

    public static native int secp256k1_iceberg_keyagg_check(long ctx, byte[] keyaggcache, byte[][] pubkeys, byte[] grouppk);

    public static native byte[] secp256k1_iceberg_partial_sign(long ctx, byte[] share, byte[] cache, byte[] sid32, byte[][] pubnonces, byte[] grouppk, byte[] keyaggcache, byte[] msg32, byte[] cosigner_aggnonce);

    public static native int secp256k1_iceberg_partial_sig_verify(long ctx, byte[] psig, byte[] pubshare, byte[][] pubnonces, int n, int t, byte[] grouppk, byte[] keyaggcache, byte[] msg32, byte[] cosigner_aggnonce);

    public static native byte[] secp256k1_iceberg_partial_sig_agg(long ctx, byte[][] psigs, int n, int t);

    /* Canonical descriptors cross the boundary as variable-length byte strings; live descriptors are opaque. */
    public static native byte[] secp256k1_confederation_rpd_parse(long ctx, byte[] input);

    public static native int secp256k1_confederation_rpd_validate(long ctx, byte[] rpd);

    public static native byte[] secp256k1_confederation_rpd_serialize(long ctx, byte[] rpd);

    public static native int secp256k1_confederation_rpd_serialized_size(long ctx, byte[] rpd);

    public static native byte[] secp256k1_confederation_rpd_hash(long ctx, byte[] rpd);

    public static native byte[] secp256k1_confederation_ksd_parse(long ctx, byte[] input, byte[] rpd);

    public static native int secp256k1_confederation_ksd_validate(long ctx, byte[] ksd, byte[] rpd);

    public static native byte[] secp256k1_confederation_ksd_serialize(long ctx, byte[] ksd, byte[] rpd);

    public static native int secp256k1_confederation_ksd_serialized_size(long ctx, byte[] ksd, byte[] rpd);

    public static native byte[] secp256k1_confederation_ksd_hash(long ctx, byte[] ksd, byte[] rpd);

    /* Returns [min_signers, min_blockers]. */
    public static native int[] secp256k1_confederation_access_analyze(long ctx, byte[] rpd);

    public static native byte[] secp256k1_confederation_transition_parse(long ctx, byte[] input, byte[] old_rpd, byte[] old_ksd, byte[] new_rpd, byte[] new_ksd);

    public static native byte[] secp256k1_confederation_transition_serialize(long ctx, byte[] transition, byte[] old_rpd, byte[] old_ksd, byte[] new_rpd, byte[] new_ksd);

    public static native int secp256k1_confederation_transition_serialized_size(long ctx, byte[] transition, byte[] old_rpd, byte[] old_ksd, byte[] new_rpd, byte[] new_ksd);

    public static native int secp256k1_confederation_transition_conflicts(long ctx, byte[] first, byte[] second);

    public static native byte[] secp256k1_confederation_transition_hash(long ctx, byte[] transition);

    public static native int secp256k1_confederation_transition_validate(long ctx, byte[] transition, byte[] old_rpd, byte[] old_ksd, byte[] new_rpd, byte[] new_ksd);

    public static native int secp256k1_confederation_transition_check_successor(long ctx, byte[] transition, byte[] current_rpd, byte[] current_ksd);

    public static native byte[] secp256k1_confederation_share_wrap(long ctx, int group_id, int admin_id, byte[] secshare32, byte[] ksd, byte[] rpd);

    public static native byte[] secp256k1_confederation_share_rebind(long ctx, byte[] share, byte[] hostseckey32, byte[] current_ksd, byte[] current_rpd);

    public static native int secp256k1_confederation_share_validate(long ctx, byte[] share, byte[] current_ksd, byte[] current_rpd);

    public static native byte[] secp256k1_confederation_recovery_issue(long ctx, byte[] share, byte[] hostseckey32, byte[] ksd, byte[] rpd, int operation, byte[] transition_hash32, byte[] recovery_nonce32);

    public static native byte[] secp256k1_confederation_recovery_open(long ctx, byte[] recovery, byte[] hostseckey32, byte[] current_ksd, byte[] current_rpd);

    public static native byte[] secp256k1_confederation_recovery_serialize(long ctx, byte[] recovery);

    public static native int secp256k1_confederation_recovery_serialized_size(long ctx, byte[] recovery);

    public static native byte[] secp256k1_confederation_recovery_parse(long ctx, byte[] input, byte[] hostseckey32);

    public static native int secp256k1_confederation_dkg_work_size(long ctx, byte[] rpd);

    /* Returns opaque KSD || transition || role-count shares || role-count recoveries. */
    public static native byte[] secp256k1_confederation_dkg(long ctx, byte[] rpd, byte[] session_seed32, byte[][] hostseckeys32, byte[][] dealer_seeds32, byte[][] recovery_nonces32);

    public static native byte[] secp256k1_confederation_sign(long ctx, byte[] rpd, byte[] ksd, byte[][] shares, byte[][] hostseckeys32, byte[] signing_session_id32, int[] group_ids, int[] inner_counts, int[] admin_ids, byte[] tweak_sequence, byte[] message32, byte[][] nonce_secrands32);

    public static native byte[] secp256k1_confederation_ksd_pubkey_get(long ctx, byte[] ksd, byte[] rpd);
    public static native int[] secp256k1_confederation_dkg_message_sizes(long ctx, byte[] rpd);

    public static native int secp256k1_confederation_dkg_participant_step1(long ctx, byte[] rpd, int group_id, int admin_id, byte[] hostseckey32, byte[] dealer_seed32, byte[] session_seed32, byte[] record_out, byte[] ciphertexts_out);

    public static native int secp256k1_confederation_dkg_coordinator_step1(long ctx, byte[] rpd, byte[] session_seed32, byte[] records, byte[] ciphertexts, byte[] broadcast_out, int[] fault);

    public static native byte[] secp256k1_confederation_dkg_derive_ksd(long ctx, byte[] rpd, byte[] broadcast);

    public static native byte[] secp256k1_confederation_dkg_genesis_prepare(long ctx, byte[] rpd, byte[] ksd, byte[] transition_hash_out);

    public static native int secp256k1_confederation_dkg_participant_step2(long ctx, byte[] rpd, int group_id, int admin_id, byte[] hostseckey32, byte[] session_seed32, byte[] own_record, byte[] broadcast, byte[] ksd_out, byte[] transition_hash_out, byte[] authorization_out, int[] fault);

    public static native byte[] secp256k1_confederation_dkg_evidence_list_write(long ctx, byte[] rpd, byte[][] signatures64);

    public static native int secp256k1_confederation_dkg_verify_evidence(long ctx, byte[] rpd, byte[] transition_hash32, int purpose, byte[] evidence_list, int[] fault);

    public static native int secp256k1_confederation_dkg_participant_acknowledge(long ctx, byte[] rpd, int group_id, int admin_id, byte[] hostseckey32, byte[] transition_hash32, byte[] authorizations, byte[] acknowledgment_out, int[] fault);

    public static native int secp256k1_confederation_dkg_coordinator_finalize(long ctx, byte[] rpd, byte[] ksd, byte[] authorizations, byte[] acknowledgments, byte[] transition_out, int[] fault);

    public static native int secp256k1_confederation_dkg_participant_finalize(long ctx, byte[] transition, byte[] rpd, byte[] ksd, int group_id, int admin_id, byte[] hostseckey32, byte[] own_record, byte[] broadcast, byte[] recovery_nonce32, byte[] share_out, byte[] recovery_out);

    public static native byte[] secp256k1_confederation_dkg_investigation_response(long ctx, byte[] rpd, byte[] session_seed32, int dealer_group_id, int dealer_admin_id, byte[] ciphertexts);

    public static native int secp256k1_confederation_dkg_investigate(long ctx, byte[] rpd, int group_id, int admin_id, byte[] hostseckey32, byte[] broadcast, byte[] responses, int[] fault);
    public static native byte[] secp256k1_confederation_sign_session_init(long ctx, byte[] rpd, byte[] ksd, byte[] session_id32, int[] group_ids, int[] inner_counts, int[] admin_ids, byte[] tweak_sequence, byte[] session_out);

    public static native int secp256k1_confederation_sign_session_check(long ctx, byte[] session, byte[] rpd, byte[] ksd, byte[] d_sign);

    public static native int[] secp256k1_confederation_sign_message_sizes(long ctx, byte[] session);

    public static native int secp256k1_confederation_signer_nonce_gen(long ctx, byte[] session, byte[] rpd, byte[] ksd, byte[] share, byte[] d_sign, byte[] session_secrand32, byte[] signer_out, byte[] pubnonce_out);

    public static native void secp256k1_confederation_signer_abort(long ctx, byte[] signer);

    public static native byte[] secp256k1_confederation_nonce_transcript_write(long ctx, byte[] session, byte[][] pubnonces66);

    public static native byte[] secp256k1_confederation_signer_confirm(long ctx, byte[] signer, byte[] session, byte[] rpd, byte[] ksd, byte[] d_sign, byte[] nonce_transcript, byte[] message32, byte[] hostseckey32);

    public static native byte[] secp256k1_confederation_confirmation_certificate_write(long ctx, byte[] session, byte[] d_sign, byte[] nonce_transcript, byte[] message32, byte[][] confirmations64);

    public static native int secp256k1_confederation_confirmation_verify(long ctx, byte[] session, byte[] rpd, byte[] ksd, byte[] d_sign, byte[] nonce_transcript, byte[] message32, byte[] certificate);

    public static native byte[] secp256k1_confederation_signer_partial(long ctx, byte[] signer, byte[] session, byte[] rpd, byte[] ksd, byte[] share, byte[] d_sign, byte[] nonce_transcript, byte[] message32, byte[] certificate);

    public static native int secp256k1_confederation_member_partial_verify(long ctx, byte[] partial32, byte[] session, byte[] rpd, byte[] ksd, byte[] d_sign, byte[] nonce_transcript, byte[] message32, byte[] certificate, int selected_index);

    public static native byte[] secp256k1_confederation_group_partial_aggregate(long ctx, byte[] session, byte[] rpd, byte[] ksd, byte[] d_sign, byte[] nonce_transcript, byte[] message32, byte[] certificate, int outer_index, byte[][] partials32);

    public static native int secp256k1_confederation_group_partial_verify(long ctx, byte[] group_partial36, byte[] session, byte[] rpd, byte[] ksd, byte[] d_sign, byte[] nonce_transcript, byte[] message32, byte[] certificate, int outer_index);

    public static native byte[] secp256k1_confederation_outer_aggregate(long ctx, byte[] session, byte[] rpd, byte[] ksd, byte[] d_sign, byte[] nonce_transcript, byte[] message32, byte[] certificate, byte[][] group_partials36);
}
