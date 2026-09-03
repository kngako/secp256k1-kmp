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
}
