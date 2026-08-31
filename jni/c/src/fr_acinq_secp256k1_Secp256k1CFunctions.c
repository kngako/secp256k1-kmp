#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#define SECP256K1_STATIC // needed on windows when linking to a static version of secp256k1
#endif
#include "fr_acinq_secp256k1_Secp256k1CFunctions.h"
#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "include/secp256k1_musig.h"
#include "include/secp256k1_frost.h"
#include "include/secp256k1_recovery.h"
#include "include/secp256k1_schnorrsig.h"

/*
 * libsecp256k1 tags each of its opaque musig2 objects with a 4-byte magic prefix and validates it
 * internally with ARG_CHECK, which invokes the context's illegal-argument callback. The default
 * callback aborts the process, so a blob that has the right size but does not actually hold a
 * musig2 object would kill the JVM instead of raising an exception. We check the prefix before
 * handing the blob to libsecp256k1 so that these cases throw Secp256k1Exception.
 *
 * Keep in sync with native/secp256k1/src/modules/musig/{keyagg,session}_impl.h.
 */
static const unsigned char MUSIG_KEYAGG_CACHE_MAGIC[4] = { 0xf4, 0xad, 0xbb, 0xdf };
static const unsigned char MUSIG_SECNONCE_MAGIC[4] = { 0x22, 0x0e, 0xdc, 0xf1 };
static const unsigned char MUSIG_SESSION_MAGIC[4] = { 0x9d, 0xed, 0xe9, 0x17 };

/* Same thing for the opaque frost objects passed back to libsecp256k1 as raw byte arrays.
 * Keep in sync with native/secp256k1/src/modules/frost/{keygen,session}_impl.h. */
static const unsigned char FROST_SECNONCE_MAGIC[4] = { 0x5c, 0xcf, 0xb9, 0x99 };
static const unsigned char FROST_TWEAK_CACHE_MAGIC[4] = { 0x8d, 0x86, 0xb5, 0x01 };
static const unsigned char FROST_SESSION_MAGIC[4] = { 0x34, 0xb5, 0x27, 0x3d };

#define CHECKMAGIC(data, magic, message) CHECKRESULT(memcmp((data), (magic), 4) != 0, message)

/*
 * Installed on every context we create, replacing the default callback that aborts the process.
 * Returning from here makes the libsecp256k1 return undefined values, but in practice calls fail with 0,
 * which the bindings below already turn into a Secp256k1Exception. 
 * The CHECKMAGIC checks above are the primary defence; this is the backstop for anything missed.
 */
static void JNI_IllegalArgumentCallback(const char* message, void* data)
{
    (void)message;
    (void)data;
}

static void JNI_ThrowByName(JNIEnv* penv, const char* name, const char* msg)
{
    jclass cls = (*penv)->FindClass(penv, name);
    if (cls != NULL) {
        (*penv)->ThrowNew(penv, cls, msg);
        (*penv)->DeleteLocalRef(penv, cls);
    }
}

static void JNI_ThrowSecp256k1(JNIEnv* penv, const char* msg)
{
    JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", msg);
}

static void JNI_ThrowNull(JNIEnv* penv, const char* name)
{
    char msg[128];
    snprintf(msg, sizeof(msg), "%s cannot be null", name);
    JNI_ThrowSecp256k1(penv, msg);
}

static void JNI_ThrowSize(JNIEnv* penv, const char* name, int size)
{
    char msg[128];
    snprintf(msg, sizeof(msg), "%s must be %d bytes", name, size);
    JNI_ThrowSecp256k1(penv, msg);
}

#define CHECKRESULT(errorcheck, message)                                             \
    {                                                                                \
        if (errorcheck) {                                                            \
            JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", message); \
            return 0;                                                                \
        }                                                                            \
    }

#define CHECKRESULT1(errorcheck, message, dosomething)                               \
    {                                                                                \
        if (errorcheck) {                                                            \
            dosomething;                                                             \
            JNI_ThrowByName(penv, "fr/acinq/secp256k1/Secp256k1Exception", message); \
            return 0;                                                                \
        }                                                                            \
    }

/* Buffers are `unsigned char` everywhere below: the jbyte <-> unsigned char conversion
 * is confined to get_bytes() and copy_bytes_to_java(), the two JNI boundary helpers. */
static inline jbyteArray copy_bytes_to_java(JNIEnv* penv, const unsigned char* from, size_t size)
{
    jbyteArray dest = (*penv)->NewByteArray(penv, (jsize)size);
    CHECKRESULT(dest == NULL, "memory allocation failed");
    (*penv)->SetByteArrayRegion(penv, dest, 0, (jsize)size, (const jbyte*)from);
    return dest;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_context_create
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1context_1create(JNIEnv* penv, jclass clazz, jint flags)
{
    secp256k1_context* ctx = secp256k1_context_create(flags);
    if (ctx != NULL) {
        /* secp256k1_context_set_illegal_callback needs exclusive access to the context, so it must
           be done here, before the context is returned and can be shared between threads. */
        secp256k1_context_set_illegal_callback(ctx, JNI_IllegalArgumentCallback, NULL);
    }
    return (jlong)ctx;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_context_destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1context_1destroy(JNIEnv* penv, jclass clazz, jlong ctx)
{
    if (ctx != 0) {
        secp256k1_context_destroy((secp256k1_context*)ctx);
    }
}

/* The get_xxx() helpers below all return 1 on success, and on failure throw a
 * Secp256k1Exception describing what was wrong with the argument and return 0.
 * They must not be called when an exception is already pending: callers are
 * expected to return as soon as one of them fails. */
static inline int get_bytes(JNIEnv* penv, jbyteArray jbytes, size_t size, unsigned char* bytes, const char* name)
{
    if (jbytes == NULL) {
        JNI_ThrowNull(penv, name);
        return 0;
    }
    if ((*penv)->GetArrayLength(penv, jbytes) != (jsize)size) {
        JNI_ThrowSize(penv, name, (int)size);
        return 0;
    }
    (*penv)->GetByteArrayRegion(penv, jbytes, 0, (jsize)size, (jbyte*)bytes);
    return 1;
}

static inline int get_bytes32(JNIEnv* penv, jbyteArray jbytes, unsigned char* bytes, const char* name)
{
    return get_bytes(penv, jbytes, 32, bytes, name);
}

static inline int get_pubkey(JNIEnv* penv, const secp256k1_context* ctx, jbyteArray jpubkey, secp256k1_pubkey* pubkey)
{
    jsize size;
    unsigned char pubkeyBytes[65];

    if (jpubkey == NULL) {
        JNI_ThrowNull(penv, "public key");
        return 0;
    }
    size = (*penv)->GetArrayLength(penv, jpubkey);
    if ((size != 33) && (size != 65)) {
        JNI_ThrowSecp256k1(penv, "public key must be 33 or 65 bytes");
        return 0;
    }
    (*penv)->GetByteArrayRegion(penv, jpubkey, 0, size, (jbyte*)pubkeyBytes);
    if (!secp256k1_ec_pubkey_parse(ctx, pubkey, pubkeyBytes, (size_t)size)) {
        JNI_ThrowSecp256k1(penv, "secp256k1_ec_pubkey_parse failed");
        return 0;
    }
    return 1;
}

static inline int get_signature(JNIEnv* penv, const secp256k1_context* ctx, jbyteArray jsig, secp256k1_ecdsa_signature* sig, const char* name)
{
    unsigned char buffer[64];

    if (!get_bytes(penv, jsig, 64, buffer, name)) return 0;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, sig, buffer)) {
        JNI_ThrowSecp256k1(penv, "secp256k1_ecdsa_signature_parse_compact failed");
        return 0;
    }
    return 1;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_ec_seckey_verify
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32];

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return 0;
    return secp256k1_ec_seckey_verify(ctx, seckey);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_parse
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1parse(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_pubkey pubkey;
    unsigned char pubkeyBytes[65];
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;
    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pubkeyBytes, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pubkeyBytes, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_create
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1create(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], pubkey[65];
    secp256k1_pubkey pub;
    int result = 0;
    size_t len;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    result = secp256k1_ec_pubkey_create(ctx, &pub, seckey);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_create failed");

    len = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pubkey, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_sign
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1sign(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jmsg, jbyteArray jseckey, jbyteArray jndata)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], msg[32], ndata[32], sig[64];
    secp256k1_ecdsa_signature signature;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    if (!get_bytes32(penv, jmsg, msg, "message")) return NULL;
    if (jndata != NULL) {
        if (!get_bytes32(penv, jndata, ndata, "auxiliary data")) return NULL;
    }

    result = secp256k1_ecdsa_sign(ctx, &signature, msg, seckey, NULL, jndata != NULL ? ndata : NULL);
    CHECKRESULT(!result, "secp256k1_ecdsa_sign failed");

    result = secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &signature);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");

    return copy_bytes_to_java(penv, sig, 64);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_verify
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char msg[32];
    secp256k1_ecdsa_signature signature;
    secp256k1_pubkey pubkey;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_signature(penv, ctx, jsig, &signature, "signature")) return 0;
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return 0;
    if (!get_bytes32(penv, jmsg, msg, "message")) return 0;

    result = secp256k1_ecdsa_verify(ctx, &signature, msg, &pubkey);
    return result;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_signature_normalize
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1signature_1normalize(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsigin, jbyteArray jsigout)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char sig[64];
    secp256k1_ecdsa_signature signature_in, signature_out;
    int result = 0;
    int return_value = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (jsigout == NULL) {
        JNI_ThrowNull(penv, "output signature");
        return 0;
    }
    if ((*penv)->GetArrayLength(penv, jsigout) != 64) {
        JNI_ThrowSize(penv, "output signature", 64);
        return 0;
    }
    if (!get_signature(penv, ctx, jsigin, &signature_in, "input signature")) return 0;

    return_value = secp256k1_ecdsa_signature_normalize(ctx, &signature_out, &signature_in);
    result = secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &signature_out);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_compact failed");

    (*penv)->SetByteArrayRegion(penv, jsigout, 0, 64, (const jbyte*)sig);

    return return_value;
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_negate
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1negate(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    result = secp256k1_ec_seckey_negate(ctx, seckey);
    CHECKRESULT(!result, "secp256k1_ec_seckey_negate failed");

    return copy_bytes_to_java(penv, seckey, 32);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_negate
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1negate(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65];
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;

    result = secp256k1_ec_pubkey_negate(ctx, &pubkey);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_negate failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jtweak)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], tweak[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    if (!get_bytes32(penv, jtweak, tweak, "tweak")) return NULL;

    result = secp256k1_ec_seckey_tweak_add(ctx, seckey, tweak);
    CHECKRESULT(!result, "secp256k1_ec_seckey_tweak_add failed");

    return copy_bytes_to_java(penv, seckey, 32);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpubkey, jbyteArray jtweak)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65], tweak[32];
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;
    if (!get_bytes32(penv, jtweak, tweak, "tweak")) return NULL;

    result = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_tweak_add failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_seckey_tweak_mul
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1seckey_1tweak_1mul(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jtweak)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], tweak[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    if (!get_bytes32(penv, jtweak, tweak, "tweak")) return NULL;

    result = secp256k1_ec_seckey_tweak_mul(ctx, seckey, tweak);
    CHECKRESULT(!result, "secp256k1_ec_seckey_tweak_mul failed");

    return copy_bytes_to_java(penv, seckey, 32);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_tweak_mul
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1tweak_1mul(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpubkey, jbyteArray jtweak)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65], tweak[32];
    secp256k1_pubkey pubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;
    if (!get_bytes32(penv, jtweak, tweak, "tweak")) return NULL;

    result = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, tweak);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_tweak_mul failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ec_pubkey_combine
 * Signature: (J[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ec_1pubkey_1combine(JNIEnv* penv, jclass clazz, jlong jctx, jobjectArray jpubkeys)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65];
    secp256k1_pubkey* pubkeys;
    secp256k1_pubkey** pubkey_ptrs;
    secp256k1_pubkey combined;
    jbyteArray jpubkey;
    size_t size, count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(jpubkeys == NULL, "public keys cannot be null");

    count = (*penv)->GetArrayLength(penv, jpubkeys);
    CHECKRESULT(count < 1, "pubkey array cannot be empty")
    pubkeys = calloc(count, sizeof(secp256k1_pubkey));
    CHECKRESULT(pubkeys == NULL, "memory allocation failed");
    pubkey_ptrs = calloc(count, sizeof(secp256k1_pubkey*));
    CHECKRESULT1(pubkey_ptrs == NULL, "memory allocation failed", free(pubkeys));

    for (i = 0; i < count; i++) {
        pubkey_ptrs[i] = &(pubkeys[i]);
        jpubkey = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpubkeys, i);
        if (!get_pubkey(penv, ctx, jpubkey, pubkey_ptrs[i])) {
            free(pubkey_ptrs);
            free(pubkeys);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jpubkey);
    }
    result = secp256k1_ec_pubkey_combine(ctx, &combined, (const secp256k1_pubkey* const*)pubkey_ptrs, count);
    free(pubkey_ptrs);
    free(pubkeys);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_combine failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &combined, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdh
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdh(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jseckey, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckeyBytes[32], output[32];
    secp256k1_pubkey pubkey;
    int result;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckeyBytes, "secret key")) return NULL;
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;

    result = secp256k1_ecdh(ctx, output, &pubkey, seckeyBytes, NULL, NULL);
    CHECKRESULT(!result, "secp256k1_ecdh failed");

    return copy_bytes_to_java(penv, output, 32);
}

/*
 * Class:     fr_acinq_bitcoin_Secp256k1Bindings
 * Method:    secp256k1_ecdsa_recover
 * Signature: (J[B[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1ecdsa_1recover(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jint recid)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char sig[64], msg[32], pub[65];
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature signature;
    size_t size;
    int result;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(recid < 0 || recid > 3, "invalid recovery id");
    if (!get_bytes(penv, jsig, 64, sig, "signature")) return NULL;
    if (!get_bytes32(penv, jmsg, msg, "message")) return NULL;

    result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature, sig, recid);
    CHECKRESULT(!result, "secp256k1_ecdsa_recoverable_signature_parse_compact failed");

    result = secp256k1_ecdsa_recover(ctx, &pubkey, &signature, msg);
    CHECKRESULT(!result, "secp256k1_ecdsa_recover failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_compact_to_der
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1compact_1to_1der(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_ecdsa_signature signature;
    unsigned char der[73];
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_signature(penv, ctx, jsig, &signature, "signature")) return NULL;

    size = 73;
    result = secp256k1_ecdsa_signature_serialize_der(ctx, der, &size, &signature);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_der failed");
    return copy_bytes_to_java(penv, der, size);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_der_to_compact
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1der_1to_1compact(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char sig[73];
    secp256k1_ecdsa_signature signature;
    unsigned char compact[64];
    jsize size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (jsig == NULL) {
        JNI_ThrowNull(penv, "signature");
        return NULL;
    }
    size = (*penv)->GetArrayLength(penv, jsig);
    CHECKRESULT(size < 8 || size > 73, "DER signature must be between 8 and 73 bytes");

    (*penv)->GetByteArrayRegion(penv, jsig, 0, size, (jbyte*)sig);
    result = secp256k1_ecdsa_signature_parse_der(ctx, &signature, sig, (size_t)size);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_parse_der failed");

    result = secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &signature);
    CHECKRESULT(!result, "secp256k1_ecdsa_signature_serialize_der failed");

    return copy_bytes_to_java(penv, compact, 64);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_schnorrsig_sign
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1schnorrsig_1sign(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jmsg, jbyteArray jseckey, jbyteArray jauxrand32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char seckey[32], msg[32], auxrand32[32];
    secp256k1_keypair keypair;
    unsigned char signature[64];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jmsg, msg, "message")) return NULL;
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    if (jauxrand32 != NULL) {
        if (!get_bytes32(penv, jauxrand32, auxrand32, "auxiliary random data")) return NULL;
    }
    result = secp256k1_keypair_create(ctx, &keypair, seckey);
    CHECKRESULT(!result, "secp256k1_keypair_create failed");

    result = secp256k1_schnorrsig_sign32(ctx, signature, msg, &keypair, jauxrand32 != NULL ? auxrand32 : NULL);
    CHECKRESULT(!result, "secp256k1_schnorrsig_sign failed");

    return copy_bytes_to_java(penv, signature, 64);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_schnorrsig_verify
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1schnorrsig_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig, jbyteArray jmsg, jbyteArray jpubkey)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[32], msg[32], sig[64];
    secp256k1_xonly_pubkey pubkey;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jsig, 64, sig, "signature")) return 0;
    if (!get_bytes32(penv, jmsg, msg, "message")) return 0;
    if (!get_bytes32(penv, jpubkey, pub, "x-only public key")) return 0;

    result = secp256k1_xonly_pubkey_parse(ctx, &pubkey, pub);
    CHECKRESULT(!result, "secp256k1_xonly_pubkey_parse failed");

    result = secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &pubkey);
    return result;
}

// session_id32: ByteArray, seckey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyagg_cache: ByteArray?, extra_input32: ByteArray?
/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_gen
 * Signature: (J[B[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1gen(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsession_id32, jbyteArray jseckey, jbyteArray jpubkey, jbyteArray jmsg32, jbyteArray jkeyaggcache, jbyteArray jextra_input32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    int result = 0;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_musig_secnonce secnonce;
    unsigned char session_id32[32];
    secp256k1_pubkey pubkey;
    unsigned char seckey[32];
    unsigned char msg32[32];
    secp256k1_musig_keyagg_cache keyaggcache;
    unsigned char extra_input32[32];
    unsigned char nonce[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jsession_id32, session_id32, "session id")) return NULL;

    if (jseckey != NULL) {
        if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    }

    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return NULL;

    if (jmsg32 != NULL) {
        if (!get_bytes32(penv, jmsg32, msg32, "message")) return NULL;
    }

    if (jkeyaggcache != NULL) {
        if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
        CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    }

    if (jextra_input32 != NULL) {
        if (!get_bytes32(penv, jextra_input32, extra_input32, "extra input")) return NULL;
    }

    result = secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce, session_id32,
                                       jseckey == NULL ? NULL : seckey, &pubkey,
                                       jmsg32 == NULL ? NULL : msg32, jkeyaggcache == NULL ? NULL : &keyaggcache, jextra_input32 == NULL ? NULL : extra_input32);
    CHECKRESULT(!result, "secp256k1_musig_nonce_gen failed");

    memcpy(nonce, secnonce.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE);
    result = secp256k1_musig_pubnonce_serialize(ctx, nonce + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, &pubnonce);
    CHECKRESULT(!result, "secp256k1_musig_pubnonce_serialize failed");

    return copy_bytes_to_java(penv, nonce, sizeof(nonce));
}

JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1gen_1counter(JNIEnv* penv, jclass clazz, jlong jctx, jlong jcounter, jbyteArray jseckey, jbyteArray jmsg32, jbyteArray jkeyaggcache, jbyteArray jextra_input32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    int result = 0;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_musig_secnonce secnonce;
    unsigned char seckey[32];
    unsigned char msg32[32];
    secp256k1_keypair keypair;
    secp256k1_musig_keyagg_cache keyaggcache;
    unsigned char extra_input32[32];
    unsigned char nonce[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jseckey, seckey, "secret key")) return NULL;
    result = secp256k1_keypair_create(ctx, &keypair, seckey);
    CHECKRESULT(!result, "secp256k1_keypair_create failed");

    if (jmsg32 != NULL) {
        if (!get_bytes32(penv, jmsg32, msg32, "message")) return NULL;
    }

    if (jkeyaggcache != NULL) {
        if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
        CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    }

    if (jextra_input32 != NULL) {
        if (!get_bytes32(penv, jextra_input32, extra_input32, "extra input")) return NULL;
    }

    result = secp256k1_musig_nonce_gen_counter(ctx, &secnonce, &pubnonce, jcounter,
                                               &keypair,
                                               jmsg32 == NULL ? NULL : msg32, jkeyaggcache == NULL ? NULL : &keyaggcache, jextra_input32 == NULL ? NULL : extra_input32);
    CHECKRESULT(!result, "secp256k1_musig_nonce_gen failed");

    memcpy(nonce, secnonce.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE);
    result = secp256k1_musig_pubnonce_serialize(ctx, nonce + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, &pubnonce);
    CHECKRESULT(!result, "secp256k1_musig_pubnonce_serialize failed");

    return copy_bytes_to_java(penv, nonce, sizeof(nonce));
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_agg
 * Signature: (J[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1agg(JNIEnv* penv, jclass clazz, jlong jctx, jobjectArray jnonces)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char in66[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
    secp256k1_musig_pubnonce* pubnonces;
    secp256k1_musig_pubnonce** pubnonce_ptrs;
    secp256k1_musig_aggnonce combined;
    jbyteArray jnonce;
    size_t count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(jnonces == NULL, "public nonces cannot be null");

    count = (*penv)->GetArrayLength(penv, jnonces);
    CHECKRESULT(count == 0, "public nonces count cannot be 0");

    pubnonces = calloc(count, sizeof(secp256k1_musig_pubnonce));
    CHECKRESULT(pubnonces == NULL, "memory allocation error");
    pubnonce_ptrs = calloc(count, sizeof(secp256k1_musig_pubnonce*));
    CHECKRESULT1(pubnonce_ptrs == NULL, "memory allocation error", free(pubnonces));

    for (i = 0; i < count; i++) {
        pubnonce_ptrs[i] = &(pubnonces[i]);
        jnonce = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jnonces, i);
        if (!get_bytes(penv, jnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, in66, "public nonce")) {
            free(pubnonce_ptrs);
            free(pubnonces);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jnonce);
        result = secp256k1_musig_pubnonce_parse(ctx, pubnonce_ptrs[i], in66);
        CHECKRESULT1(!result, "secp256k1_musig_pubnonce_parse failed", free(pubnonce_ptrs); free(pubnonces));
    }
    result = secp256k1_musig_nonce_agg(ctx, &combined, (const secp256k1_musig_pubnonce* const*)pubnonce_ptrs, count);
    free(pubnonce_ptrs);
    free(pubnonces);
    CHECKRESULT(!result, "secp256k1_musig_nonce_agg failed");

    result = secp256k1_musig_aggnonce_serialize(ctx, in66, &combined);
    CHECKRESULT(!result, "secp256k1_musig_aggnonce_serialize failed");

    return copy_bytes_to_java(penv, in66, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_agg
 * Signature: (J[[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1agg(JNIEnv* penv, jclass clazz, jlong jctx, jobjectArray jpubkeys, jbyteArray jkeyaggcache)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pub[65];
    secp256k1_pubkey* pubkeys;
    secp256k1_pubkey** pubkey_ptrs;
    secp256k1_xonly_pubkey combined;
    secp256k1_musig_keyagg_cache keyaggcache;
    jbyteArray jpubkey;
    size_t count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(jpubkeys == NULL, "public keys cannot be null");
    count = (*penv)->GetArrayLength(penv, jpubkeys);
    CHECKRESULT(count == 0, "pubkeys count cannot be 0");

    if (jkeyaggcache != NULL) {
        if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    }

    pubkeys = calloc(count, sizeof(secp256k1_pubkey));
    CHECKRESULT(pubkeys == NULL, "memory allocation error");
    pubkey_ptrs = calloc(count, sizeof(secp256k1_pubkey*));
    CHECKRESULT1(pubkey_ptrs == NULL, "memory allocation error", free(pubkeys));

    for (i = 0; i < count; i++) {
        pubkey_ptrs[i] = &(pubkeys[i]);
        jpubkey = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpubkeys, i);
        if (!get_pubkey(penv, ctx, jpubkey, pubkey_ptrs[i])) {
            free(pubkey_ptrs);
            free(pubkeys);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jpubkey);
    }
    result = secp256k1_musig_pubkey_agg(ctx, &combined, jkeyaggcache == NULL ? NULL : &keyaggcache, (const secp256k1_pubkey* const*)pubkey_ptrs, count);
    free(pubkey_ptrs);
    free(pubkeys);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_agg failed");
    result = secp256k1_xonly_pubkey_serialize(ctx, pub, &combined);
    CHECKRESULT(!result, "secp256k1_xonly_pubkey_serialize failed");

    jpubkey = (*penv)->NewByteArray(penv, 32);
    CHECKRESULT(jpubkey == NULL, "memory allocation failed");
    (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 32, (const jbyte*)pub);

    if (jkeyaggcache != NULL) {
        (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);
    }
    return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_ec_tweak_add
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1ec_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jkeyaggcache, jbyteArray jtweak32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char tweak32[32], pub[65];
    secp256k1_pubkey pubkey;
    secp256k1_musig_keyagg_cache keyaggcache;
    jbyteArray jpubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");

    if (!get_bytes32(penv, jtweak32, tweak32, "tweak")) return NULL;

    result = secp256k1_musig_pubkey_ec_tweak_add(ctx, &pubkey, &keyaggcache, tweak32);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_ec_tweak_add failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    jpubkey = (*penv)->NewByteArray(penv, 65);
    CHECKRESULT(jpubkey == NULL, "memory allocation failed");
    (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, (const jbyte*)pub);

    (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);

    return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_xonly_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1xonly_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jkeyaggcache, jbyteArray jtweak32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char tweak32[32], pub[65];
    secp256k1_pubkey pubkey;
    secp256k1_musig_keyagg_cache keyaggcache;
    jbyteArray jpubkey;
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    if (!get_bytes32(penv, jtweak32, tweak32, "tweak")) return NULL;

    result = secp256k1_musig_pubkey_xonly_tweak_add(ctx, &pubkey, &keyaggcache, tweak32);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_xonly_tweak_add failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    jpubkey = (*penv)->NewByteArray(penv, 65);
    CHECKRESULT(jpubkey == NULL, "memory allocation failed");
    (*penv)->SetByteArrayRegion(penv, jpubkey, 0, 65, (const jbyte*)pub);

    (*penv)->SetByteArrayRegion(penv, jkeyaggcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, (const jbyte*)keyaggcache.data);

    return jpubkey;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_process
 * Signature: (J[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1process(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jaggnonce, jbyteArray jmsg32, jbyteArray jkeyaggcache)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_keyagg_cache keyaggcache;
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
    unsigned char msg32[32];
    unsigned char buffer[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jaggnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, buffer, "aggregate nonce")) return NULL;
    result = secp256k1_musig_aggnonce_parse(ctx, &aggnonce, buffer);
    CHECKRESULT(!result, "secp256k1_musig_aggnonce_parse failed");

    if (!get_bytes32(penv, jmsg32, msg32, "message")) return NULL;
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");

    result = secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg32, &keyaggcache, NULL);
    CHECKRESULT(!result, "secp256k1_musig_nonce_process failed");

    return copy_bytes_to_java(penv, session.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sign
 * Signature: (J[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sign(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsecnonce, jbyteArray jprivkey, jbyteArray jkeyaggcache, jbyteArray jsession)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_partial_sig psig;
    secp256k1_musig_secnonce secnonce;
    unsigned char seckey[32], sig[32];
    secp256k1_keypair keypair;
    secp256k1_musig_keyagg_cache keyaggcache;
    secp256k1_musig_session session;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jprivkey, seckey, "secret key")) return NULL;
    result = secp256k1_keypair_create(ctx, &keypair, seckey);
    CHECKRESULT(!result, "secp256k1_keypair_create failed");
    if (!get_bytes(penv, jsecnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SECRET_NONCE_SIZE, secnonce.data, "secret nonce")) return NULL;
    CHECKMAGIC(secnonce.data, MUSIG_SECNONCE_MAGIC, "invalid secret nonce");
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, session.data, "session")) return NULL;
    CHECKMAGIC(session.data, MUSIG_SESSION_MAGIC, "invalid session");

    result = secp256k1_musig_partial_sign(ctx, &psig, &secnonce, &keypair, &keyaggcache, &session);
    CHECKRESULT(!result, "secp256k1_musig_partial_sign failed");

    result = secp256k1_musig_partial_sig_serialize(ctx, sig, &psig);
    CHECKRESULT(!result, "secp256k1_musig_partial_sig_serialize failed");

    return copy_bytes_to_java(penv, sig, 32);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sig_verify
 * Signature: (J[B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sig_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpsig, jbyteArray jpubnonce, jbyteArray jpubkey, jbyteArray jkeyaggcache, jbyteArray jsession)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_partial_sig psig;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_pubkey pubkey;
    secp256k1_musig_keyagg_cache keyaggcache;
    secp256k1_musig_session session;
    unsigned char psig_buffer[32];
    unsigned char nonce_buffer[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jpsig, psig_buffer, "partial signature")) return 0;
    if (!get_bytes(penv, jpubnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_PUBLIC_NONCE_SIZE, nonce_buffer, "public nonce")) return 0;
    if (!get_pubkey(penv, ctx, jpubkey, &pubkey)) return 0;
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return 0;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, session.data, "session")) return 0;
    CHECKMAGIC(session.data, MUSIG_SESSION_MAGIC, "invalid session");

    result = secp256k1_musig_partial_sig_parse(ctx, &psig, psig_buffer);
    CHECKRESULT(!result, "secp256k1_musig_partial_sig_parse failed");

    result = secp256k1_musig_pubnonce_parse(ctx, &pubnonce, nonce_buffer);
    CHECKRESULT(!result, "secp256k1_musig_pubnonce_parse failed");

    result = secp256k1_musig_partial_sig_verify(ctx, &psig, &pubnonce, &pubkey, &keyaggcache, &session);
    return result;
}


/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_partial_sig_agg
 * Signature: (J[B[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1partial_1sig_1agg(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsession, jobjectArray jpsigs)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_session session;
    secp256k1_musig_partial_sig* psigs;
    secp256k1_musig_partial_sig** psig_ptrs;
    unsigned char sig64[64];
    jbyteArray jpsig;
    size_t count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, session.data, "session")) return NULL;
    CHECKMAGIC(session.data, MUSIG_SESSION_MAGIC, "invalid session");

    CHECKRESULT(jpsigs == NULL, "partial signatures cannot be null");
    count = (*penv)->GetArrayLength(penv, jpsigs);
    CHECKRESULT(count == 0, "partial sigs count cannot be 0");

    psigs = calloc(count, sizeof(secp256k1_musig_partial_sig));
    CHECKRESULT(psigs == NULL, "memory allocation error");
    psig_ptrs = calloc(count, sizeof(secp256k1_musig_partial_sig*));
    CHECKRESULT1(psig_ptrs == NULL, "memory allocation error", free(psigs));

    for (i = 0; i < count; i++) {
        psig_ptrs[i] = &(psigs[i]);
        jpsig = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpsigs, i);
        if (!get_bytes(penv, jpsig, 32, sig64, "partial signature")) {
            free(psig_ptrs);
            free(psigs);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jpsig);
        result = secp256k1_musig_partial_sig_parse(ctx, psig_ptrs[i], sig64);
        CHECKRESULT1(!result, "secp256k1_musig_partial_sig_parse failed", free(psig_ptrs); free(psigs));
    }
    result = secp256k1_musig_partial_sig_agg(ctx, sig64, &session, (const secp256k1_musig_partial_sig* const*)psig_ptrs, count);
    free(psig_ptrs);
    free(psigs);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_agg failed");

    return copy_bytes_to_java(penv, sig64, 64);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_pubkey_get
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1pubkey_1get(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jkeyaggcache)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_pubkey pubkey;
    secp256k1_musig_keyagg_cache keyaggcache;
    unsigned char pub[65];
    size_t size;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jkeyaggcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_KEYAGG_CACHE_SIZE, keyaggcache.data, "keyagg cache")) return NULL;
    CHECKMAGIC(keyaggcache.data, MUSIG_KEYAGG_CACHE_MAGIC, "invalid keyagg cache");

    result = secp256k1_musig_pubkey_get(ctx, &pubkey, &keyaggcache);
    CHECKRESULT(!result, "secp256k1_musig_pubkey_get failed");

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, pub, &size, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT(!result, "secp256k1_ec_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 65);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_nonce_parity
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1nonce_1parity(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsession)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_musig_session session;
    int nonce_parity = 0;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_MUSIG_SESSION_SIZE, session.data, "session")) return 0;
    CHECKMAGIC(session.data, MUSIG_SESSION_MAGIC, "invalid session");

    result = secp256k1_musig_nonce_parity(ctx, &nonce_parity, &session);
    CHECKRESULT(!result, "secp256k1_musig_nonce_parity failed");

    return nonce_parity;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_adapt
 * Signature: (J[B[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1adapt(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpre_sig64, jbyteArray jsec_adaptor32, jint jnonce_parity)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char pre_sig64[64], sec_adaptor32[32], sig64[64];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jpre_sig64, 64, pre_sig64, "pre-signature")) return NULL;
    if (!get_bytes32(penv, jsec_adaptor32, sec_adaptor32, "adaptor secret")) return NULL;
    CHECKRESULT(jnonce_parity < 0 || jnonce_parity > 1, "nonce parity must be 0 or 1");

    result = secp256k1_musig_adapt(ctx, sig64, pre_sig64, sec_adaptor32, jnonce_parity);
    CHECKRESULT(!result, "secp256k1_musig_adapt failed");

    return copy_bytes_to_java(penv, sig64, 64);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_musig_extract_adaptor
 * Signature: (J[B[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1musig_1extract_1adaptor(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsig64, jbyteArray jpre_sig64, jint jnonce_parity)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char sig64[64], pre_sig64[64], sec_adaptor32[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jsig64, 64, sig64, "signature")) return NULL;
    if (!get_bytes(penv, jpre_sig64, 64, pre_sig64, "pre-signature")) return NULL;
    CHECKRESULT(jnonce_parity < 0 || jnonce_parity > 1, "nonce parity must be 0 or 1");

    result = secp256k1_musig_extract_adaptor(ctx, sec_adaptor32, sig64, pre_sig64, jnonce_parity);
    CHECKRESULT(!result, "secp256k1_musig_extract_adaptor failed");

    return copy_bytes_to_java(penv, sec_adaptor32, 32);
}


/* The frost_xxx() helpers below all return 1 on success, and on failure throw a
 * Secp256k1Exception describing what was wrong with the argument and return 0.
 * They must not be called when an exception is already pending: callers are
 * expected to return as soon as one of them fails. */

/* Copies a java byte array of arbitrary size into a freshly malloc'd buffer (a NULL
 * array becomes a NULL buffer of size 0). The caller must free the buffer. */
static inline int get_var_bytes(JNIEnv* penv, jbyteArray jbytes, unsigned char** out, size_t* out_size, const char* name)
{
    jsize len;
    unsigned char* bytes;

    if (jbytes == NULL) {
        *out = NULL;
        *out_size = 0;
        return 1;
    }
    len = (*penv)->GetArrayLength(penv, jbytes);
    bytes = malloc(len > 0 ? (size_t)len : 1);
    if (bytes == NULL) {
        JNI_ThrowSecp256k1(penv, "memory allocation failed");
        return 0;
    }
    (*penv)->GetByteArrayRegion(penv, jbytes, 0, len, (jbyte*)bytes);
    *out = bytes;
    *out_size = (size_t)len;
    return 1;
}

/* Copies a java int array into a freshly malloc'd uint32_t array. Signer identifiers are
 * small non-negative values (at most SECP256K1_FROST_MAX_PARTICIPANTS - 1), so negative
 * entries are rejected here instead of wrapping around. The caller must free the array. */
static inline uint32_t* get_signer_ids(JNIEnv* penv, jintArray jids, size_t* count)
{
    jsize i, n;
    jint* elems;
    uint32_t* ids;

    n = (*penv)->GetArrayLength(penv, jids);
    elems = (*penv)->GetIntArrayElements(penv, jids, NULL);
    if (elems == NULL) {
        JNI_ThrowSecp256k1(penv, "memory allocation failed");
        return NULL;
    }
    ids = malloc(sizeof(uint32_t) * (n > 0 ? (size_t)n : 1));
    if (ids == NULL) {
        (*penv)->ReleaseIntArrayElements(penv, jids, elems, JNI_ABORT);
        JNI_ThrowSecp256k1(penv, "memory allocation failed");
        return NULL;
    }
    for (i = 0; i < n; i++) {
        if (elems[i] < 0) {
            free(ids);
            (*penv)->ReleaseIntArrayElements(penv, jids, elems, JNI_ABORT);
            JNI_ThrowSecp256k1(penv, "signer ids cannot be negative");
            return NULL;
        }
        ids[i] = (uint32_t)elems[i];
    }
    (*penv)->ReleaseIntArrayElements(penv, jids, elems, JNI_ABORT);
    *count = (size_t)n;
    return ids;
}

/* Parses an array of serialized public keys into a freshly malloc'd secp256k1_pubkey
 * array. The caller must free the array. */
static inline secp256k1_pubkey* get_pubshares(JNIEnv* penv, const secp256k1_context* ctx, jobjectArray jpubshares, size_t* count)
{
    secp256k1_pubkey* pubshares;
    jbyteArray jpubshare;
    jsize i, n;

    n = (*penv)->GetArrayLength(penv, jpubshares);
    pubshares = calloc(n > 0 ? (size_t)n : 1, sizeof(secp256k1_pubkey));
    if (pubshares == NULL) {
        JNI_ThrowSecp256k1(penv, "memory allocation failed");
        return NULL;
    }
    for (i = 0; i < n; i++) {
        jpubshare = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpubshares, i);
        if (!get_pubkey(penv, ctx, jpubshare, &pubshares[i])) {
            (*penv)->DeleteLocalRef(penv, jpubshare);
            free(pubshares);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jpubshare);
    }
    *count = (size_t)n;
    return pubshares;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_trusted_dealer_keygen
 * Signature: (J[BII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1trusted_1dealer_1keygen(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jthreshseckey, jint jnparticipants, jint jthreshold)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char threshseckey[32];
    unsigned char* secshares;
    unsigned char* out;
    secp256k1_pubkey thresh_pk;
    secp256k1_pubkey* pubshares;
    size_t n, i, size;
    int result = 0;
    jbyteArray jout;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jthreshseckey, threshseckey, "threshold secret key")) return NULL;
    CHECKRESULT(jnparticipants < 1 || jnparticipants > SECP256K1_FROST_MAX_PARTICIPANTS, "invalid number of participants");
    CHECKRESULT(jthreshold < 1 || jthreshold > jnparticipants, "invalid threshold");
    n = (size_t)jnparticipants;

    secshares = malloc(32 * n);
    CHECKRESULT(secshares == NULL, "memory allocation failed");
    pubshares = calloc(n, sizeof(secp256k1_pubkey));
    CHECKRESULT1(pubshares == NULL, "memory allocation failed", free(secshares));
    out = malloc(65 + 32 * n + 65 * n);
    CHECKRESULT1(out == NULL, "memory allocation failed", free(secshares); free(pubshares));

    result = secp256k1_frost_trusted_dealer_keygen(ctx, secshares, &thresh_pk, pubshares, n, (uint32_t)jthreshold, threshseckey);
    CHECKRESULT1(!result, "secp256k1_frost_trusted_dealer_keygen failed", free(secshares); free(pubshares); free(out));

    size = 65;
    result = secp256k1_ec_pubkey_serialize(ctx, out, &size, &thresh_pk, SECP256K1_EC_UNCOMPRESSED);
    CHECKRESULT1(!result, "secp256k1_ec_pubkey_serialize failed", free(secshares); free(pubshares); free(out));
    memcpy(out + 65, secshares, 32 * n);
    for (i = 0; i < n; i++) {
        size = 65;
        result = secp256k1_ec_pubkey_serialize(ctx, out + 65 + 32 * n + 65 * i, &size, &pubshares[i], SECP256K1_EC_UNCOMPRESSED);
        CHECKRESULT1(!result, "secp256k1_ec_pubkey_serialize failed", free(secshares); free(pubshares); free(out));
    }

    jout = copy_bytes_to_java(penv, out, 65 + 32 * n + 65 * n);
    free(secshares);
    free(pubshares);
    free(out);
    return jout;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_threshold_info_validate
 * Signature: (J[B[[BI)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1threshold_1info_1validate(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jthreshpk, jobjectArray jpubshares, jint jthreshold)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_pubkey thresh_pk;
    secp256k1_pubkey* pubshares;
    size_t n;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jthreshpk, &thresh_pk)) return 0;
    CHECKRESULT(jpubshares == NULL, "public shares cannot be null");
    pubshares = get_pubshares(penv, ctx, jpubshares, &n);
    if (pubshares == NULL) return 0;
    CHECKRESULT1(n < 1, "public shares cannot be empty", free(pubshares));
    CHECKRESULT1(jthreshold < 1 || (size_t)jthreshold > n, "invalid threshold", free(pubshares));

    result = secp256k1_frost_threshold_info_validate(ctx, &thresh_pk, pubshares, n, (uint32_t)jthreshold);
    free(pubshares);
    return result;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_tweak_cache_init
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1tweak_1cache_1init(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jthreshpk)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_pubkey thresh_pk;
    secp256k1_frost_tweak_cache cache;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_pubkey(penv, ctx, jthreshpk, &thresh_pk)) return NULL;

    result = secp256k1_frost_tweak_cache_init(ctx, &cache, &thresh_pk);
    CHECKRESULT(!result, "secp256k1_frost_tweak_cache_init failed");

    return copy_bytes_to_java(penv, cache.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_TWEAK_CACHE_SIZE);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_tweaked_pubkey_get
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1tweaked_1pubkey_1get(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jtweakcache)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_frost_tweak_cache cache;
    secp256k1_xonly_pubkey tweaked_pk;
    unsigned char pub[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jtweakcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_TWEAK_CACHE_SIZE, cache.data, "tweak cache")) return NULL;
    CHECKMAGIC(cache.data, FROST_TWEAK_CACHE_MAGIC, "invalid tweak cache");

    result = secp256k1_frost_tweaked_pubkey_get(ctx, &tweaked_pk, &cache);
    CHECKRESULT(!result, "secp256k1_frost_tweaked_pubkey_get failed");

    result = secp256k1_xonly_pubkey_serialize(ctx, pub, &tweaked_pk);
    CHECKRESULT(!result, "secp256k1_xonly_pubkey_serialize failed");

    return copy_bytes_to_java(penv, pub, 32);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_pubkey_xonly_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1pubkey_1xonly_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jtweakcache, jbyteArray jtweak32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_frost_tweak_cache cache;
    secp256k1_xonly_pubkey tweaked_pk;
    unsigned char tweak32[32], pub[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jtweakcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_TWEAK_CACHE_SIZE, cache.data, "tweak cache")) return NULL;
    CHECKMAGIC(cache.data, FROST_TWEAK_CACHE_MAGIC, "invalid tweak cache");
    if (!get_bytes32(penv, jtweak32, tweak32, "tweak")) return NULL;

    result = secp256k1_frost_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &cache, tweak32);
    CHECKRESULT(!result, "secp256k1_frost_pubkey_xonly_tweak_add failed");

    result = secp256k1_xonly_pubkey_serialize(ctx, pub, &tweaked_pk);
    CHECKRESULT(!result, "secp256k1_xonly_pubkey_serialize failed");

    /* write the updated cache back into the caller's array */
    (*penv)->SetByteArrayRegion(penv, jtweakcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_TWEAK_CACHE_SIZE, (const jbyte*)cache.data);

    return copy_bytes_to_java(penv, pub, 32);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_pubkey_ec_tweak_add
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1pubkey_1ec_1tweak_1add(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jtweakcache, jbyteArray jtweak32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_frost_tweak_cache cache;
    secp256k1_xonly_pubkey tweaked_pk;
    unsigned char tweak32[32], pub[32];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jtweakcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_TWEAK_CACHE_SIZE, cache.data, "tweak cache")) return NULL;
    CHECKMAGIC(cache.data, FROST_TWEAK_CACHE_MAGIC, "invalid tweak cache");
    if (!get_bytes32(penv, jtweak32, tweak32, "tweak")) return NULL;

    result = secp256k1_frost_pubkey_ec_tweak_add(ctx, &tweaked_pk, &cache, tweak32);
    CHECKRESULT(!result, "secp256k1_frost_pubkey_ec_tweak_add failed");

    result = secp256k1_xonly_pubkey_serialize(ctx, pub, &tweaked_pk);
    CHECKRESULT(!result, "secp256k1_xonly_pubkey_serialize failed");

    /* write the updated cache back into the caller's array */
    (*penv)->SetByteArrayRegion(penv, jtweakcache, 0, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_TWEAK_CACHE_SIZE, (const jbyte*)cache.data);

    return copy_bytes_to_java(penv, pub, 32);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_nonce_gen
 * Signature: (J[B[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1nonce_1gen(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsession_secrand32, jbyteArray jsecshare32, jbyteArray jpubshare, jbyteArray jthreshpk32, jbyteArray jmsg, jbyteArray jextra_in)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_frost_secnonce secnonce;
    secp256k1_frost_pubnonce pubnonce;
    secp256k1_pubkey pubshare;
    unsigned char session_secrand32[32], secshare32[32], threshpk32[32];
    unsigned char* msg = NULL;
    unsigned char* extra_in = NULL;
    size_t msglen = 0, extra_in_len = 0;
    unsigned char nonce[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_SECRET_NONCE_SIZE + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE];
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jsession_secrand32, session_secrand32, "session random")) return NULL;
    if (jsecshare32 != NULL && !get_bytes32(penv, jsecshare32, secshare32, "secret share")) return NULL;
    if (jpubshare != NULL && !get_pubkey(penv, ctx, jpubshare, &pubshare)) return NULL;
    if (jthreshpk32 != NULL && !get_bytes32(penv, jthreshpk32, threshpk32, "threshold public key")) return NULL;
    if (!get_var_bytes(penv, jmsg, &msg, &msglen, "message")) return NULL;
    if (!get_var_bytes(penv, jextra_in, &extra_in, &extra_in_len, "extra input")) {
        free(msg);
        return NULL;
    }

    result = secp256k1_frost_nonce_gen(ctx, &secnonce, &pubnonce, session_secrand32,
                                       jsecshare32 == NULL ? NULL : secshare32,
                                       jpubshare == NULL ? NULL : &pubshare,
                                       jthreshpk32 == NULL ? NULL : threshpk32,
                                       msg, msglen, extra_in, extra_in_len);
    free(msg);
    free(extra_in);
    CHECKRESULT(!result, "secp256k1_frost_nonce_gen failed");

    memcpy(nonce, secnonce.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_SECRET_NONCE_SIZE);
    result = secp256k1_frost_pubnonce_serialize(ctx, nonce + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_SECRET_NONCE_SIZE, &pubnonce);
    CHECKRESULT(!result, "secp256k1_frost_pubnonce_serialize failed");

    return copy_bytes_to_java(penv, nonce, sizeof(nonce));
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_nonce_agg
 * Signature: (J[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1nonce_1agg(JNIEnv* penv, jclass clazz, jlong jctx, jobjectArray jnonces)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char in66[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE];
    secp256k1_frost_pubnonce* pubnonces;
    secp256k1_frost_pubnonce** pubnonce_ptrs;
    secp256k1_frost_aggnonce combined;
    jbyteArray jnonce;
    size_t count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    CHECKRESULT(jnonces == NULL, "public nonces cannot be null");

    count = (*penv)->GetArrayLength(penv, jnonces);
    CHECKRESULT(count == 0, "public nonces count cannot be 0");

    pubnonces = calloc(count, sizeof(secp256k1_frost_pubnonce));
    CHECKRESULT(pubnonces == NULL, "memory allocation error");
    pubnonce_ptrs = calloc(count, sizeof(secp256k1_frost_pubnonce*));
    CHECKRESULT1(pubnonce_ptrs == NULL, "memory allocation error", free(pubnonces));

    for (i = 0; i < count; i++) {
        pubnonce_ptrs[i] = &(pubnonces[i]);
        jnonce = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jnonces, i);
        if (!get_bytes(penv, jnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE, in66, "public nonce")) {
            free(pubnonce_ptrs);
            free(pubnonces);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jnonce);
        result = secp256k1_frost_pubnonce_parse(ctx, pubnonce_ptrs[i], in66);
        CHECKRESULT1(!result, "secp256k1_frost_pubnonce_parse failed", free(pubnonce_ptrs); free(pubnonces));
    }
    result = secp256k1_frost_nonce_agg(ctx, &combined, NULL, (const secp256k1_frost_pubnonce* const*)pubnonce_ptrs, count);
    free(pubnonce_ptrs);
    free(pubnonces);
    CHECKRESULT(!result, "secp256k1_frost_nonce_agg failed");

    result = secp256k1_frost_aggnonce_serialize(ctx, in66, &combined);
    CHECKRESULT(!result, "secp256k1_frost_aggnonce_serialize failed");

    return copy_bytes_to_java(penv, in66, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_session_init
 * Signature: (J[B[I[[BII[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1session_1init(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jaggnonce, jintArray jids, jobjectArray jpubshares, jint jnparticipants, jint jthreshold, jbyteArray jtweakcache, jbyteArray jmsg)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char in66[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE];
    secp256k1_frost_aggnonce aggnonce;
    secp256k1_frost_tweak_cache tweakcache;
    secp256k1_frost_session session;
    secp256k1_pubkey* pubshares = NULL;
    uint32_t* ids = NULL;
    unsigned char* msg = NULL;
    size_t n_pubshares = 0, n_signers = 0, msglen = 0;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jaggnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE, in66, "aggregate nonce")) return NULL;
    result = secp256k1_frost_aggnonce_parse(ctx, &aggnonce, in66);
    CHECKRESULT(!result, "secp256k1_frost_aggnonce_parse failed");

    CHECKRESULT(jids == NULL, "signer ids cannot be null");
    ids = get_signer_ids(penv, jids, &n_signers);
    if (ids == NULL) return NULL;
    CHECKRESULT1(n_signers < 1, "signer ids cannot be empty", free(ids));

    if (jpubshares != NULL) {
        pubshares = get_pubshares(penv, ctx, jpubshares, &n_pubshares);
        if (pubshares == NULL) {
            free(ids);
            return NULL;
        }
        CHECKRESULT1(n_pubshares != n_signers, "public shares count must match signer ids count", free(ids); free(pubshares));
    }

    CHECKRESULT1(jnparticipants < 1 || jnparticipants > SECP256K1_FROST_MAX_PARTICIPANTS, "invalid number of participants", free(ids); free(pubshares));
    CHECKRESULT1(jthreshold < 1 || jthreshold > jnparticipants, "invalid threshold", free(ids); free(pubshares));
    CHECKRESULT1((jint)n_signers < jthreshold || (jint)n_signers > jnparticipants, "invalid number of signers", free(ids); free(pubshares));

    if (!get_bytes(penv, jtweakcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_TWEAK_CACHE_SIZE, tweakcache.data, "tweak cache")) {
        free(ids);
        free(pubshares);
        return NULL;
    }
    if (memcmp(tweakcache.data, FROST_TWEAK_CACHE_MAGIC, 4) != 0) {
        free(ids);
        free(pubshares);
        JNI_ThrowSecp256k1(penv, "invalid tweak cache");
        return NULL;
    }
    if (!get_var_bytes(penv, jmsg, &msg, &msglen, "message")) {
        free(ids);
        free(pubshares);
        return NULL;
    }

    result = secp256k1_frost_session_init(ctx, &session, &aggnonce, ids, pubshares, n_signers, (size_t)jnparticipants, (uint32_t)jthreshold, &tweakcache, msg, msglen);
    free(ids);
    free(pubshares);
    free(msg);
    CHECKRESULT(!result, "secp256k1_frost_session_init failed");

    return copy_bytes_to_java(penv, session.data, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_SESSION_SIZE);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_sign
 * Signature: (J[B[B[B[I[[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1sign(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsecnonce, jbyteArray jsecshare32, jbyteArray jsession, jintArray jids, jobjectArray jpubshares, jint jmyid)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_frost_secnonce secnonce;
    secp256k1_frost_session session;
    secp256k1_frost_partial_sig psig;
    secp256k1_pubkey* pubshares = NULL;
    uint32_t* ids = NULL;
    unsigned char secshare32[32], sig[32];
    size_t n_pubshares = 0, n_signers = 0;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jsecnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_SECRET_NONCE_SIZE, secnonce.data, "secret nonce")) return NULL;
    CHECKMAGIC(secnonce.data, FROST_SECNONCE_MAGIC, "invalid secret nonce");
    if (!get_bytes32(penv, jsecshare32, secshare32, "secret share")) return NULL;
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_SESSION_SIZE, session.data, "session")) return NULL;
    CHECKMAGIC(session.data, FROST_SESSION_MAGIC, "invalid session");

    CHECKRESULT(jids == NULL, "signer ids cannot be null");
    ids = get_signer_ids(penv, jids, &n_signers);
    if (ids == NULL) return NULL;
    CHECKRESULT1(n_signers < 1, "signer ids cannot be empty", free(ids));

    if (jpubshares != NULL) {
        pubshares = get_pubshares(penv, ctx, jpubshares, &n_pubshares);
        if (pubshares == NULL) {
            free(ids);
            return NULL;
        }
        CHECKRESULT1(n_pubshares != n_signers, "public shares count must match signer ids count", free(ids); free(pubshares));
    }

    result = secp256k1_frost_sign(ctx, &psig, &secnonce, secshare32, &session, ids, pubshares, n_signers, (uint32_t)jmyid);
    free(ids);
    free(pubshares);
    CHECKRESULT(!result, "secp256k1_frost_sign failed");

    result = secp256k1_frost_partial_sig_serialize(ctx, sig, &psig);
    CHECKRESULT(!result, "secp256k1_frost_partial_sig_serialize failed");

    return copy_bytes_to_java(penv, sig, 32);
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_deterministic_sign
 * Signature: (J[BI[B[I[[BII[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1deterministic_1sign(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsecshare32, jint jmyid, jbyteArray jaggothernonce, jintArray jids, jobjectArray jpubshares, jint jnparticipants, jint jthreshold, jbyteArray jtweakcache, jbyteArray jmsg, jbyteArray jauxrand32)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    unsigned char in66[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE];
    secp256k1_frost_aggnonce aggothernonce;
    secp256k1_frost_tweak_cache tweakcache;
    secp256k1_frost_partial_sig psig;
    secp256k1_frost_pubnonce pubnonce;
    secp256k1_pubkey* pubshares = NULL;
    uint32_t* ids = NULL;
    unsigned char* msg = NULL;
    unsigned char secshare32[32], auxrand32[32];
    unsigned char out[32 + fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE];
    size_t n_pubshares = 0, n_signers = 0, msglen = 0;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jsecshare32, secshare32, "secret share")) return NULL;

    if (jaggothernonce != NULL) {
        if (!get_bytes(penv, jaggothernonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE, in66, "aggregate nonce")) return NULL;
        result = secp256k1_frost_aggnonce_parse(ctx, &aggothernonce, in66);
        CHECKRESULT(!result, "secp256k1_frost_aggnonce_parse failed");
    }

    CHECKRESULT(jids == NULL, "signer ids cannot be null");
    ids = get_signer_ids(penv, jids, &n_signers);
    if (ids == NULL) return NULL;
    CHECKRESULT1(n_signers < 1, "signer ids cannot be empty", free(ids));

    if (jpubshares != NULL) {
        pubshares = get_pubshares(penv, ctx, jpubshares, &n_pubshares);
        if (pubshares == NULL) {
            free(ids);
            return NULL;
        }
        CHECKRESULT1(n_pubshares != n_signers, "public shares count must match signer ids count", free(ids); free(pubshares));
    }

    CHECKRESULT1(jnparticipants < 1 || jnparticipants > SECP256K1_FROST_MAX_PARTICIPANTS, "invalid number of participants", free(ids); free(pubshares));
    CHECKRESULT1(jthreshold < 1 || jthreshold > jnparticipants, "invalid threshold", free(ids); free(pubshares));

    if (!get_bytes(penv, jtweakcache, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_TWEAK_CACHE_SIZE, tweakcache.data, "tweak cache")) {
        free(ids);
        free(pubshares);
        return NULL;
    }
    if (memcmp(tweakcache.data, FROST_TWEAK_CACHE_MAGIC, 4) != 0) {
        free(ids);
        free(pubshares);
        JNI_ThrowSecp256k1(penv, "invalid tweak cache");
        return NULL;
    }
    if (!get_var_bytes(penv, jmsg, &msg, &msglen, "message")) {
        free(ids);
        free(pubshares);
        return NULL;
    }
    if (jauxrand32 != NULL && !get_bytes32(penv, jauxrand32, auxrand32, "auxiliary random data")) {
        free(ids);
        free(pubshares);
        free(msg);
        return NULL;
    }

    result = secp256k1_frost_deterministic_sign(ctx, &psig, &pubnonce, secshare32, (uint32_t)jmyid,
                                                jaggothernonce == NULL ? NULL : &aggothernonce,
                                                ids, pubshares, n_signers, (size_t)jnparticipants, (uint32_t)jthreshold,
                                                &tweakcache, msg, msglen, jauxrand32 == NULL ? NULL : auxrand32);
    free(ids);
    free(pubshares);
    free(msg);
    CHECKRESULT(!result, "secp256k1_frost_deterministic_sign failed");

    result = secp256k1_frost_partial_sig_serialize(ctx, out, &psig);
    CHECKRESULT(!result, "secp256k1_frost_partial_sig_serialize failed");
    result = secp256k1_frost_pubnonce_serialize(ctx, out + 32, &pubnonce);
    CHECKRESULT(!result, "secp256k1_frost_pubnonce_serialize failed");

    return copy_bytes_to_java(penv, out, sizeof(out));
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_partial_sig_verify
 * Signature: (J[B[B[B[B[II)I
 */
JNIEXPORT jint JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1partial_1sig_1verify(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jpsig, jbyteArray jpubnonce, jbyteArray jpubshare, jbyteArray jsession, jintArray jids, jint jsignerindex)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_frost_partial_sig psig;
    secp256k1_frost_pubnonce pubnonce;
    secp256k1_pubkey pubshare;
    secp256k1_frost_session session;
    uint32_t* ids = NULL;
    unsigned char psig_buffer[32];
    unsigned char nonce_buffer[fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE];
    size_t n_signers = 0;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes32(penv, jpsig, psig_buffer, "partial signature")) return 0;
    if (!get_bytes(penv, jpubnonce, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_PUBLIC_NONCE_SIZE, nonce_buffer, "public nonce")) return 0;
    if (!get_pubkey(penv, ctx, jpubshare, &pubshare)) return 0;
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_SESSION_SIZE, session.data, "session")) return 0;
    CHECKMAGIC(session.data, FROST_SESSION_MAGIC, "invalid session");

    CHECKRESULT(jids == NULL, "signer ids cannot be null");
    ids = get_signer_ids(penv, jids, &n_signers);
    if (ids == NULL) return 0;
    CHECKRESULT1(n_signers < 1, "signer ids cannot be empty", free(ids));
    CHECKRESULT1(jsignerindex < 0 || (size_t)jsignerindex >= n_signers, "invalid signer index", free(ids));

    result = secp256k1_frost_partial_sig_parse(ctx, &psig, psig_buffer);
    CHECKRESULT1(!result, "secp256k1_frost_partial_sig_parse failed", free(ids));
    result = secp256k1_frost_pubnonce_parse(ctx, &pubnonce, nonce_buffer);
    CHECKRESULT1(!result, "secp256k1_frost_pubnonce_parse failed", free(ids));

    result = secp256k1_frost_partial_sig_verify(ctx, &psig, &pubnonce, &pubshare, &session, ids, n_signers, (size_t)jsignerindex);
    free(ids);
    return result;
}

/*
 * Class:     fr_acinq_secp256k1_Secp256k1CFunctions
 * Method:    secp256k1_frost_partial_sig_agg
 * Signature: (J[B[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_fr_acinq_secp256k1_Secp256k1CFunctions_secp256k1_1frost_1partial_1sig_1agg(JNIEnv* penv, jclass clazz, jlong jctx, jbyteArray jsession, jobjectArray jpsigs)
{
    const secp256k1_context* ctx = (const secp256k1_context*)jctx;
    secp256k1_frost_session session;
    secp256k1_frost_partial_sig* psigs;
    secp256k1_frost_partial_sig** psig_ptrs;
    unsigned char sig64[64];
    jbyteArray jpsig;
    size_t count;
    size_t i;
    int result = 0;

    CHECKRESULT(ctx == NULL, "secp256k1 context cannot be null");
    if (!get_bytes(penv, jsession, fr_acinq_secp256k1_Secp256k1CFunctions_SECP256K1_FROST_SESSION_SIZE, session.data, "session")) return NULL;
    CHECKMAGIC(session.data, FROST_SESSION_MAGIC, "invalid session");

    CHECKRESULT(jpsigs == NULL, "partial signatures cannot be null");
    count = (*penv)->GetArrayLength(penv, jpsigs);
    CHECKRESULT(count == 0, "partial sigs count cannot be 0");

    psigs = calloc(count, sizeof(secp256k1_frost_partial_sig));
    CHECKRESULT(psigs == NULL, "memory allocation error");
    psig_ptrs = calloc(count, sizeof(secp256k1_frost_partial_sig*));
    CHECKRESULT1(psig_ptrs == NULL, "memory allocation error", free(psigs));

    for (i = 0; i < count; i++) {
        psig_ptrs[i] = &(psigs[i]);
        jpsig = (jbyteArray)(*penv)->GetObjectArrayElement(penv, jpsigs, i);
        if (!get_bytes(penv, jpsig, 32, sig64, "partial signature")) {
            free(psig_ptrs);
            free(psigs);
            return NULL;
        }
        (*penv)->DeleteLocalRef(penv, jpsig);
        result = secp256k1_frost_partial_sig_parse(ctx, psig_ptrs[i], sig64);
        CHECKRESULT1(!result, "secp256k1_frost_partial_sig_parse failed", free(psig_ptrs); free(psigs));
    }
    result = secp256k1_frost_partial_sig_agg(ctx, sig64, NULL, &session, (const secp256k1_frost_partial_sig* const*)psig_ptrs, count);
    free(psig_ptrs);
    free(psigs);
    CHECKRESULT(!result, "secp256k1_frost_partial_sig_agg failed");

    return copy_bytes_to_java(penv, sig64, 64);
}
