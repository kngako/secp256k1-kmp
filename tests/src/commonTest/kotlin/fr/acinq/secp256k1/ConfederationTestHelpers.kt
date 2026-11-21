package fr.acinq.secp256k1

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal fun JsonElement.confederationHex(name: String): ByteArray = Hex.decode(jsonObject[name]!!.jsonPrimitive.content)

internal fun confederationVectors(): JsonElement = readResourceAsJson("confederation/vectors.json")

internal fun JsonElement.confederationHexMap(name: String): Map<String, ByteArray> =
    jsonObject[name]!!.jsonObject.mapValues { (_, value) -> Hex.decode(value.jsonPrimitive.content) }

internal fun confederationHostSecret(role: Int): ByteArray = ByteArray(32).also {
    it[30] = 0x10
    it[31] = (role + 1).toByte()
}

internal fun ByteArray.confederationReadU32(offset: Int): Int =
    ((this[offset].toInt() and 0xff) shl 24) or
        ((this[offset + 1].toInt() and 0xff) shl 16) or
        ((this[offset + 2].toInt() and 0xff) shl 8) or
        (this[offset + 3].toInt() and 0xff)

internal fun ByteArray.confederationWriteU32(offset: Int, value: Int) {
    this[offset] = (value ushr 24).toByte()
    this[offset + 1] = (value ushr 16).toByte()
    this[offset + 2] = (value ushr 8).toByte()
    this[offset + 3] = value.toByte()
}

internal fun ByteArray.confederationWriteU64(offset: Int, value: ULong) {
    confederationWriteU32(offset, (value shr 32).toInt())
    confederationWriteU32(offset + 4, value.toInt())
}

internal fun confederationEntityOffsets(rpd: ByteArray): IntArray {
    require(rpd.size >= 96)
    val groups = rpd.confederationReadU32(60)
    val offsets = ArrayList<Int>()
    var offset = 96
    repeat(groups) {
        val roles = rpd.confederationReadU32(offset + 16)
        repeat(roles) { role ->
            offsets += offset + 20 + 69 * role + 4
        }
        offset += 20 + 69 * roles
    }
    require(offset == rpd.size)
    return offsets.toIntArray()
}

internal fun confederationShareEntity(rpd: ByteArray, targetRole: Int, sourceRole: Int): ByteArray {
    val offsets = confederationEntityOffsets(rpd)
    return rpd.copyOf().also {
        rpd.copyInto(it, offsets[targetRole], offsets[sourceRole], offsets[sourceRole] + 32)
    }
}


internal fun confederationMaximumRpd(): ByteArray {
    val rpd = ByteArray(Secp256k1.CONFEDERATION_RPD_MAX_SERIALIZED_SIZE)
    "CRPD".forEachIndexed { index, char -> rpd[index] = char.code.toByte() }
    rpd.confederationWriteU32(4, Secp256k1.CONFEDERATION_VERSION)
    rpd.confederationWriteU64(8, 1uL)
    rpd.confederationWriteU64(16, 1uL)
    rpd.confederationWriteU32(56, Secp256k1.CONFEDERATION_MAX_GROUPS)
    rpd.confederationWriteU32(60, Secp256k1.CONFEDERATION_MAX_GROUPS)
    var offset = 96
    repeat(Secp256k1.CONFEDERATION_MAX_GROUPS) { group ->
        rpd.confederationWriteU32(offset, group)
        rpd.confederationWriteU64(offset + 4, 1uL)
        rpd.confederationWriteU32(offset + 12, 2)
        rpd.confederationWriteU32(offset + 16, 2)
        offset += 20
        repeat(2) { admin ->
            val role = 2 * group + admin
            rpd.confederationWriteU32(offset, admin)
            rpd.confederationWriteU32(offset + 32, role + 1)
            val hostSecret = ByteArray(32).also { it.confederationWriteU32(28, role + 1) }
            val hostPubkey = Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(hostSecret))
            hostPubkey.copyInto(rpd, offset + 36)
            hostSecret.fill(0)
            offset += 69
        }
    }
    require(offset == rpd.size)
    require(confederationEntityOffsets(rpd).size == Secp256k1.CONFEDERATION_MAX_ROLES)
    return rpd
}
