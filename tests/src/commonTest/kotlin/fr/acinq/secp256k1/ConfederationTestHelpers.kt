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
