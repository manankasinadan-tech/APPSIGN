package com.hephaistos.appsign.core.apk

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * Pure-JVM APK ZIP entry aligner (equivalent to `zipalign -p 4`) so APKs are properly aligned
 * prior to v2/v3/v4 signing on both Android devices and Linux/Termux without relying on native
 * `zipalign` binaries.
 *
 * Uncompressed (`STORED`) entries are aligned to 4096 bytes for native shared libraries (`.so`) and
 * 4 bytes for all other uncompressed entries by adding zero-filled padding in the local header extra
 * field.
 */
object PureJvmZipAligner {
  private const val LFH_FIXED_SIZE = 30
  private const val STORED = ZipEntry.STORED

  fun align(inputApk: File, outputApk: File): Boolean {
    outputApk.parentFile?.mkdirs()
    ZipFile(inputApk).use { zip ->
      val entries = zip.entries().toList()
      ZipOutputStream(BufferedOutputStream(FileOutputStream(outputApk))).use { zos ->
        var currentOffset = 0L
        val buffer = ByteArray(16 * 1024)
        for (entry in entries) {
          val clone = ZipEntry(entry.name)
          clone.method = entry.method
          clone.time = entry.time
          if (entry.comment != null) clone.comment = entry.comment

          val nameBytes = entry.name.toByteArray(Charsets.UTF_8)
          val originalExtra = entry.extra ?: ByteArray(0)

          if (entry.method == STORED) {
            clone.size = entry.size
            clone.compressedSize = entry.compressedSize
            clone.crc = entry.crc

            val alignment = if (entry.name.endsWith(".so", ignoreCase = true)) 4096 else 4
            val baseHeaderSize = LFH_FIXED_SIZE + nameBytes.size + originalExtra.size
            val dataOffset = currentOffset + baseHeaderSize
            val remainder = (dataOffset % alignment).toInt()
            val padding = if (remainder == 0) 0 else alignment - remainder

            if (padding > 0) {
              val paddedExtra = ByteArray(originalExtra.size + padding)
              System.arraycopy(originalExtra, 0, paddedExtra, 0, originalExtra.size)
              clone.extra = paddedExtra
            } else if (originalExtra.isNotEmpty()) {
              clone.extra = originalExtra
            }
          } else {
            if (originalExtra.isNotEmpty()) clone.extra = originalExtra
          }

          zos.putNextEntry(clone)
          zip.getInputStream(entry).use { input ->
            while (true) {
              val read = input.read(buffer)
              if (read <= 0) break
              zos.write(buffer, 0, read)
            }
          }
          zos.closeEntry()

          val extraLen = clone.extra?.size ?: 0
          val lfhLen = LFH_FIXED_SIZE + nameBytes.size + extraLen
          val payloadLen = clone.compressedSize.coerceAtLeast(0L)
          val descriptorLen = if (entry.method == STORED) 0L else 16L
          currentOffset += lfhLen + payloadLen + descriptorLen
        }
      }
    }
    return isAligned(outputApk)
  }

  fun isAligned(apkFile: File): Boolean {
    return try {
      RandomAccessFile(apkFile, "r").use { raf ->
        val len = raf.length()
        if (len < 22) return false
        val searchStart = (len - 65557).coerceAtLeast(0L)
        val tailLen = (len - searchStart).toInt()
        val tail = ByteArray(tailLen)
        raf.seek(searchStart)
        raf.readFully(tail)

        var eocdPos = -1
        for (i in tailLen - 22 downTo 0) {
          if (
            tail[i] == 0x50.toByte() &&
              tail[i + 1] == 0x4B.toByte() &&
              tail[i + 2] == 0x05.toByte() &&
              tail[i + 3] == 0x06.toByte()
          ) {
            eocdPos = i
            break
          }
        }
        if (eocdPos < 0) return false
        val bb = ByteBuffer.wrap(tail, eocdPos, 22).order(ByteOrder.LITTLE_ENDIAN)
        bb.position(12)
        val cdSize = bb.int.toLong() and 0xFFFFFFFFL
        val cdOffset = bb.int.toLong() and 0xFFFFFFFFL
        if (cdOffset + cdSize > len) return false

        val cdBytes = ByteArray(cdSize.toInt())
        raf.seek(cdOffset)
        raf.readFully(cdBytes)
        val cd = ByteBuffer.wrap(cdBytes).order(ByteOrder.LITTLE_ENDIAN)
        while (cd.remaining() >= 46) {
          val sig = cd.int
          if (sig != 0x02014B50) break
          cd.position(cd.position() + 6)
          val method = cd.short.toInt() and 0xFFFF
          cd.position(cd.position() + 16)
          val nameLen = cd.short.toInt() and 0xFFFF
          val extraLen = cd.short.toInt() and 0xFFFF
          val commentLen = cd.short.toInt() and 0xFFFF
          cd.position(cd.position() + 8)
          val lfhOffset = cd.int.toLong() and 0xFFFFFFFFL
          val nameArr = ByteArray(nameLen)
          cd.get(nameArr)
          val name = nameArr.toString(Charsets.UTF_8)
          cd.position(cd.position() + extraLen + commentLen)

          if (method == STORED && !name.endsWith("/")) {
            val lfhBuf = ByteArray(LFH_FIXED_SIZE)
            raf.seek(lfhOffset)
            raf.readFully(lfhBuf)
            val lfh = ByteBuffer.wrap(lfhBuf).order(ByteOrder.LITTLE_ENDIAN)
            val lfhNameLen = lfh.getShort(26).toInt() and 0xFFFF
            val lfhExtraLen = lfh.getShort(28).toInt() and 0xFFFF
            val dataStart = lfhOffset + LFH_FIXED_SIZE + lfhNameLen + lfhExtraLen
            val reqAlign = if (name.endsWith(".so", ignoreCase = true)) 4096L else 4L
            if (dataStart % reqAlign != 0L) {
              return false
            }
          }
        }
        true
      }
    } catch (_: Exception) {
      false
    }
  }
}
