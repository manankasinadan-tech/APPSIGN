package com.hephaistos.appsign.core.apk

import com.android.apksig.apk.ApkUtils
import com.android.apksig.util.DataSources
import com.hephaistos.appsign.core.crypto.CryptoSupport
import java.io.ByteArrayInputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.zip.ZipFile
import org.bouncycastle.cms.CMSSignedData

internal data class SigningBlockSchemeInspection(
  val v2Present: Boolean = false,
  val v2Verified: Boolean = false,
  val v2Signers: List<X509Certificate> = emptyList(),
  val v3Present: Boolean = false,
  val v3Verified: Boolean = false,
  val v3Signers: List<X509Certificate> = emptyList(),
  val v31Present: Boolean = false,
  val v31Signers: List<X509Certificate> = emptyList(),
  val v1EntriesPresent: Boolean = false,
  val v1ExtractedSigners: List<X509Certificate> = emptyList(),
)

private data class ParsedBlockSigner(
  val signedDataBytes: ByteArray,
  val digests: List<Pair<Int, ByteArray>>,
  val certificates: List<X509Certificate>,
  val signatures: List<Pair<Int, ByteArray>>,
)

internal object ApkSigningBlockInspector {

  private const val APK_SIG_BLOCK_V2_ID = 0x7109871a
  private const val APK_SIG_BLOCK_V3_ID = 0xf05368c0.toInt()
  private const val APK_SIG_BLOCK_V31_ID = 0x1b93ad61

  private const val CONTENT_DIGEST_CHUNKED_SHA256 = 1
  private const val CONTENT_DIGEST_CHUNKED_SHA512 = 2
  private const val CONTENT_DIGEST_VERITY_CHUNKED_SHA256 = 3

  private const val CHUNK_SIZE = 1024 * 1024

  private val sfRegex = Regex("^META-INF/[^/]+\\.SF$", RegexOption.IGNORE_CASE)
  private val blockFileRegex = Regex("^META-INF/[^/]+\\.(RSA|DSA|EC)$", RegexOption.IGNORE_CASE)

  fun inspect(apkFile: File): SigningBlockSchemeInspection {
    val (hasV1Pair, v1Certs) = inspectV1Entries(apkFile)

    var v2Present = false
    var v2Verified = false
    var v2Signers = emptyList<X509Certificate>()
    var v3Present = false
    var v3Verified = false
    var v3Signers = emptyList<X509Certificate>()
    var v31Present = false
    var v31Signers = emptyList<X509Certificate>()

    runCatching {
      RandomAccessFile(apkFile, "r").use { raf ->
        val dataSource = DataSources.asDataSource(raf)
        val zipSections = ApkUtils.findZipSections(dataSource)
        val cdOffset = zipSections.zipCentralDirectoryOffset
        val eocdOffset = zipSections.zipEndOfCentralDirectoryOffset
        if (cdOffset >= 32L) {
          val footer = ByteArray(24)
          raf.seek(cdOffset - 24L)
          raf.readFully(footer)
          val footerMagic = String(footer, 8, 16, Charsets.US_ASCII)
          if (footerMagic == "APK Sig Block 42") {
            val blockSize = ByteBuffer.wrap(footer, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
            val blockStart = cdOffset - 8L - blockSize
            if (blockStart >= 0L && blockSize >= 24L && blockStart + 8L <= cdOffset - 24L) {
              val headerBuf = ByteArray(8)
              raf.seek(blockStart)
              raf.readFully(headerBuf)
              val headerSize = ByteBuffer.wrap(headerBuf).order(ByteOrder.LITTLE_ENDIAN).long
              if (headerSize == blockSize) {
                val pairsLen = (cdOffset - 24L) - (blockStart + 8L)
                if (pairsLen in 1..64L * 1024L * 1024L) {
                  val pairsBytes = ByteArray(pairsLen.toInt())
                  raf.seek(blockStart + 8L)
                  raf.readFully(pairsBytes)
                  val pairs = parsePairs(pairsBytes)

                  pairs[APK_SIG_BLOCK_V2_ID]?.let { v2Bytes ->
                    v2Present = true
                    val parsed = parseSchemeSigners(v2Bytes, isV3 = false)
                    v2Signers = parsed.mapNotNull { it.certificates.firstOrNull() }
                    v2Verified =
                      parsed.isNotEmpty() &&
                        verifySchemeSigners(
                          raf = raf,
                          signingBlockStart = blockStart,
                          cdOffset = cdOffset,
                          eocdOffset = eocdOffset,
                          signers = parsed,
                        )
                  }

                  pairs[APK_SIG_BLOCK_V3_ID]?.let { v3Bytes ->
                    v3Present = true
                    val parsed = parseSchemeSigners(v3Bytes, isV3 = true)
                    v3Signers = parsed.mapNotNull { it.certificates.firstOrNull() }
                    v3Verified =
                      parsed.isNotEmpty() &&
                        verifySchemeSigners(
                          raf = raf,
                          signingBlockStart = blockStart,
                          cdOffset = cdOffset,
                          eocdOffset = eocdOffset,
                          signers = parsed,
                        )
                  }

                  pairs[APK_SIG_BLOCK_V31_ID]?.let { v31Bytes ->
                    v31Present = true
                    val parsed = parseSchemeSigners(v31Bytes, isV3 = true)
                    v31Signers = parsed.mapNotNull { it.certificates.firstOrNull() }
                  }
                }
              }
            }
          }
        }
      }
    }

    return SigningBlockSchemeInspection(
      v2Present = v2Present,
      v2Verified = v2Verified,
      v2Signers = v2Signers,
      v3Present = v3Present,
      v3Verified = v3Verified,
      v3Signers = v3Signers,
      v31Present = v31Present,
      v31Signers = v31Signers,
      v1EntriesPresent = hasV1Pair,
      v1ExtractedSigners = v1Certs,
    )
  }

  private fun inspectV1Entries(apkFile: File): Pair<Boolean, List<X509Certificate>> {
    var hasSf = false
    var hasBlock = false
    val certsBySha = linkedMapOf<String, X509Certificate>()

    runCatching {
      ZipFile(apkFile).use { zip ->
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
          val entry = entries.nextElement()
          if (entry.isDirectory) continue
          val name = entry.name
          if (sfRegex.matches(name)) {
            hasSf = true
          } else if (blockFileRegex.matches(name)) {
            hasBlock = true
            val bytes = zip.getInputStream(entry).use { it.readBytes() }
            extractCertsFromPkcs7(bytes).forEach { cert ->
              val sha = CryptoSupport.certificateFingerprints(cert).sha256
              certsBySha.putIfAbsent(sha, cert)
            }
          }
        }
      }
    }

    return (hasSf && hasBlock) to certsBySha.values.toList()
  }

  private fun extractCertsFromPkcs7(blockBytes: ByteArray): List<X509Certificate> {
    val result = mutableListOf<X509Certificate>()
    // 1. BouncyCastle CMS SignedData handles full CMS signature blocks cleanly on JVM & Android
    runCatching {
      val cms = CMSSignedData(blockBytes)
      val store = cms.certificates
      val signerInfos = cms.signerInfos.signers
      val allHolders = store.getMatches(null)
      val cf = CertificateFactory.getInstance("X.509")
      for (signerInfo in signerInfos) {
        for (holder in allHolders) {
          if (signerInfo.sid.match(holder)) {
            val cert = cf.generateCertificate(ByteArrayInputStream(holder.encoded)) as? X509Certificate
            if (cert != null) result += cert
          }
        }
      }
      if (result.isEmpty()) {
        for (holder in allHolders) {
          val cert = cf.generateCertificate(ByteArrayInputStream(holder.encoded)) as? X509Certificate
          if (cert != null) result += cert
        }
      }
    }
    if (result.isNotEmpty()) return result

    // 2. Fallback via Java CertificateFactory
    runCatching {
      val cf = CertificateFactory.getInstance("X.509")
      cf.generateCertificates(ByteArrayInputStream(blockBytes))
        .mapNotNull { it as? X509Certificate }
        .forEach { result += it }
    }
    return result
  }

  private fun parsePairs(pairsBytes: ByteArray): Map<Int, ByteArray> {
    val map = linkedMapOf<Int, ByteArray>()
    val buf = ByteBuffer.wrap(pairsBytes).order(ByteOrder.LITTLE_ENDIAN)
    while (buf.remaining() >= 12) {
      val pairLen = buf.long
      if (pairLen < 4L || pairLen > buf.remaining().toLong()) break
      val id = buf.int
      val valLen = (pairLen - 4L).toInt()
      val value = ByteArray(valLen)
      buf.get(value)
      map[id] = value
    }
    return map
  }

  private fun parseSchemeSigners(blockValue: ByteArray, isV3: Boolean): List<ParsedBlockSigner> {
    val signers = mutableListOf<ParsedBlockSigner>()
    val root = ByteBuffer.wrap(blockValue).order(ByteOrder.LITTLE_ENDIAN)
    val signersSeq = readLengthPrefixedSlice(root) ?: return emptyList()
    while (signersSeq.hasRemaining()) {
      val signerSlice = readLengthPrefixedSlice(signersSeq) ?: break
      val signedDataSlice = readLengthPrefixedSlice(signerSlice) ?: break
      val signedDataBytes = ByteArray(signedDataSlice.remaining()).also {
        signedDataSlice.duplicate().get(it)
      }

      val digestsSlice = readLengthPrefixedSlice(signedDataSlice) ?: continue
      val digests = mutableListOf<Pair<Int, ByteArray>>()
      while (digestsSlice.hasRemaining()) {
        val digestRecord = readLengthPrefixedSlice(digestsSlice) ?: break
        if (digestRecord.remaining() < 4) break
        val sigAlgId = digestRecord.int
        val digestBytes = readLengthPrefixedBytes(digestRecord) ?: break
        digests += sigAlgId to digestBytes
      }

      val certsSlice = readLengthPrefixedSlice(signedDataSlice) ?: continue
      val certs = mutableListOf<X509Certificate>()
      val cf = CertificateFactory.getInstance("X.509")
      while (certsSlice.hasRemaining()) {
        val certBytes = readLengthPrefixedBytes(certsSlice) ?: break
        runCatching {
          (cf.generateCertificate(ByteArrayInputStream(certBytes)) as? X509Certificate)?.let { certs += it }
        }
      }

      if (isV3 && signedDataSlice.remaining() >= 8) {
        // minSdk, maxSdk, additionalAttributes (lineage/rotation etc.)
        signedDataSlice.int
        signedDataSlice.int
      }

      val sigsSlice = readLengthPrefixedSlice(signerSlice) ?: continue
      val signatures = mutableListOf<Pair<Int, ByteArray>>()
      while (sigsSlice.hasRemaining()) {
        val sigRecord = readLengthPrefixedSlice(sigsSlice) ?: break
        if (sigRecord.remaining() < 4) break
        val sigAlgId = sigRecord.int
        val sigBytes = readLengthPrefixedBytes(sigRecord) ?: break
        signatures += sigAlgId to sigBytes
      }

      // Skip publicKey slice
      readLengthPrefixedSlice(signerSlice)

      signers +=
        ParsedBlockSigner(
          signedDataBytes = signedDataBytes,
          digests = digests,
          certificates = certs,
          signatures = signatures,
        )
    }
    return signers
  }

  private fun verifySchemeSigners(
    raf: RandomAccessFile,
    signingBlockStart: Long,
    cdOffset: Long,
    eocdOffset: Long,
    signers: List<ParsedBlockSigner>,
  ): Boolean {
    if (signers.isEmpty()) return false
    val requiredDigestTypes = mutableSetOf<Int>()
    for (signer in signers) {
      val cert = signer.certificates.firstOrNull() ?: return false
      if (signer.signatures.isEmpty() || signer.digests.isEmpty()) return false
      var anySigValid = false
      for ((sigAlgId, sigBytes) in signer.signatures) {
        if (verifySignatureRecord(sigAlgId, sigBytes, signer.signedDataBytes, cert)) {
          anySigValid = true
          signatureAlgToContentDigestType(sigAlgId)?.let { requiredDigestTypes += it }
        }
      }
      if (!anySigValid) return false
    }

    // Compute APK content digests for any SHA-256 / SHA-512 chunked digest algorithms present
    val standardTypes = requiredDigestTypes.filter {
      it == CONTENT_DIGEST_CHUNKED_SHA256 || it == CONTENT_DIGEST_CHUNKED_SHA512
    }
    if (standardTypes.isEmpty()) return true

    val computedDigests =
      computeApkContentDigests(
        raf = raf,
        signingBlockStart = signingBlockStart,
        cdOffset = cdOffset,
        eocdOffset = eocdOffset,
        digestTypes = standardTypes,
      )

    for (signer in signers) {
      val digestByContentType =
        signer.digests.mapNotNull { (sigAlgId, bytes) ->
          val contentType = signatureAlgToContentDigestType(sigAlgId) ?: return@mapNotNull null
          contentType to bytes
        }.toMap()
      var verifiedAtLeastOneDigest = false
      for (contentType in standardTypes) {
        val expected = digestByContentType[contentType] ?: continue
        val actual = computedDigests[contentType] ?: continue
        if (!expected.contentEquals(actual)) {
          return false
        }
        verifiedAtLeastOneDigest = true
      }
      if (!verifiedAtLeastOneDigest) return false
    }
    return true
  }

  private fun verifySignatureRecord(
    sigAlgId: Int,
    sigBytes: ByteArray,
    signedData: ByteArray,
    cert: X509Certificate,
  ): Boolean {
    return runCatching {
      val sig =
        when (sigAlgId) {
          0x0101 -> Signature.getInstance("SHA256withRSA/PSS").apply {
            setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
          }
          0x0102 -> Signature.getInstance("SHA512withRSA/PSS").apply {
            setParameter(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))
          }
          0x0103 -> Signature.getInstance("SHA256withRSA")
          0x0104 -> Signature.getInstance("SHA512withRSA")
          0x0201 -> Signature.getInstance("SHA256withECDSA")
          0x0202 -> Signature.getInstance("SHA512withECDSA")
          0x0301 -> Signature.getInstance("SHA256withDSA")
          else -> return@runCatching false
        }
      sig.initVerify(cert.publicKey)
      sig.update(signedData)
      sig.verify(sigBytes)
    }.getOrDefault(false)
  }

  private fun signatureAlgToContentDigestType(sigAlgId: Int): Int? =
    when (sigAlgId) {
      0x0101, 0x0103, 0x0201, 0x0301 -> CONTENT_DIGEST_CHUNKED_SHA256
      0x0102, 0x0104, 0x0202 -> CONTENT_DIGEST_CHUNKED_SHA512
      0x0105, 0x0203 -> CONTENT_DIGEST_VERITY_CHUNKED_SHA256
      else -> null
    }

  private fun computeApkContentDigests(
    raf: RandomAccessFile,
    signingBlockStart: Long,
    cdOffset: Long,
    eocdOffset: Long,
    digestTypes: List<Int>,
  ): Map<Int, ByteArray> {
    val fileLen = raf.length()
    val eocdLen = (fileLen - eocdOffset).toInt()
    val eocdBytes = ByteArray(eocdLen)
    raf.seek(eocdOffset)
    raf.readFully(eocdBytes)
    if (eocdBytes.size >= 20) {
      ByteBuffer.wrap(eocdBytes, 16, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(signingBlockStart.toInt())
    }

    val totalChunks =
      chunkCount(signingBlockStart) + chunkCount(eocdOffset - cdOffset) + chunkCount(eocdLen.toLong())

    val out = mutableMapOf<Int, ByteArray>()
    for (type in digestTypes) {
      val jcaAlg =
        when (type) {
          CONTENT_DIGEST_CHUNKED_SHA256 -> "SHA-256"
          CONTENT_DIGEST_CHUNKED_SHA512 -> "SHA-512"
          else -> continue
        }
      val digestLen = MessageDigest.getInstance(jcaAlg).digestLength
      val topConcat = ByteBuffer.allocate(5 + totalChunks * digestLen).order(ByteOrder.LITTLE_ENDIAN)
      topConcat.put(0x5a.toByte())
      topConcat.putInt(totalChunks)

      val md = MessageDigest.getInstance(jcaAlg)
      val lenPrefix = ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN)

      // Section 1: Before APK Signing Block [0 .. signingBlockStart)
      digestFileChunks(raf, 0L, signingBlockStart, md, lenPrefix, topConcat)
      // Section 3: ZIP Central Directory [cdOffset .. eocdOffset)
      digestFileChunks(raf, cdOffset, eocdOffset - cdOffset, md, lenPrefix, topConcat)
      // Section 4: EOCD with patched centralDirOffset
      digestMemoryChunks(eocdBytes, md, lenPrefix, topConcat)

      out[type] = MessageDigest.getInstance(jcaAlg).digest(topConcat.array())
    }
    return out
  }

  private fun chunkCount(size: Long): Int = ((size + CHUNK_SIZE - 1L) / CHUNK_SIZE).toInt()

  private fun digestFileChunks(
    raf: RandomAccessFile,
    startOffset: Long,
    length: Long,
    md: MessageDigest,
    lenPrefix: ByteBuffer,
    topConcat: ByteBuffer,
  ) {
    var remaining = length
    var offset = startOffset
    val ioBuf = ByteArray(CHUNK_SIZE)
    while (remaining > 0L) {
      val chunkSize = minOf(remaining, CHUNK_SIZE.toLong()).toInt()
      raf.seek(offset)
      raf.readFully(ioBuf, 0, chunkSize)
      md.reset()
      lenPrefix.clear()
      lenPrefix.put(0xa5.toByte())
      lenPrefix.putInt(chunkSize)
      md.update(lenPrefix.array(), 0, 5)
      md.update(ioBuf, 0, chunkSize)
      topConcat.put(md.digest())
      offset += chunkSize
      remaining -= chunkSize
    }
  }

  private fun digestMemoryChunks(
    bytes: ByteArray,
    md: MessageDigest,
    lenPrefix: ByteBuffer,
    topConcat: ByteBuffer,
  ) {
    var offset = 0
    while (offset < bytes.size) {
      val chunkSize = minOf(bytes.size - offset, CHUNK_SIZE)
      md.reset()
      lenPrefix.clear()
      lenPrefix.put(0xa5.toByte())
      lenPrefix.putInt(chunkSize)
      md.update(lenPrefix.array(), 0, 5)
      md.update(bytes, offset, chunkSize)
      topConcat.put(md.digest())
      offset += chunkSize
    }
  }

  private fun readLengthPrefixedSlice(buf: ByteBuffer): ByteBuffer? {
    if (buf.remaining() < 4) return null
    val len = buf.int
    if (len < 0 || len > buf.remaining()) return null
    val slice = buf.slice().order(ByteOrder.LITTLE_ENDIAN)
    slice.limit(len)
    buf.position(buf.position() + len)
    return slice
  }

  private fun readLengthPrefixedBytes(buf: ByteBuffer): ByteArray? {
    if (buf.remaining() < 4) return null
    val len = buf.int
    if (len < 0 || len > buf.remaining()) return null
    val out = ByteArray(len)
    buf.get(out)
    return out
  }
}
