package com.hephaistos.appsign.core.ossign

import com.hephaistos.appsign.core.apk.ApkVerifierEngine
import com.hephaistos.appsign.core.apk.JarSignerEngine
import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.ApkVerificationReport
import com.hephaistos.appsign.core.model.CertificateDetails
import com.hephaistos.appsign.core.model.OsArtifactKind
import com.hephaistos.appsign.core.model.OsPermissionReference
import com.hephaistos.appsign.core.model.OsReferenceFormat
import com.hephaistos.appsign.core.model.OsScannedArtifact
import com.hephaistos.appsign.core.model.OsSignInspectionReport
import com.hephaistos.appsign.core.model.OsSignatureGroup
import com.hephaistos.appsign.core.model.OsTrustAction
import com.hephaistos.appsign.core.model.SignatureSchemeVersion
import com.hephaistos.appsign.core.model.VerificationStatus
import java.io.File
import java.io.IOException
import java.nio.file.FileVisitOption
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.EnumSet
import java.util.zip.ZipFile

object OsSignAnalyzerEngine {

  private const val MAX_TEXT_SCAN_BYTES = 4L * 1024L * 1024L
  private val hexCertRegex = Regex("""\b(308[0-9a-fA-F]{120,})\b""")
  private val pemCertRegex =
    Regex("""-----BEGIN CERTIFICATE-----[\r\n\sA-Za-z0-9+/=]+-----END CERTIFICATE-----""")

  private val binarySkipExtensions =
    setOf(
      "so", "odex", "vdex", "art", "oat", "dex", "png", "jpg", "jpeg", "webp",
      "gif", "ogg", "mp3", "mp4", "wav", "ttf", "otf", "woff", "woff2", "img",
      "bin", "dat", "db", "gz", "xz", "lz4", "zst",
    )

  private val textLikeExtensions =
    setOf("xml", "conf", "cfg", "pem", "crt", "cer", "txt", "json", "prop", "rc", "policy", "info")

  fun analyzeDirectory(
    rootDir: File,
    onProgress: (scannedCount: Int, currentName: String) -> Unit = { _, _ -> },
  ): OsSignInspectionReport {
    if (!rootDir.exists() || !rootDir.isDirectory) {
      throw IllegalArgumentException("Target directory not found: ${rootDir.absolutePath}")
    }
    val startNs = System.nanoTime()
    val rootPath = rootDir.toPath()

    var totalVisited = 0
    var symlinksIgnored = 0
    val binaryCandidates = mutableListOf<File>()
    val refCandidates = mutableListOf<File>()

    // Strictly DO NOT follow symbolic links anywhere in traversal.
    Files.walkFileTree(
      rootPath,
      EnumSet.noneOf(FileVisitOption::class.java),
      Int.MAX_VALUE,
      object : SimpleFileVisitor<Path>() {
        override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
          if (Files.isSymbolicLink(dir) || attrs.isSymbolicLink) {
            symlinksIgnored++
            return FileVisitResult.SKIP_SUBTREE
          }
          return FileVisitResult.CONTINUE
        }

        override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
          if (Files.isSymbolicLink(file) || attrs.isSymbolicLink) {
            symlinksIgnored++
            return FileVisitResult.CONTINUE
          }
          if (!attrs.isRegularFile) return FileVisitResult.CONTINUE

          val f = file.toFile()
          val nameLower = f.name.lowercase()
          // Ignore APPSIGN backup files if present
          if (nameLower.endsWith(".appsign.bak") || nameLower.endsWith(".bak")) {
            return FileVisitResult.CONTINUE
          }
          totalVisited++
          if (totalVisited % 50 == 0) {
            onProgress(totalVisited, f.name)
          }

          val ext = f.extension.lowercase()
          when {
            ext == "apk" || ext == "apex" || ext == "jar" || ext == "capex" -> binaryCandidates += f
            ext == "der" || ext == "pem" || ext == "crt" || ext == "cer" || ext == "avbpubkey" || ext == "pubkey" -> {
              refCandidates += f
            }
            ext in textLikeExtensions || (f.length() in 1L..MAX_TEXT_SCAN_BYTES && ext !in binarySkipExtensions && looksLikeTextFile(f)) -> {
              refCandidates += f
            }
          }
          return FileVisitResult.CONTINUE
        }

        override fun visitFileFailed(file: Path, exc: IOException): FileVisitResult {
          if (Files.isSymbolicLink(file)) {
            symlinksIgnored++
          }
          return FileVisitResult.CONTINUE
        }
      },
    )

    val scannedArtifacts = mutableListOf<OsScannedArtifact>()
    val certBySha256 = linkedMapOf<String, CertificateDetails>()
    val certsX509BySha256 = linkedMapOf<String, X509Certificate>()

    for ((idx, binFile) in binaryCandidates.withIndex()) {
      onProgress(idx + 1, binFile.name)
      val rel = rootPath.relativize(binFile.toPath()).toString().replace('\\', '/')
      val artifact = inspectBinaryArtifact(binFile, rel)
      scannedArtifacts += artifact

      // Register unique signer certificates
      artifact.apkReport?.allUniqueSigners?.forEach { details ->
        certBySha256.putIfAbsent(details.fingerprints.sha256, details)
        certsX509BySha256.putIfAbsent(
          details.fingerprints.sha256,
          CryptoSupport.parseX509Certificate(details.certificatePem.toByteArray(Charsets.UTF_8)),
        )
      }
      if (artifact.kind == OsArtifactKind.JAR && artifact.trustAction == OsTrustAction.REQUIRES_RESIGN) {
        val jarRes = JarSignerEngine.verifyJar(binFile)
        jarRes.signers.forEach { details ->
          certBySha256.putIfAbsent(details.fingerprints.sha256, details)
          certsX509BySha256.putIfAbsent(
            details.fingerprints.sha256,
            CryptoSupport.parseX509Certificate(details.certificatePem.toByteArray(Charsets.UTF_8)),
          )
        }
      }
    }

    // Build reverse lookup indices from known signers for dynamic reference scanning
    val refMatches = mutableListOf<OsPermissionReference>()
    val seinfoHintsBySha = mutableMapOf<String, String>()
    val signerSha256ColonToCert = certBySha256.keys.associateBy { it.lowercase() }
    val signerSha256CompactToSha256 =
      certBySha256.keys.associateBy { it.replace(":", "").lowercase() }
    val signerSha1ColonToSha256 =
      certBySha256.values.associate { it.fingerprints.sha1.lowercase() to it.fingerprints.sha256 }
    val signerSha1CompactToSha256 =
      certBySha256.values.associate {
        it.fingerprints.sha1.replace(":", "").lowercase() to it.fingerprints.sha256
      }

    for (refFile in refCandidates) {
      val rel = rootPath.relativize(refFile.toPath()).toString().replace('\\', '/')
      refMatches +=
        scanReferenceFile(
          file = refFile,
          relativePath = rel,
          knownCertsBySha256 = certBySha256,
          seinfoHintsBySha = seinfoHintsBySha,
          signerSha256ColonToCert = signerSha256ColonToCert,
          signerSha256CompactToSha256 = signerSha256CompactToSha256,
          signerSha1ColonToSha256 = signerSha1ColonToSha256,
          signerSha1CompactToSha256 = signerSha1CompactToSha256,
        )
    }
    // Ensure X509Certificate map also has certs discovered solely in XML/PEM/DER files
    certBySha256.forEach { (sha, details) ->
      certsX509BySha256.putIfAbsent(
        sha,
        CryptoSupport.parseX509Certificate(details.certificatePem.toByteArray(Charsets.UTF_8)),
      )
    }

    val signedArtifacts = scannedArtifacts.filter { it.trustAction == OsTrustAction.REQUIRES_RESIGN }
    val preservedArtifacts = scannedArtifacts.filter { it.trustAction != OsTrustAction.REQUIRES_RESIGN }

    // Group signed artifacts by primary signer SHA-256 while preserving all co-signers as valid groups
    val groupedBySha = linkedMapOf<String, MutableList<OsScannedArtifact>>()
    for (art in signedArtifacts) {
      val key = art.primarySignerSha256 ?: continue
      groupedBySha.getOrPut(key) { mutableListOf() }.add(art)
      for (coSha in art.allSignerSha256s) {
        if (certBySha256.containsKey(coSha)) {
          groupedBySha.putIfAbsent(coSha, mutableListOf())
        }
      }
    }
    // Include groups referenced ONLY in permission XMLs/PEMs if a valid X.509 was discovered
    for (ref in refMatches) {
      if (!groupedBySha.containsKey(ref.matchedSignerSha256) && certBySha256.containsKey(ref.matchedSignerSha256)) {
        groupedBySha.putIfAbsent(ref.matchedSignerSha256, mutableListOf())
      }
    }

    val rawLabels =
      groupedBySha.entries.mapIndexed { index, (sha256, members) ->
        sha256 to inferGroupLabel(index, certBySha256.getValue(sha256), members, seinfoHintsBySha[sha256])
      }.toMap()
    val duplicateLabels = rawLabels.values.groupingBy { it }.eachCount().filter { it.value > 1 }.keys

    val groups =
      groupedBySha.entries.map { (sha256, members) ->
        val certDetails = certBySha256.getValue(sha256)
        val x509 = certsX509BySha256.getValue(sha256)
        val keySpec = CryptoSupport.extractExactKeySpec(x509)
        val refsForGroup = refMatches.filter { it.matchedSignerSha256 == sha256 }
        val schemes =
          members
            .flatMap { it.schemes }
            .distinct()
            .sortedBy { it.ordinal }
            .ifEmpty { listOf(SignatureSchemeVersion.V1, SignatureSchemeVersion.V2, SignatureSchemeVersion.V3) }
        val baseLabel = rawLabels.getValue(sha256)
        val shortHex = sha256.replace(":", "").take(4).uppercase()
        val finalLabel =
          if (baseLabel in duplicateLabels) "$baseLabel · $shortHex" else baseLabel
        val validityDays =
          runCatching {
            val s = Instant.parse(certDetails.notBeforeIso)
            val e = Instant.parse(certDetails.notAfterIso)
            Duration.between(s, e).toDays().coerceIn(365L, 36500L)
          }.getOrDefault(365L * 25L)

        OsSignatureGroup(
          groupId = "grp_${sha256.replace(":", "").take(12).lowercase()}",
          label = finalLabel,
          sha256 = sha256,
          certificate = certDetails,
          keySpec = keySpec,
          recommendedSchemes = schemes,
          artifacts = members.sortedBy { it.relativePath },
          permissionReferences = refsForGroup.sortedBy { it.relativePath },
          hasMultipleSignersInMembers = members.any { it.allSignerSha256s.size > 1 },
          hasKeyRotationInMembers = members.any { it.apkReport?.keyRotation?.hasRotation == true },
          validityDays = validityDays,
        )
      }.sortedByDescending { it.artifacts.size }

    val warnings = mutableListOf<String>()
    signedArtifacts
      .filter { it.kind == OsArtifactKind.APEX && it.apexHasEmbeddedPubKey }
      .takeIf { it.isNotEmpty() }
      ?.let { apexList ->
        warnings +=
          "${apexList.size} APEX archive(s) embed apex_pubkey inside apex_payload.img; outer APEX signature will be resigned while payload ext4/erofs image stays untouched."
      }
    if (symlinksIgnored > 0) {
      warnings += "$symlinksIgnored symbolic link(s) strictly ignored and left untouched."
    }

    val v1Count = signedArtifacts.count { SignatureSchemeVersion.V1 in it.schemes }
    val v2Count = signedArtifacts.count { SignatureSchemeVersion.V2 in it.schemes }
    val v3Count = signedArtifacts.count { SignatureSchemeVersion.V3 in it.schemes }
    val v31Count = signedArtifacts.count { SignatureSchemeVersion.V3_1 in it.schemes }
    val roleSummary =
      signedArtifacts
        .groupingBy { it.inferredRole }
        .eachCount()
        .entries
        .sortedByDescending { it.value }
        .joinToString(", ") { "${it.key}:${it.value}" }

    val trustChainSummary = buildList {
      add("Detected ${groups.size} distinct cryptographic key group(s) across ${signedArtifacts.size} signed artifact(s).")
      add("Schemes detected -> V1:$v1Count, V2:$v2Count, V3:$v3Count, V3.1:$v31Count.")
      if (roleSummary.isNotBlank()) {
        add("Partitions/Roles -> $roleSummary.")
      }
      add("Preserving ${preservedArtifacts.size} unsigned/non-impacting artifact(s) untouched.")
      add("Detected ${refMatches.size} cryptographic signature reference(s) across permission/config files.")
      add("Ignored $symlinksIgnored symbolic link(s) (never followed or modified).")
    }

    val durationMs = (System.nanoTime() - startNs) / 1_000_000L

    return OsSignInspectionReport(
      rootDirectory = rootDir.absolutePath,
      scannedAtIso = CryptoSupport.nowIso(),
      durationMs = durationMs,
      totalFilesVisited = totalVisited,
      symlinksIgnoredCount = symlinksIgnored,
      signedArtifactsCount = signedArtifacts.size,
      preservedUnsignedCount = preservedArtifacts.size,
      groups = groups,
      preservedArtifacts = preservedArtifacts.sortedBy { it.relativePath },
      allPermissionReferences = refMatches.sortedBy { it.relativePath },
      trustChainSummary = trustChainSummary,
      warnings = warnings,
    )
  }

  private fun inspectBinaryArtifact(file: File, relativePath: String): OsScannedArtifact {
    val ext = file.extension.lowercase()
    val inferredRole = inferArtifactRole(relativePath)

    if (ext == "jar") {
      val jarRes = JarSignerEngine.verifyJar(file)
      val primary = jarRes.signers.firstOrNull()?.fingerprints?.sha256
      val action =
        if (jarRes.present && jarRes.signers.isNotEmpty()) OsTrustAction.REQUIRES_RESIGN
        else OsTrustAction.PRESERVED_UNSIGNED
      return OsScannedArtifact(
        relativePath = relativePath,
        absolutePath = file.absolutePath,
        kind = OsArtifactKind.JAR,
        sizeBytes = file.length(),
        verified = jarRes.verified,
        status = jarRes.status,
        primarySignerSha256 = primary,
        allSignerSha256s = jarRes.signers.map { it.fingerprints.sha256 },
        schemes = if (jarRes.present) listOf(SignatureSchemeVersion.V1) else emptyList(),
        inferredRole = inferredRole,
        trustAction = action,
        reason =
          if (action == OsTrustAction.REQUIRES_RESIGN) "Signed JAR archive impacts trust chain"
          else "Unsigned framework/library JAR preserved untouched",
      )
    }

    if (ext == "capex") {
      return OsScannedArtifact(
        relativePath = relativePath,
        absolutePath = file.absolutePath,
        kind = OsArtifactKind.APEX,
        sizeBytes = file.length(),
        verified = false,
        status = VerificationStatus.UNSIGNED,
        inferredRole = inferredRole,
        trustAction = OsTrustAction.UNSUPPORTED_ARCHIVE,
        reason = "Compressed CAPEX container preserved (requires decompression before resigning)",
      )
    }

    // Detect APEX vs APK dynamically from ZIP contents + extension
    val (isApex, hasApexPubKey) = detectApexStructure(file)
    val kind = if (isApex) OsArtifactKind.APEX else OsArtifactKind.APK

    val report: ApkVerificationReport? = runCatching { ApkVerifierEngine.verify(file) }.getOrNull()
    if (report == null) {
      return OsScannedArtifact(
        relativePath = relativePath,
        absolutePath = file.absolutePath,
        kind = kind,
        sizeBytes = file.length(),
        verified = false,
        status = VerificationStatus.UNSIGNED,
        inferredRole = inferredRole,
        trustAction = OsTrustAction.UNSUPPORTED_ARCHIVE,
        reason = "Unreadable or non-APK ZIP container preserved",
      )
    }

    val primarySha = report.allUniqueSigners.firstOrNull()?.fingerprints?.sha256
    val presentSchemes = report.schemeResults.filter { it.present }.map { it.scheme }
    val hasSignatures = report.allUniqueSigners.isNotEmpty() && presentSchemes.isNotEmpty()

    val trustAction =
      if (hasSignatures) OsTrustAction.REQUIRES_RESIGN else OsTrustAction.PRESERVED_UNSIGNED

    return OsScannedArtifact(
      relativePath = relativePath,
      absolutePath = file.absolutePath,
      kind = kind,
      sizeBytes = file.length(),
      verified = report.verified,
      status = report.overallStatus,
      primarySignerSha256 = primarySha,
      allSignerSha256s = report.allUniqueSigners.map { it.fingerprints.sha256 },
      schemes = presentSchemes,
      inferredRole = inferredRole,
      trustAction = trustAction,
      reason =
        when {
          trustAction == OsTrustAction.PRESERVED_UNSIGNED -> "Unsigned container preserved untouched"
          kind == OsArtifactKind.APEX -> "Signed APEX container (outer APK signature block)"
          else -> "Signed APK impacting trust chain (${presentSchemes.joinToString(",") { it.name }})"
        },
      apkReport = report,
      apexHasEmbeddedPubKey = hasApexPubKey,
      apexPayloadWarning =
        if (hasApexPubKey) "Contains apex_pubkey; inner apex_payload.img is read-only ext4/erofs" else null,
    )
  }

  private fun detectApexStructure(file: File): Pair<Boolean, Boolean> {
    var hasManifestApex = file.extension.equals("apex", ignoreCase = true)
    var hasPubKey = false
    runCatching {
      ZipFile(file).use { zip ->
        if (zip.getEntry("apex_manifest.pb") != null || zip.getEntry("apex_manifest.json") != null) {
          hasManifestApex = true
        }
        if (zip.getEntry("apex_pubkey") != null || zip.getEntry("apex_payload.img") != null) {
          hasPubKey = true
        }
      }
    }
    return hasManifestApex to hasPubKey
  }

  private val seinfoRegex = Regex("""<seinfo\s+value="([^"]+)"\s*/?>""", RegexOption.IGNORE_CASE)

  private fun scanReferenceFile(
    file: File,
    relativePath: String,
    knownCertsBySha256: MutableMap<String, CertificateDetails>,
    seinfoHintsBySha: MutableMap<String, String>,
    signerSha256ColonToCert: Map<String, String>,
    signerSha256CompactToSha256: Map<String, String>,
    signerSha1ColonToSha256: Map<String, String>,
    signerSha1CompactToSha256: Map<String, String>,
  ): List<OsPermissionReference> {
    val results = mutableListOf<OsPermissionReference>()
    val ext = file.extension.lowercase()

    // Check standalone DER certificate files
    if (ext == "der" || ext == "crt" || ext == "cer") {
      val parsed = runCatching { CryptoSupport.parseX509Certificate(file.readBytes()) }.getOrNull()
      if (parsed != null) {
        val details = CryptoSupport.extractCertificateDetails(parsed)
        val sha = details.fingerprints.sha256
        knownCertsBySha256.putIfAbsent(sha, details)
        results +=
          OsPermissionReference(
            relativePath = relativePath,
            absolutePath = file.absolutePath,
            format = OsReferenceFormat.STANDALONE_CERT_FILE,
            matchedSignerSha256 = sha,
            occurrences = 1,
            previewSnippet = "X.509 Subject: ${details.subjectDn}",
            writableUpdateSupported = true,
          )
        return results
      }
    }

    if (file.length() > MAX_TEXT_SCAN_BYTES) return results
    val text = runCatching { file.readText(Charsets.UTF_8) }.getOrNull() ?: return results

    // 1. Hex-encoded X.509 DER certificates (e.g., mac_permissions.xml, privapp-permissions, etc.)
    val hexBySha = linkedMapOf<String, MutableList<String>>()
    for (match in hexCertRegex.findAll(text)) {
      val hex = match.groupValues[1]
      val cert = CryptoSupport.tryParseCertificateHex(hex) ?: continue
      val details = CryptoSupport.extractCertificateDetails(cert)
      val sha = details.fingerprints.sha256
      knownCertsBySha256.putIfAbsent(sha, details)
      val windowEnd = minOf(text.length, match.range.last + 500)
      val tailSnippet = text.substring(match.range.last + 1, windowEnd)
      val stopIdx = tailSnippet.indexOf("</signer>", ignoreCase = true).let { if (it > 0) it else tailSnippet.length }
      seinfoRegex.find(tailSnippet.substring(0, stopIdx))?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }?.let { se ->
        seinfoHintsBySha.putIfAbsent(sha, se)
      }
      hexBySha.getOrPut(sha) { mutableListOf() }.add(extractLinePreview(text, match.range.first))
    }
    hexBySha.forEach { (sha, previews) ->
      results +=
        OsPermissionReference(
          relativePath = relativePath,
          absolutePath = file.absolutePath,
          format = OsReferenceFormat.XML_HEX_CERT,
          matchedSignerSha256 = sha,
          occurrences = previews.size,
          previewSnippet = previews.first(),
          writableUpdateSupported = true,
        )
    }

    // 2. PEM Certificate blocks
    val pemBySha = linkedMapOf<String, MutableList<String>>()
    for (match in pemCertRegex.findAll(text)) {
      val cert = runCatching { CryptoSupport.parseX509Certificate(match.value.toByteArray(Charsets.UTF_8)) }.getOrNull() ?: continue
      val details = CryptoSupport.extractCertificateDetails(cert)
      val sha = details.fingerprints.sha256
      knownCertsBySha256.putIfAbsent(sha, details)
      pemBySha.getOrPut(sha) { mutableListOf() }.add(extractLinePreview(text, match.range.first))
    }
    pemBySha.forEach { (sha, previews) ->
      results +=
        OsPermissionReference(
          relativePath = relativePath,
          absolutePath = file.absolutePath,
          format = OsReferenceFormat.PEM_CERT_BLOCK,
          matchedSignerSha256 = sha,
          occurrences = previews.size,
          previewSnippet = previews.first(),
          writableUpdateSupported = true,
        )
    }

    // 3. SHA-256 and SHA-1 fingerprints matching discovered signers
    val lower = text.lowercase()
    for ((colonSha, canonicalSha) in signerSha256ColonToCert) {
      val count = countOccurrences(lower, colonSha) + countOccurrences(lower, colonSha.replace(":", ""))
      if (count > 0) {
        results +=
          OsPermissionReference(
            relativePath = relativePath,
            absolutePath = file.absolutePath,
            format = OsReferenceFormat.SHA256_FINGERPRINT,
            matchedSignerSha256 = canonicalSha,
            occurrences = count,
            previewSnippet = "SHA-256 ref: $canonicalSha",
            writableUpdateSupported = true,
          )
      }
    }
    for ((compactSha, canonicalSha) in signerSha256CompactToSha256) {
      if (results.none { it.format == OsReferenceFormat.SHA256_FINGERPRINT && it.matchedSignerSha256 == canonicalSha }) {
        val count = countOccurrences(lower, compactSha)
        if (count > 0) {
          results +=
            OsPermissionReference(
              relativePath = relativePath,
              absolutePath = file.absolutePath,
              format = OsReferenceFormat.SHA256_FINGERPRINT,
              matchedSignerSha256 = canonicalSha,
              occurrences = count,
              previewSnippet = "SHA-256 hex ref: ${compactSha.take(24)}...",
              writableUpdateSupported = true,
            )
        }
      }
    }
    for ((colonSha1, canonicalSha256) in signerSha1ColonToSha256) {
      val count = countOccurrences(lower, colonSha1) + countOccurrences(lower, colonSha1.replace(":", ""))
      if (count > 0) {
        results +=
          OsPermissionReference(
            relativePath = relativePath,
            absolutePath = file.absolutePath,
            format = OsReferenceFormat.SHA1_FINGERPRINT,
            matchedSignerSha256 = canonicalSha256,
            occurrences = count,
            previewSnippet = "SHA-1 ref: ${colonSha1.uppercase()}",
            writableUpdateSupported = true,
          )
      }
    }
    for ((compactSha1, canonicalSha256) in signerSha1CompactToSha256) {
      if (results.none { it.format == OsReferenceFormat.SHA1_FINGERPRINT && it.matchedSignerSha256 == canonicalSha256 }) {
        val count = countOccurrences(lower, compactSha1)
        if (count > 0) {
          results +=
            OsPermissionReference(
              relativePath = relativePath,
              absolutePath = file.absolutePath,
              format = OsReferenceFormat.SHA1_FINGERPRINT,
              matchedSignerSha256 = canonicalSha256,
              occurrences = count,
              previewSnippet = "SHA-1 hex ref: ${compactSha1.take(20)}...",
              writableUpdateSupported = true,
            )
        }
      }
    }

    return results
  }

  private fun inferArtifactRole(relativePath: String): String {
    val parts = relativePath.lowercase().split('/').filter { it.isNotBlank() }
    return when {
      parts.contains("framework") -> "framework"
      parts.contains("priv-app") -> "priv-app"
      parts.contains("apex") -> "apex"
      parts.contains("overlay") -> "overlay"
      parts.contains("app") -> "app"
      else -> parts.firstOrNull() ?: "system"
    }
  }

  private fun inferGroupLabel(
    index: Int,
    cert: CertificateDetails,
    members: List<OsScannedArtifact>,
    seinfoHint: String? = null,
  ): String {
    val dn = cert.subjectDn
    val cnMatch = Regex("""CN=([^,]+)""").find(dn)?.groupValues?.get(1)?.trim()
    val ouMatch = Regex("""OU=([^,]+)""").find(dn)?.groupValues?.get(1)?.trim()
    val base =
      when {
        !seinfoHint.isNullOrBlank() -> seinfoHint
        !cnMatch.isNullOrBlank() && !cnMatch.equals("Android", ignoreCase = true) -> cnMatch
        !ouMatch.isNullOrBlank() -> ouMatch
        !cnMatch.isNullOrBlank() -> cnMatch
        else -> "Signer-${index + 1}"
      }
    val topRole = members.groupingBy { it.inferredRole }.eachCount().maxByOrNull { it.value }?.key
    return if (topRole != null && !base.contains(topRole, ignoreCase = true)) {
      "$base ($topRole)"
    } else {
      base
    }
  }

  private fun looksLikeTextFile(file: File): Boolean {
    return runCatching {
      file.inputStream().use { input ->
        val sample = ByteArray(512)
        val read = input.read(sample)
        if (read <= 0) return@runCatching false
        for (i in 0 until read) {
          val b = sample[i].toInt() and 0xFF
          if (b == 0) return@runCatching false
        }
        true
      }
    }.getOrDefault(false)
  }

  private fun extractLinePreview(text: String, offset: Int): String {
    val start = text.lastIndexOf('\n', offset).let { if (it < 0) 0 else it + 1 }
    val end = text.indexOf('\n', offset).let { if (it < 0) text.length else it }
    return text.substring(start, end).trim().take(120)
  }

  private fun countOccurrences(haystack: String, needle: String): Int {
    if (needle.isEmpty()) return 0
    var count = 0
    var idx = 0
    while (true) {
      val found = haystack.indexOf(needle, idx)
      if (found < 0) break
      count++
      idx = found + needle.length
    }
    return count
  }
}
