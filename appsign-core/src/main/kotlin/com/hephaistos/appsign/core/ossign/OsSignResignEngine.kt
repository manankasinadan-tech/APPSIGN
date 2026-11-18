package com.hephaistos.appsign.core.ossign

import com.hephaistos.appsign.core.apk.ApkSignerEngine
import com.hephaistos.appsign.core.apk.ApkVerifierEngine
import com.hephaistos.appsign.core.apk.JarSignerEngine
import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.AskContainer
import com.hephaistos.appsign.core.model.AskInspectResult
import com.hephaistos.appsign.core.model.IdentityInput
import com.hephaistos.appsign.core.model.OsArtifactKind
import com.hephaistos.appsign.core.model.OsArtifactResignOutcome
import com.hephaistos.appsign.core.model.OsBackupEntry
import com.hephaistos.appsign.core.model.OsBackupManifest
import com.hephaistos.appsign.core.model.OsPermissionReference
import com.hephaistos.appsign.core.model.OsReferenceFormat
import com.hephaistos.appsign.core.model.OsResignKeyStrategy
import com.hephaistos.appsign.core.model.OsSignInspectionReport
import com.hephaistos.appsign.core.model.OsSignResignReport
import com.hephaistos.appsign.core.model.OsSignatureGroup
import com.hephaistos.appsign.core.model.SignatureSchemeVersion
import com.hephaistos.appsign.core.model.SigningOptions
import com.hephaistos.appsign.core.model.UnlockedKeyMaterial
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

data class OsResignPlan(
  val strategy: OsResignKeyStrategy,
  val identityPerGroup: Map<String, IdentityInput> = emptyMap(),
  val existingKeyPerGroup: Map<String, UnlockedKeyMaterial> = emptyMap(),
  val clonePassphrase: CharArray? = null,
  val createBackups: Boolean = true,
)

object OsSignResignEngine {

  const val BACKUP_SUFFIX = ".appsign.bak"

  private val hexCertRegex = Regex("""\b(308[0-9a-fA-F]{120,})\b""")
  private val pemCertRegex =
    Regex("""-----BEGIN CERTIFICATE-----[\r\n\sA-Za-z0-9+/=]+-----END CERTIFICATE-----""")

  fun executeResign(
    inspection: OsSignInspectionReport,
    plan: OsResignPlan,
    askOutputDir: File,
    onAskCreated: (AskContainer, File) -> Unit = { _, _ -> },
    onProgress: (index: Int, total: Int, label: String) -> Unit = { _, _, _ -> },
  ): OsSignResignReport {
    val startNs = System.nanoTime()
    askOutputDir.mkdirs()

    val resolvedKeys = linkedMapOf<String, UnlockedKeyMaterial>() // groupId -> material
    val generatedAskPaths = mutableListOf<String>()
    val generatedAskInspects = mutableListOf<AskInspectResult>()
    val warnings = mutableListOf<String>()

    // 1. Resolve or generate .ask key for every detected cryptographic group
    for (group in inspection.groups) {
      when (plan.strategy) {
        OsResignKeyStrategy.USE_EXISTING_KEYS -> {
          val material =
            plan.existingKeyPerGroup[group.groupId]
              ?: throw IllegalArgumentException("Missing existing key mapping for group '${group.label}'.")
          resolvedKeys[group.groupId] = material
        }
        OsResignKeyStrategy.CREATE_WITH_IDENTITIES -> {
          val identity =
            plan.identityPerGroup[group.groupId]
              ?: plan.identityPerGroup.values.firstOrNull()
              ?: IdentityInput(alias = "os_${group.groupId}", commonName = "APPSIGN OS ${group.label}")
          val alias = identity.alias.ifBlank { "os_${group.groupId}" }
          val container =
            AskKeyManager.createAskFromExactSpec(
              alias = alias,
              spec = group.keySpec,
              subjectDn = identity.buildSubjectDn(),
              issuerDn = identity.buildSubjectDn(),
              validityDays = group.validityDays,
              passphrase = identity.passphrase,
              notes = "OS Sign matched spec for group '${group.label}' (orig SHA-256=${group.sha256.take(20)})",
            )
          val askFile = writeAskToDir(container, alias, askOutputDir)
          onAskCreated(container, askFile)
          generatedAskPaths += askFile.absolutePath
          generatedAskInspects += AskKeyManager.inspectAsk(container)
          resolvedKeys[group.groupId] = AskKeyManager.unlockAsk(container, identity.passphrase)
        }
        OsResignKeyStrategy.CLONE_DETECTED_KEYS -> {
          val cleanBaseAlias =
            group.label.lowercase().replace(Regex("[^a-z0-9_-]+"), "_").trim('_').ifBlank { group.groupId }
          val alias = "clone_${cleanBaseAlias}"
          val container =
            AskKeyManager.createAskFromExactSpec(
              alias = alias,
              spec = group.keySpec,
              subjectDn = group.certificate.subjectDn,
              issuerDn = group.certificate.issuerDn,
              validityDays = group.validityDays,
              passphrase = plan.clonePassphrase,
              notes = "OS Sign CLONED target profile '${group.label}' (orig SHA-256=${group.sha256.take(20)})",
            )
          val askFile = writeAskToDir(container, alias, askOutputDir)
          onAskCreated(container, askFile)
          generatedAskPaths += askFile.absolutePath
          generatedAskInspects += AskKeyManager.inspectAsk(container)
          resolvedKeys[group.groupId] = AskKeyManager.unlockAsk(container, plan.clonePassphrase)
        }
      }
    }

    val groupByOldSha = inspection.groups.associateBy { it.sha256 }
    val newCertByOldSha =
      inspection.groups.associate { grp -> grp.sha256 to resolvedKeys.getValue(grp.groupId).certificate }

    val backupEntries = mutableListOf<OsBackupEntry>()
    val outcomes = mutableListOf<OsArtifactResignOutcome>()

    val allSignedArtifacts = inspection.groups.flatMap { grp -> grp.artifacts.map { grp to it } }
    val uniqueRefPaths = inspection.allPermissionReferences.groupBy { it.absolutePath }
    val totalSteps = allSignedArtifacts.size + uniqueRefPaths.size
    var stepCounter = 0

    // 2. Re-sign impacted binaries in place (strictly ignoring symlinks)
    for ((group, artifact) in allSignedArtifacts) {
      stepCounter++
      onProgress(stepCounter, totalSteps, artifact.relativePath)

      val targetFile = File(artifact.absolutePath)
      val targetPath = targetFile.toPath()
      if (Files.isSymbolicLink(targetPath)) {
        warnings += "Skipped symlink during resign: ${artifact.relativePath}"
        continue
      }

      val keyMaterial = resolvedKeys.getValue(group.groupId)
      val newCertSha = CryptoSupport.certificateFingerprints(keyMaterial.certificate).sha256

      val outcome =
        runCatching {
          val backedUp =
            if (plan.createBackups) {
              ensureBackup(targetFile, "BINARY", backupEntries)
            } else {
              false
            }

          val tempOut = File.createTempFile("appsign_os_resign_", ".${targetFile.extension.ifBlank { "tmp" }}", targetFile.parentFile ?: askOutputDir)
          try {
            when (artifact.kind) {
              OsArtifactKind.JAR -> {
                JarSignerEngine.signJar(targetFile, tempOut, keyMaterial)
                val postJar = JarSignerEngine.verifyJar(tempOut)
                if (!postJar.verified) {
                  throw IllegalStateException("Post-sign JAR verification failed for ${artifact.relativePath}")
                }
                replaceInPlaceSafely(tempOut, targetFile)
                OsArtifactResignOutcome(
                  relativePath = artifact.relativePath,
                  absolutePath = artifact.absolutePath,
                  kind = artifact.kind.name,
                  groupLabel = group.label,
                  newKeyAlias = keyMaterial.alias,
                  newKeySha256 = newCertSha,
                  success = true,
                  backedUp = backedUp,
                  details = "Signed JAR v1 & verified",
                )
              }
              OsArtifactKind.APK,
              OsArtifactKind.APEX -> {
                // Reproduce target's exact signer set, scheme mask, and rotation/minSdk logic
                val signerList =
                  artifact.allSignerSha256s.mapNotNull { sha ->
                    groupByOldSha[sha]?.let { resolvedKeys[it.groupId] }
                  }.ifEmpty { listOf(keyMaterial) }

                val schemes = artifact.schemes
                val enableV1 = if (schemes.isEmpty()) true else SignatureSchemeVersion.V1 in schemes
                val enableV2 = if (schemes.isEmpty()) true else SignatureSchemeVersion.V2 in schemes
                val hasRotation = artifact.apkReport?.keyRotation?.hasRotation == true
                val allowV3 = signerList.size == 1 || hasRotation
                val enableV31 = (SignatureSchemeVersion.V3_1 in schemes) && allowV3
                val enableV3 = ((SignatureSchemeVersion.V3 in schemes) || enableV31) && allowV3
                val targetMinSdk =
                  com.hephaistos.appsign.core.pro.ResignProEngine.extractMinSdkVersion(targetFile)

                val opts =
                  SigningOptions(
                    enableV1 = enableV1,
                    enableV2 = enableV2,
                    enableV3 = enableV3,
                    enableV31 = enableV31,
                    enableV4 = false, // V4 .idsig is incremental install sidecar, not used inside static partitions
                    alignBeforeSign = true,
                    minSdkVersion = targetMinSdk,
                  )
                val res =
                  ApkSignerEngine.resignWithSigners(
                    inputApk = targetFile,
                    outputApk = tempOut,
                    signers = signerList,
                    options = opts,
                    useKeyRotationLineage = hasRotation && signerList.size >= 2,
                  )
                if (!res.success) {
                  throw IllegalStateException(res.errorMessage ?: "APK/APEX signing failed")
                }
                replaceInPlaceSafely(tempOut, targetFile)
                val verifyMinSdk =
                  targetMinSdk
                    ?: when {
                      enableV1 -> null
                      enableV2 -> 24
                      else -> 28
                    }
                val postVerify = ApkVerifierEngine.verify(targetFile, minSdkOverride = verifyMinSdk)
                if (!postVerify.verified) {
                  throw IllegalStateException("Post-replace verify failed: ${postVerify.errors.joinToString()}")
                }
                OsArtifactResignOutcome(
                  relativePath = artifact.relativePath,
                  absolutePath = artifact.absolutePath,
                  kind = artifact.kind.name,
                  groupLabel = group.label,
                  newKeyAlias = signerList.joinToString(",") { it.alias },
                  newKeySha256 = newCertSha,
                  success = true,
                  backedUp = backedUp,
                  details = "Signed (${res.appliedSchemes.joinToString(",") { it.name }}) & post-verified",
                )
              }
            }
          } finally {
            if (tempOut.exists()) tempOut.delete()
          }
        }.getOrElse { err ->
          OsArtifactResignOutcome(
            relativePath = artifact.relativePath,
            absolutePath = artifact.absolutePath,
            kind = artifact.kind.name,
            groupLabel = group.label,
            newKeyAlias = keyMaterial.alias,
            newKeySha256 = newCertSha,
            success = false,
            backedUp = false,
            details = err.message ?: "Resign error",
          )
        }
      outcomes += outcome
    }

    // 3. Update cryptographic references in permission/config files while preserving rules and mappings
    var refsUpdatedCount = 0
    for ((absPath, refsForFile) in uniqueRefPaths) {
      stepCounter++
      val refFile = File(absPath)
      onProgress(stepCounter, totalSteps, refFile.name)
      if (Files.isSymbolicLink(refFile.toPath()) || !refFile.exists()) continue

      runCatching {
        val backedUp =
          if (plan.createBackups) {
            ensureBackup(refFile, "REFERENCE", backupEntries)
          } else {
            false
          }
        val updated = updateReferenceFileInPlace(refFile, refsForFile, newCertByOldSha)
        if (updated) {
          refsUpdatedCount++
        } else if (backedUp) {
          // No effective byte change needed
        }
      }.onFailure { err ->
        warnings += "Failed updating reference '${refFile.name}': ${err.message}"
      }
    }

    val backupManifest =
      if (plan.createBackups && backupEntries.isNotEmpty()) {
        OsBackupManifest(
          sessionId = UUID.randomUUID().toString(),
          rootDirectory = inspection.rootDirectory,
          createdAtIso = CryptoSupport.nowIso(),
          entries = backupEntries.distinctBy { it.originalPath },
        )
      } else {
        null
      }

    val durationMs = (System.nanoTime() - startNs) / 1_000_000L
    val succeeded = outcomes.count { it.success }
    val failed = outcomes.count { !it.success }

    return OsSignResignReport(
      rootDirectory = inspection.rootDirectory,
      strategy = plan.strategy,
      durationMs = durationMs,
      totalResigned = outcomes.size,
      totalSucceeded = succeeded,
      totalFailed = failed,
      totalReferencesUpdated = refsUpdatedCount,
      totalPreserved = inspection.preservedUnsignedCount,
      symlinksIgnoredCount = inspection.symlinksIgnoredCount,
      generatedAskPaths = generatedAskPaths,
      generatedAskKeys = generatedAskInspects,
      outcomes = outcomes,
      backupManifest = backupManifest,
      warnings = warnings,
    )
  }

  fun restoreFromBackups(manifest: OsBackupManifest): Pair<Int, List<String>> {
    var restored = 0
    val errors = mutableListOf<String>()
    for (entry in manifest.entries) {
      val orig = File(entry.originalPath)
      val bak = File(entry.backupPath)
      if (Files.isSymbolicLink(orig.toPath()) || Files.isSymbolicLink(bak.toPath())) {
        errors += "Skipped symlink during restore: ${orig.name}"
        continue
      }
      if (!bak.exists()) {
        errors += "Missing backup file: ${bak.name}"
        continue
      }
      runCatching {
        replaceInPlaceSafely(bak, orig)
        restored++
      }.onFailure { err ->
        errors += "Restore failed for ${orig.name}: ${err.message}"
      }
    }
    return restored to errors
  }

  fun deleteBackups(manifest: OsBackupManifest): Pair<Int, List<String>> {
    var deleted = 0
    val errors = mutableListOf<String>()
    for (entry in manifest.entries) {
      val bak = File(entry.backupPath)
      if (Files.isSymbolicLink(bak.toPath())) {
        errors += "Skipped symlink during cleanup: ${bak.name}"
        continue
      }
      if (bak.exists()) {
        if (bak.delete()) {
          deleted++
        } else {
          errors += "Could not delete backup: ${bak.name}"
        }
      }
    }
    return deleted to errors
  }

  private fun ensureBackup(
    targetFile: File,
    kind: String,
    backupEntries: MutableList<OsBackupEntry>,
  ): Boolean {
    val bakFile = File("${targetFile.absolutePath}$BACKUP_SUFFIX")
    if (Files.isSymbolicLink(bakFile.toPath())) {
      throw IllegalStateException("Refusing to overwrite symlink backup target: ${bakFile.name}")
    }
    if (!bakFile.exists()) {
      Files.copy(targetFile.toPath(), bakFile.toPath(), StandardCopyOption.COPY_ATTRIBUTES)
    }
    backupEntries +=
      OsBackupEntry(
        originalPath = targetFile.absolutePath,
        backupPath = bakFile.absolutePath,
        kind = kind,
      )
    return true
  }

  private fun replaceInPlaceSafely(sourceTemp: File, destination: File) {
    // Preserve POSIX permissions when running on POSIX filesystems (Linux/Android)
    val origPerms = runCatching { Files.getPosixFilePermissions(destination.toPath()) }.getOrNull()
    try {
      Files.move(
        sourceTemp.toPath(),
        destination.toPath(),
        StandardCopyOption.REPLACE_EXISTING,
        StandardCopyOption.ATOMIC_MOVE,
      )
    } catch (_: Exception) {
      Files.move(sourceTemp.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING)
    }
    if (origPerms != null) {
      runCatching { Files.setPosixFilePermissions(destination.toPath(), origPerms) }
    }
  }

  private fun updateReferenceFileInPlace(
    file: File,
    refs: List<OsPermissionReference>,
    newCertByOldSha256: Map<String, java.security.cert.X509Certificate>,
  ): Boolean {
    if (refs.any { it.format == OsReferenceFormat.STANDALONE_CERT_FILE }) {
      val oldSha = refs.first { it.format == OsReferenceFormat.STANDALONE_CERT_FILE }.matchedSignerSha256
      val newCert = newCertByOldSha256[oldSha] ?: return false
      val temp = File.createTempFile("appsign_cert_", ".tmp", file.parentFile)
      try {
        temp.writeBytes(newCert.encoded)
        replaceInPlaceSafely(temp, file)
      } finally {
        if (temp.exists()) temp.delete()
      }
      return true
    }

    val originalText = file.readText(Charsets.UTF_8)
    var updatedText = originalText

    // 1. Replace hex DER certificates (preserving uppercase vs lowercase case style)
    updatedText =
      hexCertRegex.replace(updatedText) { match ->
        val rawHex = match.groupValues[1]
        val parsed = CryptoSupport.tryParseCertificateHex(rawHex) ?: return@replace match.value
        val oldSha = CryptoSupport.certificateFingerprints(parsed).sha256
        val replacement = newCertByOldSha256[oldSha] ?: return@replace match.value
        val isUpper = rawHex.any { it in 'A'..'F' } && rawHex.none { it in 'a'..'f' }
        CryptoSupport.encodeCertHexDer(replacement, uppercase = isUpper)
      }

    // 2. Replace PEM certificate blocks
    updatedText =
      pemCertRegex.replace(updatedText) { match ->
        val parsed =
          runCatching { CryptoSupport.parseX509Certificate(match.value.toByteArray(Charsets.UTF_8)) }.getOrNull()
            ?: return@replace match.value
        val oldSha = CryptoSupport.certificateFingerprints(parsed).sha256
        val replacement = newCertByOldSha256[oldSha] ?: return@replace match.value
        CryptoSupport.toPem("CERTIFICATE", replacement.encoded)
      }

    // 3. Replace SHA-256 and SHA-1 fingerprint references (colon-separated & compact, preserving casing)
    for ((oldSha256, newCert) in newCertByOldSha256) {
      val newFp = CryptoSupport.certificateFingerprints(newCert)
      val oldCompact256 = oldSha256.replace(":", "")
      val newCompact256 = newFp.sha256.replace(":", "")
      updatedText = replaceCasePreserving(updatedText, oldSha256, newFp.sha256)
      updatedText = replaceCasePreserving(updatedText, oldCompact256, newCompact256)

      // Lookup old SHA-1 from refs if present or skip if unrelated
      val matchingSha1Ref = refs.firstOrNull { it.format == OsReferenceFormat.SHA1_FINGERPRINT && it.matchedSignerSha256 == oldSha256 }
      if (matchingSha1Ref != null) {
        val colonSha1 = Regex("""([0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}""").find(matchingSha1Ref.previewSnippet)?.value
        if (colonSha1 != null) {
          updatedText = replaceCasePreserving(updatedText, colonSha1, newFp.sha1)
          updatedText = replaceCasePreserving(updatedText, colonSha1.replace(":", ""), newFp.sha1.replace(":", ""))
        }
      }
    }

    if (updatedText == originalText) return false

    val temp = File.createTempFile("appsign_ref_", ".tmp", file.parentFile)
    try {
      temp.writeText(updatedText, Charsets.UTF_8)
      replaceInPlaceSafely(temp, file)
    } finally {
      if (temp.exists()) temp.delete()
    }
    return true
  }

  private fun replaceCasePreserving(input: String, oldToken: String, newUpperColonToken: String): String {
    var result = input
    result = result.replace(oldToken.uppercase(), newUpperColonToken.uppercase())
    result = result.replace(oldToken.lowercase(), newUpperColonToken.lowercase())
    return result
  }

  private fun writeAskToDir(container: AskContainer, alias: String, dir: File): File {
    val safeAlias = alias.replace(Regex("[^a-zA-Z0-9_-]"), "_").ifBlank { "os_key" }
    val target = File(dir, "${safeAlias}_${container.keyId.take(8)}.ask")
    AskKeyManager.writeAsk(container, target)
    return target
  }
}
