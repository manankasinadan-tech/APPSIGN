package com.hephaistos.appsign.core.pro

import com.android.apksig.apk.ApkUtils
import com.hephaistos.appsign.core.apk.ApkSignerEngine
import com.hephaistos.appsign.core.apk.ApkVerifierEngine
import com.hephaistos.appsign.core.apk.PureJvmZipAligner
import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.AskContainer
import com.hephaistos.appsign.core.model.AskInspectResult
import com.hephaistos.appsign.core.model.CertificateDetails
import com.hephaistos.appsign.core.model.ExactKeySpec
import com.hephaistos.appsign.core.model.IdentityInput
import com.hephaistos.appsign.core.model.ResignProResult
import com.hephaistos.appsign.core.model.SignatureSchemeVersion
import com.hephaistos.appsign.core.model.SignerCryptographicProfile
import com.hephaistos.appsign.core.model.SigningOptions
import com.hephaistos.appsign.core.model.TargetSignatureProfile
import com.hephaistos.appsign.core.model.UnlockedKeyMaterial
import java.io.File
import java.nio.ByteBuffer
import java.time.Duration
import java.time.Instant
import java.util.zip.ZipFile

object ResignProEngine {

  fun analyzeTarget(apkFile: File): TargetSignatureProfile {
    val report = ApkVerifierEngine.verify(apkFile)
    val isAligned = runCatching { PureJvmZipAligner.isAligned(apkFile) }.getOrDefault(true)
    val minSdk = extractMinSdkVersion(apkFile)

    val detectedSchemes = report.schemeResults.filter { it.present }.map { it.scheme }
    val hasV1 = report.schemeResults.any { it.scheme == SignatureSchemeVersion.V1 && it.present }
    val hasV2 = report.schemeResults.any { it.scheme == SignatureSchemeVersion.V2 && it.present }
    val hasV3 = report.schemeResults.any { it.scheme == SignatureSchemeVersion.V3 && it.present }
    val hasV31 = report.schemeResults.any { it.scheme == SignatureSchemeVersion.V3_1 && it.present }
    val hasV4 = report.schemeResults.any { it.scheme == SignatureSchemeVersion.V4 && it.present }

    val effectiveV1 = if (detectedSchemes.isEmpty()) true else hasV1
    val effectiveV2 = if (detectedSchemes.isEmpty()) true else hasV2
    val effectiveV3 = if (detectedSchemes.isEmpty()) true else (hasV3 || hasV31)

    val signerProfiles =
      if (report.allUniqueSigners.isEmpty()) {
        listOf(
          SignerCryptographicProfile(
            signerIndex = 0,
            detectedSubjectDn = "UNSIGNED TARGET",
            detectedIssuerDn = "UNSIGNED TARGET",
            detectedSha256 = "NONE",
            detectedSha1 = "NONE",
            keySpec = ExactKeySpec("RSA", 2048, "SHA256withRSA", null),
            serialNumberHex = "0",
            notBeforeIso = CryptoSupport.nowIso(),
            notAfterIso = CryptoSupport.nowIso(),
            validityDays = 365L * 25L,
            presentInSchemes = emptyList(),
          )
        )
      } else {
        report.allUniqueSigners.mapIndexed { idx, certDetails ->
          val cert = CryptoSupport.parseX509Certificate(certDetails.certificatePem.toByteArray(Charsets.UTF_8))
          val spec = CryptoSupport.extractExactKeySpec(cert)
          val schemesForSigner =
            report.schemeResults
              .filter { sr -> sr.signers.any { it.fingerprints.sha256 == certDetails.fingerprints.sha256 } }
              .map { it.scheme }
          val days = computeValidityDays(certDetails)
          SignerCryptographicProfile(
            signerIndex = idx,
            detectedSubjectDn = certDetails.subjectDn,
            detectedIssuerDn = certDetails.issuerDn,
            detectedSha256 = certDetails.fingerprints.sha256,
            detectedSha1 = certDetails.fingerprints.sha1,
            keySpec = spec,
            serialNumberHex = certDetails.serialNumberHex,
            notBeforeIso = certDetails.notBeforeIso,
            notAfterIso = certDetails.notAfterIso,
            validityDays = days,
            presentInSchemes = schemesForSigner,
          )
        }
      }

    return TargetSignatureProfile(
      apkPath = apkFile.absolutePath,
      apkName = apkFile.name,
      detectedSchemes = detectedSchemes,
      enableV1 = effectiveV1,
      enableV2 = effectiveV2,
      enableV3 = effectiveV3,
      enableV31 = hasV31,
      enableV4 = hasV4 && (effectiveV2 || effectiveV3),
      wasZipAligned = isAligned,
      minSdkVersion = minSdk,
      signerProfiles = signerProfiles,
      hasMultipleSigners = signerProfiles.size > 1,
      hasKeyRotation = report.keyRotation.hasRotation,
      lineageCount = report.keyRotation.lineageCount,
      verificationReport = report,
    )
  }

  fun buildMatchedSigningOptions(profile: TargetSignatureProfile): SigningOptions =
    SigningOptions(
      enableV1 = profile.enableV1,
      enableV2 = profile.enableV2,
      enableV3 = profile.enableV3,
      enableV31 = profile.enableV31,
      enableV4 = profile.enableV4,
      alignBeforeSign = profile.wasZipAligned || true,
      minSdkVersion = profile.minSdkVersion,
    )

  fun generateMatchedAskKey(
    signerProfile: SignerCryptographicProfile,
    identity: IdentityInput,
  ): Pair<AskContainer, UnlockedKeyMaterial> {
    val subjectDn = identity.buildSubjectDn()
    val notes =
      identity.notes.ifBlank {
        "RESIGNPRO matched spec (${signerProfile.keySpec.keyAlgorithm} ${signerProfile.keySpec.keySizeBits}-bit ${signerProfile.keySpec.sigAlgName}) from target SHA-256=${signerProfile.detectedSha256.take(23)}"
      }
    val container =
      AskKeyManager.createAskFromExactSpec(
        alias = identity.alias.trim().ifBlank { "resignpro-key" },
        spec = signerProfile.keySpec,
        subjectDn = subjectDn,
        issuerDn = subjectDn,
        validityDays = signerProfile.validityDays,
        passphrase = identity.passphrase,
        notes = notes,
      )
    val unlocked = AskKeyManager.unlockAsk(container, identity.passphrase)
    return container to unlocked
  }

  fun resignPro(
    inputApk: File,
    outputApk: File,
    identities: List<IdentityInput>,
    askOutputDir: File,
    targetProfileOverride: TargetSignatureProfile? = null,
    onAskCreated: (AskContainer, File) -> Unit = { _, _ -> },
  ): ResignProResult {
    val profile = targetProfileOverride ?: analyzeTarget(inputApk)
    val options = buildMatchedSigningOptions(profile)
    askOutputDir.mkdirs()

    val containers = mutableListOf<AskContainer>()
    val unlockedSigners = mutableListOf<UnlockedKeyMaterial>()
    val askPaths = mutableListOf<String>()

    profile.signerProfiles.forEachIndexed { idx, signerProf ->
      val baseId = identities.getOrNull(idx) ?: identities.first()
      val effectiveAlias =
        if (profile.signerProfiles.size > 1 && identities.size == 1) {
          "${baseId.alias}_s${idx + 1}"
        } else {
          baseId.alias
        }
      val effectiveId = baseId.copy(alias = effectiveAlias)
      val (container, unlocked) = generateMatchedAskKey(signerProf, effectiveId)
      val safeName = effectiveAlias.replace(Regex("[^a-zA-Z0-9_-]"), "_").ifBlank { "resignpro" }
      val askFile = File(askOutputDir, "${safeName}_${container.keyId.take(8)}.ask")
      AskKeyManager.writeAsk(container, askFile)
      onAskCreated(container, askFile)
      containers += container
      unlockedSigners += unlocked
      askPaths += askFile.absolutePath
    }

    val resignRes = ApkSignerEngine.resignWithSigners(inputApk, outputApk, unlockedSigners, options)
    return ResignProResult(
      targetProfile = profile,
      generatedAskContainers = containers.map { AskKeyManager.inspectAsk(it) },
      generatedAskPaths = askPaths,
      resignResult = resignRes,
    )
  }

  private fun computeValidityDays(certDetails: CertificateDetails): Long {
    return runCatching {
      val start = Instant.parse(certDetails.notBeforeIso)
      val end = Instant.parse(certDetails.notAfterIso)
      Duration.between(start, end).toDays().coerceIn(365L, 36500L)
    }.getOrDefault(365L * 25L)
  }

  fun extractMinSdkVersion(apkFile: File): Int? {
    return runCatching {
      ZipFile(apkFile).use { zip ->
        val entry = zip.getEntry("AndroidManifest.xml") ?: return@runCatching null
        val bytes = zip.getInputStream(entry).use { it.readBytes() }
        ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(ByteBuffer.wrap(bytes))
      }
    }.getOrNull()
  }
}
