package com.hephaistos.appsign.core.apk

import com.android.apksig.ApkVerifier
import com.hephaistos.appsign.core.ask.ApkOperationException
import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.ApkVerificationReport
import com.hephaistos.appsign.core.model.KeyRotationInfo
import com.hephaistos.appsign.core.model.SchemeVerificationResult
import com.hephaistos.appsign.core.model.SignatureSchemeVersion
import com.hephaistos.appsign.core.model.VerificationStatus
import java.io.File
import java.security.cert.X509Certificate

object ApkVerifierEngine {

  fun verify(
    apkFile: File,
    explicitIdsigFile: File? = null,
    minSdkOverride: Int? = null,
  ): ApkVerificationReport {
    if (!apkFile.exists() || !apkFile.isFile) {
      throw ApkOperationException("APK file not found: ${apkFile.absolutePath}")
    }
    val startNs = System.nanoTime()
    val candidateIdsig =
      explicitIdsigFile
        ?: File("${apkFile.absolutePath}.idsig").takeIf { it.exists() && it.isFile }

    val extraWarnings = mutableListOf<String>()
    val result =
      try {
        val builder = ApkVerifier.Builder(apkFile)
        if (minSdkOverride != null) {
          builder.setMinCheckedPlatformVersion(minSdkOverride)
        }
        if (candidateIdsig != null) {
          builder.setV4SignatureFile(candidateIdsig)
        }
        builder.build().verify()
      } catch (_: com.android.apksig.apk.MinSdkVersionException) {
        val fallbackSdk = minSdkOverride ?: 21
        extraWarnings +=
          "Could not parse minSdkVersion from AndroidManifest.xml; verified with fallback minSdkVersion=$fallbackSdk."
        try {
          val fallbackBuilder = ApkVerifier.Builder(apkFile).setMinCheckedPlatformVersion(fallbackSdk)
          if (candidateIdsig != null) {
            fallbackBuilder.setV4SignatureFile(candidateIdsig)
          }
          fallbackBuilder.build().verify()
        } catch (e: Exception) {
          throw ApkOperationException("Failed to verify APK '${apkFile.name}': ${e.message}", e)
        }
      } catch (e: Exception) {
        throw ApkOperationException("Failed to verify APK '${apkFile.name}': ${e.message}", e)
      }

    val errors = result.allErrors.map { it.toString() }.distinct().toMutableList()
    val warnings =
      buildList {
        addAll(extraWarnings)
        result.warnings.forEach { add(it.toString()) }
        result.v1SchemeSigners.forEach { signer -> signer.warnings.forEach { add(it.toString()) } }
        result.v2SchemeSigners.forEach { signer -> signer.warnings.forEach { add(it.toString()) } }
        result.v3SchemeSigners.forEach { signer -> signer.warnings.forEach { add(it.toString()) } }
        result.v31SchemeSigners.forEach { signer -> signer.warnings.forEach { add(it.toString()) } }
        result.v4SchemeSigners.forEach { signer -> signer.warnings.forEach { add(it.toString()) } }
      }.distinct().toMutableList()

    val v1Signers = result.v1SchemeSigners.mapNotNull { it.certificate }
    val v2Signers = result.v2SchemeSigners.mapNotNull { it.certificate }
    val v3Signers = result.v3SchemeSigners.mapNotNull { it.certificate }
    val v31Signers = result.v31SchemeSigners.mapNotNull { it.certificate }
    val v4Signers = result.v4SchemeSigners.mapNotNull { it.certificate }

    val v1Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V1,
        present = result.isVerifiedUsingV1Scheme || v1Signers.isNotEmpty(),
        verified = result.isVerifiedUsingV1Scheme,
        signerCount = v1Signers.size,
        signers = v1Signers.map { CryptoSupport.extractCertificateDetails(it) },
        notes =
          buildList {
            if (!result.isVerifiedUsingV1Scheme && v1Signers.isEmpty()) {
              add("No JAR (v1) signature present.")
            }
          },
      )

    val v2Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V2,
        present = result.isVerifiedUsingV2Scheme || v2Signers.isNotEmpty(),
        verified = result.isVerifiedUsingV2Scheme,
        signerCount = v2Signers.size,
        signers = v2Signers.map { CryptoSupport.extractCertificateDetails(it) },
      )

    val v3Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V3,
        present = result.isVerifiedUsingV3Scheme || v3Signers.isNotEmpty(),
        verified = result.isVerifiedUsingV3Scheme,
        signerCount = v3Signers.size,
        signers = v3Signers.map { CryptoSupport.extractCertificateDetails(it) },
      )

    val v31Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V3_1,
        present = result.isVerifiedUsingV31Scheme || v31Signers.isNotEmpty(),
        verified = result.isVerifiedUsingV31Scheme,
        signerCount = v31Signers.size,
        signers = v31Signers.map { CryptoSupport.extractCertificateDetails(it) },
      )

    val v4Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V4,
        present = candidateIdsig != null || result.isVerifiedUsingV4Scheme || v4Signers.isNotEmpty(),
        verified = result.isVerifiedUsingV4Scheme,
        signerCount = v4Signers.size,
        signers = v4Signers.map { CryptoSupport.extractCertificateDetails(it) },
        notes =
          buildList {
            if (candidateIdsig == null) {
              add("No companion .idsig v4 signature file found alongside APK.")
            }
          },
      )

    val schemeResults = listOf(v1Result, v2Result, v3Result, v31Result, v4Result)

    val uniqueCertMap = linkedMapOf<String, X509Certificate>()
    for (cert in result.signerCertificates) {
      val sha256 = CryptoSupport.certificateFingerprints(cert).sha256
      uniqueCertMap.putIfAbsent(sha256, cert)
    }
    val allUniqueDetails = uniqueCertMap.values.map { CryptoSupport.extractCertificateDetails(it) }

    // Cryptographic & validity advisories
    for (certDetails in allUniqueDetails) {
      if (certDetails.isExpired) {
        warnings += "Certificate '${certDetails.subjectDn}' expired on ${certDetails.notAfterIso}."
      }
      if (certDetails.isNotYetValid) {
        warnings += "Certificate '${certDetails.subjectDn}' is not valid until ${certDetails.notBeforeIso}."
      }
      if (certDetails.publicKeyAlgorithm.equals("RSA", ignoreCase = true) && certDetails.publicKeyBits < 2048) {
        warnings += "Weak RSA key size (${certDetails.publicKeyBits} bits) detected; 2048+ bits recommended."
      }
      if (certDetails.sigAlgName.contains("SHA1", ignoreCase = true) || certDetails.sigAlgName.contains("MD5", ignoreCase = true)) {
        warnings += "Legacy certificate signature algorithm '${certDetails.sigAlgName}' detected."
      }
    }

    // Key rotation lineage detection
    val lineage = result.signingCertificateLineage
    val lineageCerts = lineage?.certificatesInLineage ?: emptyList()
    val hasRotation = lineageCerts.size > 1
    val lineageDetails = lineageCerts.map { CryptoSupport.extractCertificateDetails(it) }
    val rotationSummary =
      if (hasRotation) {
        lineageDetails.mapIndexed { index, details ->
          "#${index + 1}: ${details.subjectDn} (${details.fingerprints.sha256.take(23)}...)"
        }
      } else {
        emptyList()
      }

    val anySchemePresent = schemeResults.any { it.present }
    val status =
      when {
        !result.isVerified && !anySchemePresent -> VerificationStatus.UNSIGNED
        !result.isVerified -> VerificationStatus.INVALID
        warnings.isNotEmpty() -> VerificationStatus.VALID_WITH_WARNINGS
        else -> VerificationStatus.VALID
      }

    val durationMs = (System.nanoTime() - startNs) / 1_000_000L

    return ApkVerificationReport(
      apkName = apkFile.name,
      apkPath = apkFile.absolutePath,
      apkSizeBytes = apkFile.length(),
      verified = result.isVerified,
      overallStatus = status,
      schemeResults = schemeResults,
      allUniqueSigners = allUniqueDetails,
      hasMultipleSigners = allUniqueDetails.size > 1,
      keyRotation =
        KeyRotationInfo(
          hasRotation = hasRotation,
          lineageCount = lineageDetails.size,
          lineageSigners = lineageDetails,
          summary = rotationSummary,
        ),
      v4IdsigPresent = candidateIdsig != null,
      v4IdsigPath = candidateIdsig?.absolutePath,
      errors = errors.distinct(),
      warnings = warnings.distinct(),
      durationMs = durationMs,
      verifiedAtIso = CryptoSupport.nowIso(),
    )
  }
}
