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
        val initialFallback = minSdkOverride ?: 21
        try {
          fun verifyWithSdk(sdk: Int): ApkVerifier.Result {
            val b = ApkVerifier.Builder(apkFile).setMinCheckedPlatformVersion(sdk)
            if (candidateIdsig != null) b.setV4SignatureFile(candidateIdsig)
            return b.build().verify()
          }
          var resolvedSdk = initialFallback
          var res = verifyWithSdk(initialFallback)
          if (
            minSdkOverride == null &&
              !res.isVerified &&
              !res.isVerifiedUsingV1Scheme &&
              res.v1SchemeSigners.isEmpty() &&
              (res.v2SchemeSigners.isNotEmpty() || res.v3SchemeSigners.isNotEmpty() || res.v31SchemeSigners.isNotEmpty())
          ) {
            val targetSdk = if (res.v2SchemeSigners.isNotEmpty()) 24 else 28
            val higherRes = verifyWithSdk(targetSdk)
            if (higherRes.isVerified) {
              resolvedSdk = targetSdk
              res = higherRes
            }
          }
          extraWarnings +=
            "Could not parse minSdkVersion from AndroidManifest.xml; verified with fallback minSdkVersion=$resolvedSdk."
          res
        } catch (e: Exception) {
          throw ApkOperationException("Failed to verify APK '${apkFile.name}': ${e.message}", e)
        }
      } catch (e: Exception) {
        throw ApkOperationException("Failed to verify APK '${apkFile.name}': ${e.message}", e)
      }

    // Physical + cryptographic per-scheme inspection so v1/v2 are NEVER masked on high-minSdk APKs
    val blockInfo = ApkSigningBlockInspector.inspect(apkFile)

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

    // V1: Combine apksig result + JAR signature verification when minSdk >= 24 caused apksig to skip V1
    val apksigV1Signers = result.v1SchemeSigners.mapNotNull { it.certificate }
    val v1JarVerification =
      if (blockInfo.v1EntriesPresent && !result.isVerifiedUsingV1Scheme) {
        JarSignerEngine.verifyJar(apkFile)
      } else {
        null
      }
    val v1Signers =
      when {
        apksigV1Signers.isNotEmpty() -> apksigV1Signers
        blockInfo.v1ExtractedSigners.isNotEmpty() -> blockInfo.v1ExtractedSigners
        v1JarVerification != null && v1JarVerification.signers.isNotEmpty() ->
          v1JarVerification.signers.map {
            CryptoSupport.parseX509Certificate(it.certificatePem.toByteArray(Charsets.UTF_8))
          }
        else -> emptyList()
      }
    val v1Present =
      result.isVerifiedUsingV1Scheme ||
        apksigV1Signers.isNotEmpty() ||
        blockInfo.v1EntriesPresent
    val v1Verified =
      result.isVerifiedUsingV1Scheme || (v1JarVerification?.verified == true)

    // V2: Combine apksig result + physical APK Signing Block V2 inspection & verification
    val apksigV2Signers = result.v2SchemeSigners.mapNotNull { it.certificate }
    val v2Signers = if (apksigV2Signers.isNotEmpty()) apksigV2Signers else blockInfo.v2Signers
    val v2Present = result.isVerifiedUsingV2Scheme || v2Signers.isNotEmpty() || blockInfo.v2Present
    val v2Verified = result.isVerifiedUsingV2Scheme || blockInfo.v2Verified

    // V3: Combine apksig result + physical APK Signing Block V3 inspection & verification
    val apksigV3Signers = result.v3SchemeSigners.mapNotNull { it.certificate }
    val v3Signers = if (apksigV3Signers.isNotEmpty()) apksigV3Signers else blockInfo.v3Signers
    val v3Present = result.isVerifiedUsingV3Scheme || v3Signers.isNotEmpty() || blockInfo.v3Present
    val v3Verified = result.isVerifiedUsingV3Scheme || blockInfo.v3Verified

    // V3.1: Combine apksig result + physical V3.1 block
    val apksigV31Signers = result.v31SchemeSigners.mapNotNull { it.certificate }
    val v31Signers = if (apksigV31Signers.isNotEmpty()) apksigV31Signers else blockInfo.v31Signers
    val v31Present = result.isVerifiedUsingV31Scheme || v31Signers.isNotEmpty() || blockInfo.v31Present
    val v31Verified = result.isVerifiedUsingV31Scheme

    // V4
    val v4Signers = result.v4SchemeSigners.mapNotNull { it.certificate }

    val v1Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V1,
        present = v1Present,
        verified = v1Verified,
        signerCount = v1Signers.size,
        signers = v1Signers.map { CryptoSupport.extractCertificateDetails(it) },
        notes =
          buildList {
            if (!v1Present) {
              add("No JAR (v1) signature present.")
            } else if (!result.isVerifiedUsingV1Scheme && v1JarVerification?.verified == true) {
              add("JAR (v1) signature present and verified independently (manifest minSdk skips v1 at runtime).")
            }
          },
      )

    val v2Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V2,
        present = v2Present,
        verified = v2Verified,
        signerCount = v2Signers.size,
        signers = v2Signers.map { CryptoSupport.extractCertificateDetails(it) },
        notes =
          buildList {
            if (v2Present && !result.isVerifiedUsingV2Scheme && blockInfo.v2Verified) {
              add("APK Signature Scheme v2 present and verified from APK Signing Block (0x7109871a).")
            }
          },
      )

    val v3Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V3,
        present = v3Present,
        verified = v3Verified,
        signerCount = v3Signers.size,
        signers = v3Signers.map { CryptoSupport.extractCertificateDetails(it) },
      )

    val v31Result =
      SchemeVerificationResult(
        scheme = SignatureSchemeVersion.V3_1,
        present = v31Present,
        verified = v31Verified,
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
    fun registerCerts(certs: List<X509Certificate>) {
      for (cert in certs) {
        val sha256 = CryptoSupport.certificateFingerprints(cert).sha256
        uniqueCertMap.putIfAbsent(sha256, cert)
      }
    }
    registerCerts(result.signerCertificates)
    registerCerts(v31Signers)
    registerCerts(v3Signers)
    registerCerts(v2Signers)
    registerCerts(v1Signers)
    registerCerts(v4Signers)

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
