package com.hephaistos.appsign.core.apk

import com.android.apksig.ApkSigner
import com.hephaistos.appsign.core.ask.ApkOperationException
import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.ApkResignResult
import com.hephaistos.appsign.core.model.SignatureSchemeVersion
import com.hephaistos.appsign.core.model.SigningOptions
import com.hephaistos.appsign.core.model.UnlockedKeyMaterial
import java.io.File

object ApkSignerEngine {

  fun resign(
    inputApk: File,
    outputApk: File,
    keyMaterial: UnlockedKeyMaterial,
    options: SigningOptions = SigningOptions(),
  ): ApkResignResult {
    if (!inputApk.exists() || !inputApk.isFile) {
      throw ApkOperationException("Input APK not found: ${inputApk.absolutePath}")
    }
    if (inputApk.canonicalFile == outputApk.canonicalFile) {
      throw ApkOperationException(
        "Output APK path cannot overwrite the original input APK (${inputApk.name})."
      )
    }
    if (!options.enableV1 && !options.enableV2 && !options.enableV3 && !options.enableV31 && !options.enableV4) {
      throw ApkOperationException("At least one signature scheme (v1, v2, v3, v3.1, v4) must be enabled.")
    }
    if (options.enableV4 && !options.enableV2 && !options.enableV3 && !options.enableV31) {
      throw ApkOperationException("APK Signature Scheme v4 requires v2 or v3 to also be enabled.")
    }

    val startNs = System.nanoTime()
    val certFingerprint = CryptoSupport.certificateFingerprints(keyMaterial.certificate).sha256
    var tempAlignedFile: File? = null

    return try {
      outputApk.parentFile?.mkdirs()
      val effectiveInput: File
      val aligned: Boolean
      if (options.alignBeforeSign) {
        tempAlignedFile = File.createTempFile("appsign_aligned_", ".apk")
        aligned = PureJvmZipAligner.align(inputApk, tempAlignedFile)
        effectiveInput = tempAlignedFile
      } else {
        aligned = PureJvmZipAligner.isAligned(inputApk)
        effectiveInput = inputApk
      }

      val signerConfig =
        ApkSigner.SignerConfig.Builder(
            keyMaterial.alias,
            com.android.apksig.KeyConfig.Jca(keyMaterial.privateKey),
            keyMaterial.certificateChain,
          )
          .build()

      val effectiveV3 = options.enableV3 || options.enableV31
      val v4OutputFile =
        if (options.enableV4) File("${outputApk.absolutePath}.idsig") else null

      val builder =
        ApkSigner.Builder(listOf(signerConfig))
          .setInputApk(effectiveInput)
          .setOutputApk(outputApk)
          .setV1SigningEnabled(options.enableV1)
          .setV2SigningEnabled(options.enableV2)
          .setV3SigningEnabled(effectiveV3)
          .setV4SigningEnabled(options.enableV4)
          .setCreatedBy(options.createdBy)

      if (v4OutputFile != null) {
        builder.setV4SignatureOutputFile(v4OutputFile)
      }
      if (options.minSdkVersion != null) {
        builder.setMinSdkVersion(options.minSdkVersion)
      }

      builder.build().sign()

      val appliedSchemes = buildList {
        if (options.enableV1) add(SignatureSchemeVersion.V1)
        if (options.enableV2) add(SignatureSchemeVersion.V2)
        if (effectiveV3) add(if (options.enableV31) SignatureSchemeVersion.V3_1 else SignatureSchemeVersion.V3)
        if (options.enableV4) add(SignatureSchemeVersion.V4)
      }

      // Mandatory automatic post-sign verification
      val postReport = ApkVerifierEngine.verify(outputApk, v4OutputFile, options.minSdkVersion)
      val durationMs = (System.nanoTime() - startNs) / 1_000_000L

      ApkResignResult(
        sourcePath = inputApk.absolutePath,
        outputPath = outputApk.absolutePath,
        v4IdsigOutputPath = v4OutputFile?.absolutePath,
        success = postReport.verified,
        zipAligned = aligned,
        appliedSchemes = appliedSchemes,
        keyAlias = keyMaterial.alias,
        keyFingerprintSha256 = certFingerprint,
        postVerifyReport = postReport,
        errorMessage = if (postReport.verified) null else postReport.errors.joinToString("; "),
        durationMs = durationMs,
      )
    } catch (e: Exception) {
      val durationMs = (System.nanoTime() - startNs) / 1_000_000L
      ApkResignResult(
        sourcePath = inputApk.absolutePath,
        outputPath = outputApk.absolutePath,
        v4IdsigOutputPath = null,
        success = false,
        zipAligned = false,
        appliedSchemes = emptyList(),
        keyAlias = keyMaterial.alias,
        keyFingerprintSha256 = certFingerprint,
        postVerifyReport = null,
        errorMessage = e.message ?: "Unknown signing error",
        durationMs = durationMs,
      )
    } finally {
      tempAlignedFile?.delete()
    }
  }

  fun resignBatch(
    inputApks: List<File>,
    outputDir: File,
    keyMaterial: UnlockedKeyMaterial,
    options: SigningOptions = SigningOptions(),
    suffix: String = "-signed",
    onProgress: (index: Int, total: Int, fileName: String) -> Unit = { _, _, _ -> },
  ): List<ApkResignResult> {
    outputDir.mkdirs()
    return inputApks.mapIndexed { idx, inputFile ->
      onProgress(idx + 1, inputApks.size, inputFile.name)
      val baseName = inputFile.nameWithoutExtension
      val ext = inputFile.extension.ifBlank { "apk" }
      val candidateOut = File(outputDir, "$baseName$suffix.$ext")
      val safeOut =
        if (candidateOut.canonicalFile == inputFile.canonicalFile) {
          File(outputDir, "${baseName}_resigned.$ext")
        } else {
          candidateOut
        }
      resign(inputFile, safeOut, keyMaterial, options)
    }
  }
}
