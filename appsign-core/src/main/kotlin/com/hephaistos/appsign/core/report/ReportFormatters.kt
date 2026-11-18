package com.hephaistos.appsign.core.report

import com.hephaistos.appsign.core.model.ApkResignResult
import com.hephaistos.appsign.core.model.ApkVerificationReport
import com.hephaistos.appsign.core.model.AskInspectResult
import com.hephaistos.appsign.core.model.OsSignInspectionReport
import com.hephaistos.appsign.core.model.OsSignResignReport
import com.hephaistos.appsign.core.model.ResignProResult
import com.hephaistos.appsign.core.model.TargetSignatureProfile
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object ReportFormatters {
  val json = Json {
    prettyPrint = true
    encodeDefaults = true
  }

  fun verificationToJson(reports: List<ApkVerificationReport>): String =
    if (reports.size == 1) json.encodeToString(reports.first()) else json.encodeToString(reports)

  fun resignToJson(results: List<ApkResignResult>): String =
    if (results.size == 1) json.encodeToString(results.first()) else json.encodeToString(results)

  fun askInspectToJson(result: AskInspectResult): String = json.encodeToString(result)

  fun targetProfileToJson(profile: TargetSignatureProfile): String = json.encodeToString(profile)

  fun resignProToJson(result: ResignProResult): String = json.encodeToString(result)

  fun osSignInspectionToJson(report: OsSignInspectionReport): String = json.encodeToString(report)

  fun osSignResignToJson(report: OsSignResignReport): String = json.encodeToString(report)

  fun verificationToText(report: ApkVerificationReport, french: Boolean = false): String =
    buildString {
      appendLine("============================================================")
      appendLine("APPSIGN VERIFICATION REPORT")
      appendLine("============================================================")
      appendLine("${if (french) "Fichier" else "File"}       : ${report.apkName}")
      appendLine("${if (french) "Chemin" else "Path"}       : ${report.apkPath}")
      appendLine("${if (french) "Taille" else "Size"}       : ${report.apkSizeBytes} bytes")
      appendLine("${if (french) "Statut" else "Status"}     : ${report.overallStatus} (verified=${report.verified})")
      appendLine("${if (french) "Durée" else "Duration"}   : ${report.durationMs} ms")
      appendLine("${if (french) "Multi-sign" else "Multi-sign"} : ${report.hasMultipleSigners}")
      appendLine(
        "${if (french) "Rotation" else "Rotation"}   : ${report.keyRotation.hasRotation} (lineage=${report.keyRotation.lineageCount})"
      )
      appendLine()
      appendLine(if (french) "--- SCHÉMAS DE SIGNATURE ---" else "--- SIGNATURE SCHEMES ---")
      for (scheme in report.schemeResults) {
        val flag =
          when {
            scheme.verified -> "VERIFIED"
            scheme.present -> "FAILED"
            else -> "ABSENT"
          }
        appendLine("  ${scheme.scheme.label.padEnd(36)} : $flag (signers=${scheme.signerCount})")
      }
      if (report.allUniqueSigners.isNotEmpty()) {
        appendLine()
        appendLine(if (french) "--- CERTIFICATS SIGNATAIRES ---" else "--- SIGNER CERTIFICATES ---")
        report.allUniqueSigners.forEachIndexed { idx, cert ->
          appendLine("  Signer #${idx + 1}:")
          appendLine("    Subject   : ${cert.subjectDn}")
          appendLine("    Issuer    : ${cert.issuerDn}")
          appendLine("    Serial    : ${cert.serialNumberHex}")
          appendLine("    Validity  : ${cert.notBeforeIso} -> ${cert.notAfterIso}")
          appendLine("    Algorithm : ${cert.sigAlgName} (${cert.publicKeyAlgorithm} ${cert.publicKeyBits}-bit)")
          appendLine("    SHA-256   : ${cert.fingerprints.sha256}")
          appendLine("    SHA-1     : ${cert.fingerprints.sha1}")
          appendLine("    MD5       : ${cert.fingerprints.md5}")
        }
      }
      if (report.warnings.isNotEmpty()) {
        appendLine()
        appendLine(if (french) "--- AVERTISSEMENTS ---" else "--- WARNINGS ---")
        report.warnings.forEach { appendLine("  [!] $it") }
      }
      if (report.errors.isNotEmpty()) {
        appendLine()
        appendLine(if (french) "--- ERREURS ---" else "--- ERRORS ---")
        report.errors.forEach { appendLine("  [X] $it") }
      }
    }

  fun resignToText(result: ApkResignResult, french: Boolean = false): String =
    buildString {
      appendLine("------------------------------------------------------------")
      appendLine("${if (french) "Source" else "Source"}    : ${result.sourcePath}")
      appendLine("${if (french) "Sortie" else "Output"}    : ${result.outputPath}")
      if (result.v4IdsigOutputPath != null) {
        appendLine("V4 .idsig : ${result.v4IdsigOutputPath}")
      }
      appendLine("${if (french) "Résultat" else "Result"}    : ${if (result.success) "SUCCESS" else "FAILED"}")
      appendLine("ZipAlign  : ${result.zipAligned}")
      appendLine("${if (french) "Schémas" else "Schemes"}   : ${result.appliedSchemes.joinToString(", ") { it.name }}")
      appendLine("${if (french) "Clé" else "Key"}       : ${result.keyAlias} (${result.keyFingerprintSha256})")
      appendLine("${if (french) "Durée" else "Duration"}  : ${result.durationMs} ms")
      if (result.errorMessage != null) {
        appendLine("${if (french) "Erreur" else "Error"}     : ${result.errorMessage}")
      }
      if (result.postVerifyReport != null) {
        appendLine(
          "${if (french) "Auto-Vérif" else "Post-Verify"}: ${result.postVerifyReport.overallStatus} (${result.postVerifyReport.durationMs} ms)"
        )
      }
    }

  fun askInspectToText(info: AskInspectResult, french: Boolean = false): String =
    buildString {
      appendLine("============================================================")
      appendLine("APPSIGN KEY CONTAINER (.ask v${info.formatVersion})")
      appendLine("============================================================")
      appendLine("Key ID    : ${info.keyId}")
      appendLine("Alias     : ${info.metadata.alias}")
      appendLine("Mode      : ${info.mode} (encrypted=${info.encrypted})")
      appendLine("Algorithm : ${info.metadata.algorithm} (${info.metadata.keySizeBits} bits)")
      appendLine("Subject   : ${info.metadata.subjectDn}")
      appendLine("Issuer    : ${info.metadata.issuerDn}")
      appendLine("Serial    : ${info.metadata.serialNumberHex}")
      appendLine("Valid     : ${info.metadata.notBeforeIso} -> ${info.metadata.notAfterIso}")
      appendLine("Chain Len : ${info.chainLength}")
      appendLine("SHA-256   : ${info.metadata.fingerprints.sha256}")
      appendLine("SHA-1     : ${info.metadata.fingerprints.sha1}")
      appendLine("MD5       : ${info.metadata.fingerprints.md5}")
      if (info.metadata.notes.isNotBlank()) {
        appendLine("Notes     : ${info.metadata.notes}")
      }
      if (info.securityWarning != null) {
        appendLine()
        appendLine("[!] ${if (french) com.hephaistos.appsign.core.ask.AskKeyManager.UNENCRYPTED_WARNING_FR else info.securityWarning}")
      }
    }

  fun resignProToText(result: ResignProResult, french: Boolean = false): String =
    buildString {
      val prof = result.targetProfile
      appendLine("============================================================")
      appendLine("APPSIGN RESIGNPRO REPORT")
      appendLine("============================================================")
      appendLine("${if (french) "Cible" else "Target"}      : ${prof.apkName}")
      appendLine(
        "${if (french) "Schémas" else "Schemes"}     : ${prof.detectedSchemes.joinToString(", ") { it.name }.ifBlank { "DEFAULT" }}"
      )
      appendLine("ZipAligned  : ${prof.wasZipAligned} | minSdk=${prof.minSdkVersion ?: "auto"}")
      appendLine(
        "${if (french) "Signataires" else "Signers"}     : ${prof.signerProfiles.size} (multi=${prof.hasMultipleSigners}, rotation=${prof.hasKeyRotation})"
      )
      result.generatedAskPaths.forEachIndexed { idx, path ->
        val askInfo = result.generatedAskContainers.getOrNull(idx)
        appendLine(
          "  ASK #${idx + 1}    : $path (${askInfo?.mode ?: "?"} • ${askInfo?.metadata?.algorithm ?: "?"} ${askInfo?.metadata?.keySizeBits ?: 0}-bit)"
        )
      }
      append(resignToText(result.resignResult, french))
    }

  fun osSignInspectionToText(report: OsSignInspectionReport, french: Boolean = false): String =
    buildString {
      appendLine("============================================================")
      appendLine("APPSIGN OS SIGN — INSPECTION DASHBOARD")
      appendLine("============================================================")
      appendLine("${if (french) "Racine" else "Root"}        : ${report.rootDirectory}")
      appendLine("${if (french) "Durée" else "Duration"}    : ${report.durationMs} ms")
      appendLine("${if (french) "Analysés" else "Scanned"}     : ${report.totalFilesVisited} file(s)")
      appendLine("${if (french) "Signés" else "Signed"}      : ${report.signedArtifactsCount}")
      appendLine("${if (french) "Préservés" else "Preserved"}   : ${report.preservedUnsignedCount}")
      appendLine("${if (french) "Symlinks" else "Symlinks"}    : ${report.symlinksIgnoredCount} (${if (french) "ignorés" else "ignored"})")
      appendLine("${if (french) "Groupes" else "Key Groups"}  : ${report.groups.size}")
      appendLine("${if (french) "Réf. perms" else "Perm Refs"}   : ${report.allPermissionReferences.size}")
      report.groups.forEachIndexed { idx, grp ->
        appendLine()
        appendLine("--- GROUP #${idx + 1}: ${grp.label} ---")
        appendLine("  SHA-256   : ${grp.sha256}")
        appendLine("  Spec      : ${grp.keySpec.keyAlgorithm} ${grp.keySpec.keySizeBits}-bit (${grp.keySpec.sigAlgName})")
        appendLine("  Subject   : ${grp.certificate.subjectDn}")
        appendLine("  Artifacts : ${grp.artifacts.size} (${grp.artifacts.joinToString(", ") { it.relativePath }.take(140)})")
        appendLine("  Perm Refs : ${grp.permissionReferences.size}")
      }
      if (report.warnings.isNotEmpty()) {
        appendLine()
        report.warnings.forEach { appendLine("  [!] $it") }
      }
    }

  fun osSignResignToText(report: OsSignResignReport, french: Boolean = false): String =
    buildString {
      appendLine("============================================================")
      appendLine("APPSIGN OS SIGN — RESIGN SUMMARY")
      appendLine("============================================================")
      appendLine("${if (french) "Racine" else "Root"}        : ${report.rootDirectory}")
      appendLine("${if (french) "Stratégie" else "Strategy"}    : ${report.strategy}")
      appendLine("${if (french) "Durée" else "Duration"}    : ${report.durationMs} ms")
      appendLine("${if (french) "Succès" else "Succeeded"}   : ${report.totalSucceeded}/${report.totalResigned}")
      appendLine("${if (french) "Échecs" else "Failed"}      : ${report.totalFailed}")
      appendLine("${if (french) "Réf. MàJ" else "Refs Updated"}: ${report.totalReferencesUpdated}")
      appendLine("${if (french) "Préservés" else "Preserved"}   : ${report.totalPreserved}")
      appendLine("${if (french) "Symlinks" else "Symlinks"}    : ${report.symlinksIgnoredCount}")
      report.generatedAskPaths.forEach { appendLine("  ASK Key   : $it") }
      if (report.backupManifest != null) {
        appendLine("  Backups   : ${report.backupManifest.entries.size} .appsign.bak")
      }
      if (report.warnings.isNotEmpty()) {
        appendLine()
        report.warnings.forEach { appendLine("  [!] $it") }
      }
    }
}
