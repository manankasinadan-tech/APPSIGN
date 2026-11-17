package com.hephaistos.appsign.core.report

import com.hephaistos.appsign.core.model.ApkResignResult
import com.hephaistos.appsign.core.model.ApkVerificationReport
import com.hephaistos.appsign.core.model.AskInspectResult
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
}
