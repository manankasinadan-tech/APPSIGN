package com.hephaistos.appsign.core.model

import kotlinx.serialization.Serializable

// --- RESIGNPRO MODELS ---

@Serializable
data class SignerCryptographicProfile(
  val signerIndex: Int,
  val detectedSubjectDn: String,
  val detectedIssuerDn: String,
  val detectedSha256: String,
  val detectedSha1: String,
  val keySpec: ExactKeySpec,
  val serialNumberHex: String,
  val notBeforeIso: String,
  val notAfterIso: String,
  val validityDays: Long,
  val presentInSchemes: List<SignatureSchemeVersion>,
)

@Serializable
data class TargetSignatureProfile(
  val apkPath: String,
  val apkName: String,
  val detectedSchemes: List<SignatureSchemeVersion>,
  val enableV1: Boolean,
  val enableV2: Boolean,
  val enableV3: Boolean,
  val enableV31: Boolean,
  val enableV4: Boolean,
  val wasZipAligned: Boolean,
  val minSdkVersion: Int? = null,
  val signerProfiles: List<SignerCryptographicProfile>,
  val hasMultipleSigners: Boolean,
  val hasKeyRotation: Boolean,
  val lineageCount: Int,
  val verificationReport: ApkVerificationReport,
)

data class IdentityInput(
  val alias: String,
  val commonName: String,
  val organization: String = "APPSIGN",
  val organizationalUnit: String = "Security",
  val country: String = "FR",
  val passphrase: CharArray? = null,
  val notes: String = "",
) {
  fun buildSubjectDn(): String {
    val parts = buildList {
      if (commonName.isNotBlank()) add("CN=${escapeDn(commonName)}")
      if (organizationalUnit.isNotBlank()) add("OU=${escapeDn(organizationalUnit)}")
      if (organization.isNotBlank()) add("O=${escapeDn(organization)}")
      if (country.isNotBlank()) add("C=${escapeDn(country)}")
    }
    return if (parts.isEmpty()) "CN=APPSIGN" else parts.joinToString(", ")
  }

  private fun escapeDn(value: String): String =
    value.replace("\\", "\\\\").replace(",", "\\,").replace("+", "\\+").replace("=", "\\=")
}

@Serializable
data class ResignProResult(
  val targetProfile: TargetSignatureProfile,
  val generatedAskContainers: List<AskInspectResult>,
  val generatedAskPaths: List<String>,
  val resignResult: ApkResignResult,
)

// --- OS SIGN MODELS ---

@Serializable
enum class OsArtifactKind {
  APK,
  APEX,
  JAR,
}

@Serializable
enum class OsTrustAction {
  REQUIRES_RESIGN,
  PRESERVED_UNSIGNED,
  IGNORED_SYMLINK,
  UNSUPPORTED_ARCHIVE,
}

@Serializable
enum class OsReferenceFormat {
  XML_HEX_CERT,
  PEM_CERT_BLOCK,
  BASE64_DER_CERT,
  SHA256_FINGERPRINT,
  SHA1_FINGERPRINT,
  APEX_PUBKEY_ENTRY,
  STANDALONE_CERT_FILE,
}

@Serializable
enum class OsResignKeyStrategy {
  CREATE_WITH_IDENTITIES,
  USE_EXISTING_KEYS,
  CLONE_DETECTED_KEYS,
}

@Serializable
data class OsScannedArtifact(
  val relativePath: String,
  val absolutePath: String,
  val kind: OsArtifactKind,
  val sizeBytes: Long,
  val verified: Boolean,
  val status: VerificationStatus,
  val primarySignerSha256: String? = null,
  val allSignerSha256s: List<String> = emptyList(),
  val schemes: List<SignatureSchemeVersion> = emptyList(),
  val inferredRole: String = "",
  val trustAction: OsTrustAction,
  val reason: String = "",
  val apkReport: ApkVerificationReport? = null,
  val apexHasEmbeddedPubKey: Boolean = false,
  val apexPayloadWarning: String? = null,
)

@Serializable
data class OsPermissionReference(
  val relativePath: String,
  val absolutePath: String,
  val format: OsReferenceFormat,
  val matchedSignerSha256: String,
  val occurrences: Int,
  val previewSnippet: String = "",
  val writableUpdateSupported: Boolean = true,
)

@Serializable
data class OsSignatureGroup(
  val groupId: String,
  val label: String,
  val sha256: String,
  val certificate: CertificateDetails,
  val keySpec: ExactKeySpec,
  val recommendedSchemes: List<SignatureSchemeVersion>,
  val artifacts: List<OsScannedArtifact>,
  val permissionReferences: List<OsPermissionReference>,
  val hasMultipleSignersInMembers: Boolean = false,
  val hasKeyRotationInMembers: Boolean = false,
  val validityDays: Long = 365L * 25L,
)

@Serializable
data class OsSignInspectionReport(
  val rootDirectory: String,
  val scannedAtIso: String,
  val durationMs: Long,
  val totalFilesVisited: Int,
  val symlinksIgnoredCount: Int,
  val signedArtifactsCount: Int,
  val preservedUnsignedCount: Int,
  val groups: List<OsSignatureGroup>,
  val preservedArtifacts: List<OsScannedArtifact>,
  val allPermissionReferences: List<OsPermissionReference>,
  val trustChainSummary: List<String>,
  val warnings: List<String> = emptyList(),
)

@Serializable
data class OsBackupEntry(
  val originalPath: String,
  val backupPath: String,
  val kind: String, // "BINARY" or "REFERENCE"
)

@Serializable
data class OsBackupManifest(
  val sessionId: String,
  val rootDirectory: String,
  val createdAtIso: String,
  val entries: List<OsBackupEntry>,
)

@Serializable
data class OsArtifactResignOutcome(
  val relativePath: String,
  val absolutePath: String,
  val kind: String,
  val groupLabel: String,
  val newKeyAlias: String,
  val newKeySha256: String,
  val success: Boolean,
  val backedUp: Boolean,
  val details: String,
)

@Serializable
data class OsSignResignReport(
  val rootDirectory: String,
  val strategy: OsResignKeyStrategy,
  val durationMs: Long,
  val totalResigned: Int,
  val totalSucceeded: Int,
  val totalFailed: Int,
  val totalReferencesUpdated: Int,
  val totalPreserved: Int,
  val symlinksIgnoredCount: Int,
  val generatedAskPaths: List<String>,
  val generatedAskKeys: List<AskInspectResult>,
  val outcomes: List<OsArtifactResignOutcome>,
  val backupManifest: OsBackupManifest? = null,
  val warnings: List<String> = emptyList(),
)
