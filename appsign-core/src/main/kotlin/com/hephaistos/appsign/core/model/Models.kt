package com.hephaistos.appsign.core.model

import java.security.PrivateKey
import java.security.cert.X509Certificate
import kotlinx.serialization.Serializable

@Serializable
enum class AskMode {
  ASK_OPEN,
  ASK_LOCKED,
}

@Serializable
enum class KeyAlgorithm(val displayName: String, val keyAlg: String, val keySizeBits: Int, val sigAlg: String) {
  RSA_2048("RSA 2048-bit", "RSA", 2048, "SHA256withRSA"),
  RSA_3072("RSA 3072-bit", "RSA", 3072, "SHA256withRSA"),
  RSA_4096("RSA 4096-bit", "RSA", 4096, "SHA512withRSA"),
  EC_P256("ECDSA P-256", "EC", 256, "SHA256withECDSA"),
  EC_P384("ECDSA P-384", "EC", 384, "SHA384withECDSA"),
}

@Serializable
enum class SignatureSchemeVersion(val label: String) {
  V1("v1 (JAR)"),
  V2("v2 (APK Signature Scheme v2)"),
  V3("v3 (APK Signature Scheme v3)"),
  V3_1("v3.1 (Key Rotation Target SDK 33+)"),
  V4("v4 (Incremental .idsig)"),
}

@Serializable
enum class VerificationStatus {
  VALID,
  VALID_WITH_WARNINGS,
  INVALID,
  UNSIGNED,
}

@Serializable
data class CertificateFingerprint(
  val sha256: String,
  val sha1: String,
  val md5: String,
)

@Serializable
data class CertificateDetails(
  val subjectDn: String,
  val issuerDn: String,
  val serialNumberHex: String,
  val notBeforeIso: String,
  val notAfterIso: String,
  val isExpired: Boolean,
  val isNotYetValid: Boolean,
  val sigAlgName: String,
  val publicKeyAlgorithm: String,
  val publicKeyBits: Int,
  val publicKeyFormat: String,
  val publicKeySha256: String,
  val fingerprints: CertificateFingerprint,
  val version: Int,
  val publicKeyPem: String,
  val certificatePem: String,
)

@Serializable
data class SchemeVerificationResult(
  val scheme: SignatureSchemeVersion,
  val present: Boolean,
  val verified: Boolean,
  val signerCount: Int,
  val signers: List<CertificateDetails> = emptyList(),
  val notes: List<String> = emptyList(),
)

@Serializable
data class KeyRotationInfo(
  val hasRotation: Boolean,
  val lineageCount: Int,
  val lineageSigners: List<CertificateDetails> = emptyList(),
  val summary: List<String> = emptyList(),
)

@Serializable
data class ApkVerificationReport(
  val apkName: String,
  val apkPath: String,
  val apkSizeBytes: Long,
  val verified: Boolean,
  val overallStatus: VerificationStatus,
  val schemeResults: List<SchemeVerificationResult>,
  val allUniqueSigners: List<CertificateDetails>,
  val hasMultipleSigners: Boolean,
  val keyRotation: KeyRotationInfo,
  val v4IdsigPresent: Boolean,
  val v4IdsigPath: String? = null,
  val errors: List<String> = emptyList(),
  val warnings: List<String> = emptyList(),
  val durationMs: Long,
  val verifiedAtIso: String,
)

@Serializable
data class SigningOptions(
  val enableV1: Boolean = true,
  val enableV2: Boolean = true,
  val enableV3: Boolean = true,
  val enableV31: Boolean = false,
  val enableV4: Boolean = false,
  val alignBeforeSign: Boolean = true,
  val minSdkVersion: Int? = null,
  val createdBy: String = "APPSIGN 1.0",
)

@Serializable
data class ApkResignResult(
  val sourcePath: String,
  val outputPath: String,
  val v4IdsigOutputPath: String? = null,
  val success: Boolean,
  val zipAligned: Boolean,
  val appliedSchemes: List<SignatureSchemeVersion> = emptyList(),
  val keyAlias: String,
  val keyFingerprintSha256: String,
  val postVerifyReport: ApkVerificationReport? = null,
  val errorMessage: String? = null,
  val durationMs: Long,
)

@Serializable
data class AskContainerMetadata(
  val alias: String,
  val createdAtIso: String,
  val updatedAtIso: String,
  val algorithm: String,
  val keySizeBits: Int,
  val subjectDn: String,
  val issuerDn: String,
  val serialNumberHex: String,
  val notBeforeIso: String,
  val notAfterIso: String,
  val fingerprints: CertificateFingerprint,
  val notes: String = "",
)

@Serializable
data class AskPrivateKeyPayload(
  val encrypted: Boolean,
  val pkcs8Base64: String? = null,
  val kdfAlgorithm: String? = null,
  val kdfIterations: Int? = null,
  val saltBase64: String? = null,
  val cipherAlgorithm: String? = null,
  val ivBase64: String? = null,
  val ciphertextBase64: String? = null,
)

@Serializable
data class AskContainer(
  val containerType: String = CONTAINER_TYPE,
  val formatVersion: Int = CURRENT_FORMAT_VERSION,
  val keyId: String,
  val mode: AskMode,
  val metadata: AskContainerMetadata,
  val x509CertificatePem: String,
  val certificateChainPem: List<String> = emptyList(),
  val publicKeyPem: String,
  val privateKeyPayload: AskPrivateKeyPayload,
) {
  companion object {
    const val CONTAINER_TYPE = "APPSIGN-KEY-CONTAINER"
    const val CURRENT_FORMAT_VERSION = 1
  }
}

@Serializable
data class AskInspectResult(
  val keyId: String,
  val formatVersion: Int,
  val mode: AskMode,
  val encrypted: Boolean,
  val metadata: AskContainerMetadata,
  val certificate: CertificateDetails,
  val chainLength: Int,
  val securityWarning: String? = null,
)

data class CreateAskOptions(
  val alias: String,
  val algorithm: KeyAlgorithm = KeyAlgorithm.RSA_2048,
  val commonName: String = "APPSIGN Key",
  val organization: String = "APPSIGN",
  val organizationalUnit: String = "Mobile Security",
  val country: String = "FR",
  val validityYears: Int = 25,
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

data class UnlockedKeyMaterial(
  val keyId: String,
  val alias: String,
  val privateKey: PrivateKey,
  val certificate: X509Certificate,
  val certificateChain: List<X509Certificate>,
)
