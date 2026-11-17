package com.hephaistos.appsign.core.ask

import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.AskContainer
import com.hephaistos.appsign.core.model.AskContainerMetadata
import com.hephaistos.appsign.core.model.AskInspectResult
import com.hephaistos.appsign.core.model.AskMode
import com.hephaistos.appsign.core.model.AskPrivateKeyPayload
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.UnlockedKeyMaterial
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.UUID
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object AskKeyManager {
  const val KDF_ALGORITHM = "PBKDF2WithHmacSHA256"
  const val KDF_ITERATIONS = 600_000
  const val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
  const val UNENCRYPTED_WARNING_EN =
    "SECURITY WARNING: Private key is NOT encrypted. Anyone who obtains this file can sign APKs as you."
  const val UNENCRYPTED_WARNING_FR =
    "AVERTISSEMENT DE SÉCURITÉ : La clé privée n'est PAS chiffrée. Toute personne obtenant ce fichier peut signer des APK en votre nom."

  private val json = Json {
    prettyPrint = true
    encodeDefaults = true
    ignoreUnknownKeys = false
  }

  private val lenientJson = Json {
    prettyPrint = true
    encodeDefaults = true
    ignoreUnknownKeys = true
  }

  fun createAsk(options: CreateAskOptions): AskContainer {
    if (options.alias.isBlank()) {
      throw AskFormatException("Key alias cannot be blank.")
    }
    val (keyPair, cert) = CryptoSupport.generateKeyPairAndSelfSignedCert(options)
    return buildContainerFromMaterial(
      alias = options.alias.trim(),
      privateKey = keyPair.private,
      chain = listOf(cert),
      passphrase = options.passphrase,
      notes = options.notes,
    )
  }

  fun buildContainerFromMaterial(
    alias: String,
    privateKey: PrivateKey,
    chain: List<X509Certificate>,
    passphrase: CharArray? = null,
    notes: String = "",
    existingKeyId: String? = null,
    existingCreatedAt: String? = null,
  ): AskContainer {
    if (chain.isEmpty()) {
      throw AskFormatException("Certificate chain cannot be empty.")
    }
    val leafCert = chain.first()
    CryptoSupport.verifyPrivateKeyMatchesCertificate(privateKey, leafCert)

    val keyId = existingKeyId ?: UUID.randomUUID().toString()
    val now = CryptoSupport.nowIso()
    val certDetails = CryptoSupport.extractCertificateDetails(leafCert)
    val mode = if (passphrase != null && passphrase.isNotEmpty()) AskMode.ASK_LOCKED else AskMode.ASK_OPEN
    val pkcs8Bytes = privateKey.encoded

    val payload =
      if (mode == AskMode.ASK_LOCKED && passphrase != null) {
        val salt = CryptoSupport.randomBytes(16)
        val iv = CryptoSupport.randomBytes(12)
        val aesKey = CryptoSupport.deriveAesKeyPbkdf2(passphrase, salt, KDF_ITERATIONS)
        val aad = buildAad(AskContainer.CURRENT_FORMAT_VERSION, keyId, mode)
        val encrypted = CryptoSupport.encryptAesGcm(pkcs8Bytes, aesKey, iv, aad)
        AskPrivateKeyPayload(
          encrypted = true,
          pkcs8Base64 = null,
          kdfAlgorithm = KDF_ALGORITHM,
          kdfIterations = KDF_ITERATIONS,
          saltBase64 = Base64.getEncoder().encodeToString(salt),
          cipherAlgorithm = CIPHER_ALGORITHM,
          ivBase64 = Base64.getEncoder().encodeToString(iv),
          ciphertextBase64 = Base64.getEncoder().encodeToString(encrypted),
        )
      } else {
        AskPrivateKeyPayload(
          encrypted = false,
          pkcs8Base64 = Base64.getEncoder().encodeToString(pkcs8Bytes),
        )
      }

    val metadata =
      AskContainerMetadata(
        alias = alias,
        createdAtIso = existingCreatedAt ?: now,
        updatedAtIso = now,
        algorithm = certDetails.publicKeyAlgorithm,
        keySizeBits = certDetails.publicKeyBits,
        subjectDn = certDetails.subjectDn,
        issuerDn = certDetails.issuerDn,
        serialNumberHex = certDetails.serialNumberHex,
        notBeforeIso = certDetails.notBeforeIso,
        notAfterIso = certDetails.notAfterIso,
        fingerprints = certDetails.fingerprints,
        notes = notes,
      )

    return AskContainer(
      containerType = AskContainer.CONTAINER_TYPE,
      formatVersion = AskContainer.CURRENT_FORMAT_VERSION,
      keyId = keyId,
      mode = mode,
      metadata = metadata,
      x509CertificatePem = certDetails.certificatePem,
      certificateChainPem = chain.map { CryptoSupport.toPem("CERTIFICATE", it.encoded) },
      publicKeyPem = certDetails.publicKeyPem,
      privateKeyPayload = payload,
    )
  }

  fun serializeAsk(container: AskContainer): String = json.encodeToString(container)

  fun writeAsk(container: AskContainer, outputFile: File) {
    outputFile.parentFile?.mkdirs()
    outputFile.writeText(serializeAsk(container), Charsets.UTF_8)
  }

  fun parseAsk(content: String): AskContainer {
    val container =
      try {
        lenientJson.decodeFromString<AskContainer>(content)
      } catch (e: Exception) {
        throw AskFormatException("Invalid ASK JSON container: ${e.message}", e)
      }
    validateContainer(container)
    return container
  }

  fun readAsk(file: File): AskContainer {
    if (!file.exists() || !file.isFile) {
      throw AskFormatException("ASK file does not exist: ${file.absolutePath}")
    }
    return parseAsk(file.readText(Charsets.UTF_8))
  }

  fun validateContainer(container: AskContainer) {
    if (container.containerType != AskContainer.CONTAINER_TYPE) {
      throw AskFormatException("Invalid containerType '${container.containerType}'.")
    }
    if (container.formatVersion != AskContainer.CURRENT_FORMAT_VERSION) {
      throw AskFormatException("Unsupported ASK formatVersion: ${container.formatVersion}")
    }
    if (container.keyId.isBlank()) {
      throw AskFormatException("Missing keyId in ASK container.")
    }
    if (container.metadata.alias.isBlank()) {
      throw AskFormatException("Missing alias in ASK container metadata.")
    }
    val cert = CryptoSupport.parseX509Certificate(container.x509CertificatePem.toByteArray(Charsets.UTF_8))
    val actualSha256 = CryptoSupport.certificateFingerprints(cert).sha256
    if (!actualSha256.equals(container.metadata.fingerprints.sha256, ignoreCase = true)) {
      throw AskFormatException("ASK metadata SHA-256 fingerprint does not match embedded certificate.")
    }
    val payload = container.privateKeyPayload
    when (container.mode) {
      AskMode.ASK_OPEN -> {
        if (payload.encrypted || payload.pkcs8Base64.isNullOrBlank()) {
          throw AskFormatException("ASK-OPEN container must contain an unencrypted PKCS#8 payload.")
        }
      }
      AskMode.ASK_LOCKED -> {
        if (
          !payload.encrypted ||
            payload.saltBase64.isNullOrBlank() ||
            payload.ivBase64.isNullOrBlank() ||
            payload.ciphertextBase64.isNullOrBlank()
        ) {
          throw AskFormatException("ASK-LOCKED container is missing required encryption fields.")
        }
      }
    }
  }

  fun inspectAsk(container: AskContainer): AskInspectResult {
    validateContainer(container)
    val cert = CryptoSupport.parseX509Certificate(container.x509CertificatePem.toByteArray(Charsets.UTF_8))
    val details = CryptoSupport.extractCertificateDetails(cert)
    val warning = if (container.mode == AskMode.ASK_OPEN) UNENCRYPTED_WARNING_EN else null
    return AskInspectResult(
      keyId = container.keyId,
      formatVersion = container.formatVersion,
      mode = container.mode,
      encrypted = container.privateKeyPayload.encrypted,
      metadata = container.metadata,
      certificate = details,
      chainLength = container.certificateChainPem.size.coerceAtLeast(1),
      securityWarning = warning,
    )
  }

  fun inspectAsk(file: File): AskInspectResult = inspectAsk(readAsk(file))

  fun unlockAsk(container: AskContainer, passphrase: CharArray? = null): UnlockedKeyMaterial {
    validateContainer(container)
    val cert = CryptoSupport.parseX509Certificate(container.x509CertificatePem.toByteArray(Charsets.UTF_8))
    val chain =
      if (container.certificateChainPem.isNotEmpty()) {
        CryptoSupport.parseX509CertificateChain(container.certificateChainPem)
      } else {
        listOf(cert)
      }

    val pkcs8Bytes =
      when (container.mode) {
        AskMode.ASK_OPEN -> {
          val b64 =
            container.privateKeyPayload.pkcs8Base64
              ?: throw AskFormatException("Missing PKCS#8 payload in ASK-OPEN container.")
          try {
            Base64.getDecoder().decode(b64)
          } catch (e: Exception) {
            throw AskFormatException("Corrupted Base64 PKCS#8 payload.", e)
          }
        }
        AskMode.ASK_LOCKED -> {
          if (passphrase == null || passphrase.isEmpty()) {
            throw AskPasswordRequiredException()
          }
          val payload = container.privateKeyPayload
          val iterations = payload.kdfIterations ?: KDF_ITERATIONS
          val salt = Base64.getDecoder().decode(payload.saltBase64)
          val iv = Base64.getDecoder().decode(payload.ivBase64)
          val ciphertext = Base64.getDecoder().decode(payload.ciphertextBase64)
          val aad = buildAad(container.formatVersion, container.keyId, container.mode)
          try {
            val key = CryptoSupport.deriveAesKeyPbkdf2(passphrase, salt, iterations)
            CryptoSupport.decryptAesGcm(ciphertext, key, iv, aad)
          } catch (e: Exception) {
            throw AskDecryptionException(cause = e)
          }
        }
      }

    val privateKey = CryptoSupport.parsePrivateKeyPkcs8(pkcs8Bytes)
    CryptoSupport.verifyPrivateKeyMatchesCertificate(privateKey, cert)
    return UnlockedKeyMaterial(
      keyId = container.keyId,
      alias = container.metadata.alias,
      privateKey = privateKey,
      certificate = cert,
      certificateChain = chain,
    )
  }

  fun changeProtection(
    container: AskContainer,
    currentPassphrase: CharArray?,
    newPassphrase: CharArray?,
  ): AskContainer {
    val unlocked = unlockAsk(container, currentPassphrase)
    return buildContainerFromMaterial(
      alias = container.metadata.alias,
      privateKey = unlocked.privateKey,
      chain = unlocked.certificateChain,
      passphrase = newPassphrase,
      notes = container.metadata.notes,
      existingKeyId = container.keyId,
      existingCreatedAt = container.metadata.createdAtIso,
    )
  }

  fun importFromPkcs12(
    p12File: File,
    storePassword: CharArray,
    targetAlias: String? = null,
    keyPassword: CharArray = storePassword,
    askPassphrase: CharArray? = null,
    notes: String = "",
  ): AskContainer {
    if (!p12File.exists()) throw AskFormatException("PKCS#12 file not found: ${p12File.absolutePath}")
    val ks = KeyStore.getInstance("PKCS12")
    p12File.inputStream().use { ks.load(it, storePassword) }
    val aliases = ks.aliases().toList().filter { ks.isKeyEntry(it) }
    if (aliases.isEmpty()) {
      throw AskFormatException("No private key entry found in PKCS#12 file.")
    }
    val chosenAlias =
      if (targetAlias != null) {
        aliases.firstOrNull { it.equals(targetAlias, ignoreCase = true) }
          ?: throw AskFormatException("Alias '$targetAlias' not found in PKCS#12. Available: $aliases")
      } else {
        aliases.first()
      }
    val privateKey =
      ks.getKey(chosenAlias, keyPassword) as? PrivateKey
        ?: throw AskFormatException("Unable to extract PrivateKey for alias '$chosenAlias'.")
    val chain =
      ks.getCertificateChain(chosenAlias)?.mapNotNull { it as? X509Certificate }?.takeIf { it.isNotEmpty() }
        ?: listOfNotNull(ks.getCertificate(chosenAlias) as? X509Certificate)
    return buildContainerFromMaterial(
      alias = chosenAlias,
      privateKey = privateKey,
      chain = chain,
      passphrase = askPassphrase,
      notes = notes,
    )
  }

  fun importFromJks(
    jksFile: File,
    storePassword: CharArray,
    targetAlias: String? = null,
    keyPassword: CharArray = storePassword,
    askPassphrase: CharArray? = null,
    notes: String = "",
  ): AskContainer {
    if (!jksFile.exists()) throw AskFormatException("JKS file not found: ${jksFile.absolutePath}")
    val jksBytes = jksFile.readBytes()
    val entry =
      try {
        val ks = KeyStore.getInstance("JKS")
        ks.load(ByteArrayInputStream(jksBytes), storePassword)
        val aliases = ks.aliases().toList().filter { ks.isKeyEntry(it) }
        val chosen =
          if (targetAlias != null) {
            aliases.firstOrNull { it.equals(targetAlias, ignoreCase = true) }
              ?: throw AskFormatException("Alias '$targetAlias' not found in JKS. Available: $aliases")
          } else {
            aliases.firstOrNull() ?: throw AskFormatException("No private key entry in JKS.")
          }
        val key = ks.getKey(chosen, keyPassword) as? PrivateKey
          ?: throw AskFormatException("Key entry '$chosen' is not a PrivateKey.")
        val chain = ks.getCertificateChain(chosen)?.mapNotNull { it as? X509Certificate } ?: emptyList()
        PureJvmJksCodec.JksEntryResult(chosen, key, chain)
      } catch (e: AskFormatException) {
        throw e
      } catch (_: Exception) {
        // Fallback to pure-JVM JKS codec (essential on Android ART where "JKS" provider is absent)
        PureJvmJksCodec.readPrivateKeyEntry(jksBytes, storePassword, targetAlias, keyPassword)
      }
    return buildContainerFromMaterial(
      alias = entry.alias,
      privateKey = entry.privateKey,
      chain = entry.chain,
      passphrase = askPassphrase,
      notes = notes,
    )
  }

  fun importFromPkcs8AndCert(
    pkcs8File: File,
    certFile: File,
    alias: String,
    askPassphrase: CharArray? = null,
    notes: String = "",
  ): AskContainer {
    if (!pkcs8File.exists()) throw AskFormatException("PKCS#8 file not found: ${pkcs8File.absolutePath}")
    if (!certFile.exists()) throw AskFormatException("Certificate file not found: ${certFile.absolutePath}")
    val privateKey = CryptoSupport.parsePrivateKeyPkcs8(pkcs8File.readBytes())
    val cert = CryptoSupport.parseX509Certificate(certFile.readBytes())
    return buildContainerFromMaterial(
      alias = alias.ifBlank { "imported-key" },
      privateKey = privateKey,
      chain = listOf(cert),
      passphrase = askPassphrase,
      notes = notes,
    )
  }

  fun exportToPkcs12(
    material: UnlockedKeyMaterial,
    outputFile: File,
    storePassword: CharArray,
    alias: String = material.alias,
  ) {
    outputFile.parentFile?.mkdirs()
    val ks = KeyStore.getInstance("PKCS12")
    ks.load(null, storePassword)
    ks.setKeyEntry(alias, material.privateKey, storePassword, material.certificateChain.toTypedArray())
    outputFile.outputStream().use { ks.store(it, storePassword) }
  }

  fun exportToJks(
    material: UnlockedKeyMaterial,
    outputFile: File,
    storePassword: CharArray,
    keyPassword: CharArray = storePassword,
    alias: String = material.alias,
  ) {
    outputFile.parentFile?.mkdirs()
    val bytes =
      try {
        val ks = KeyStore.getInstance("JKS")
        ks.load(null, storePassword)
        ks.setKeyEntry(alias, material.privateKey, keyPassword, material.certificateChain.toTypedArray())
        val baos = ByteArrayOutputStream()
        ks.store(baos, storePassword)
        baos.toByteArray()
      } catch (_: Exception) {
        PureJvmJksCodec.writePrivateKeyEntry(
          alias = alias,
          privateKey = material.privateKey,
          chain = material.certificateChain,
          storePassword = storePassword,
          keyPassword = keyPassword,
        )
      }
    outputFile.writeBytes(bytes)
  }

  /**
   * Exports unencrypted PKCS#8 private key + X.509 certificate.
   * Returns a mandatory security warning string for callers to display.
   */
  fun exportToPkcs8AndCert(
    material: UnlockedKeyMaterial,
    pkcs8OutFile: File,
    certOutFile: File,
    pemEncoded: Boolean = true,
  ): String {
    pkcs8OutFile.parentFile?.mkdirs()
    certOutFile.parentFile?.mkdirs()
    if (pemEncoded) {
      pkcs8OutFile.writeText(CryptoSupport.toPem("PRIVATE KEY", material.privateKey.encoded), Charsets.UTF_8)
      certOutFile.writeText(CryptoSupport.toPem("CERTIFICATE", material.certificate.encoded), Charsets.UTF_8)
    } else {
      pkcs8OutFile.writeBytes(material.privateKey.encoded)
      certOutFile.writeBytes(material.certificate.encoded)
    }
    return UNENCRYPTED_WARNING_EN
  }

  private fun buildAad(formatVersion: Int, keyId: String, mode: AskMode): ByteArray =
    "APPSIGN|v$formatVersion|$keyId|${mode.name}".toByteArray(Charsets.UTF_8)
}
