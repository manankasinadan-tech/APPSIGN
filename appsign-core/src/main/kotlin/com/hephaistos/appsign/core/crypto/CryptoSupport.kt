package com.hephaistos.appsign.core.crypto

import com.hephaistos.appsign.core.ask.AskFormatException
import com.hephaistos.appsign.core.ask.AskKeyMismatchException
import com.hephaistos.appsign.core.model.CertificateDetails
import com.hephaistos.appsign.core.model.CertificateFingerprint
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.KeyAlgorithm
import com.hephaistos.appsign.core.model.ExactKeySpec
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

object CryptoSupport {
  val bcProvider: BouncyCastleProvider = BouncyCastleProvider()
  private val secureRandom = SecureRandom()
  private val isoFormatter = DateTimeFormatter.ISO_INSTANT

  fun nowIso(): String = isoFormatter.format(Instant.now())

  fun formatIso(date: Date): String = isoFormatter.format(date.toInstant())

  fun digestHex(bytes: ByteArray, algorithm: String, colonSeparated: Boolean = true): String {
    val digest = MessageDigest.getInstance(algorithm).digest(bytes)
    return if (colonSeparated) {
      digest.joinToString(":") { "%02X".format(it) }
    } else {
      digest.joinToString("") { "%02x".format(it) }
    }
  }

  fun certificateFingerprints(cert: X509Certificate): CertificateFingerprint {
    val encoded = cert.encoded
    return CertificateFingerprint(
      sha256 = digestHex(encoded, "SHA-256", colonSeparated = true),
      sha1 = digestHex(encoded, "SHA-1", colonSeparated = true),
      md5 = digestHex(encoded, "MD5", colonSeparated = true),
    )
  }

  fun encodeCertHexDer(cert: X509Certificate, uppercase: Boolean = false): String {
    val fmt = if (uppercase) "%02X" else "%02x"
    return cert.encoded.joinToString("") { fmt.format(it) }
  }

  fun encodeCertBase64Der(cert: X509Certificate): String =
    Base64.getEncoder().encodeToString(cert.encoded)

  fun tryParseCertificateHex(hex: String): X509Certificate? {
    val clean = hex.trim()
    if (clean.length < 40 || clean.length % 2 != 0 || !clean.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
      return null
    }
    return runCatching {
      val bytes = ByteArray(clean.length / 2) { idx ->
        clean.substring(idx * 2, idx * 2 + 2).toInt(16).toByte()
      }
      parseX509Certificate(bytes)
    }.getOrNull()
  }

  fun toPem(type: String, derBytes: ByteArray): String {
    val b64 = Base64.getMimeEncoder(64, "\n".toByteArray(Charsets.UTF_8)).encodeToString(derBytes)
    return "-----BEGIN $type-----\n$b64\n-----END $type-----"
  }

  fun parsePemBytes(pemOrDer: ByteArray): List<Pair<String?, ByteArray>> {
    val text = pemOrDer.toString(Charsets.UTF_8)
    val regex = Regex("-----BEGIN ([A-Z0-9 ]+)-----([\\s\\S]*?)-----END \\1-----")
    val matches = regex.findAll(text).toList()
    if (matches.isEmpty()) {
      return listOf(null to pemOrDer)
    }
    return matches.map { match ->
      val header = match.groupValues[1].trim()
      val body = match.groupValues[2].replace("\\s".toRegex(), "")
      header to Base64.getDecoder().decode(body)
    }
  }

  fun parseX509Certificate(bytes: ByteArray): X509Certificate {
    val parsed = parsePemBytes(bytes)
    val certBytes =
      parsed.firstOrNull { it.first == null || it.first == "CERTIFICATE" }?.second
        ?: throw AskFormatException("No X.509 certificate block found.")
    return try {
      val cf = CertificateFactory.getInstance("X.509")
      cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
    } catch (e: Exception) {
      throw AskFormatException("Invalid X.509 certificate encoding: ${e.message}", e)
    }
  }

  fun parseX509CertificateChain(pemList: List<String>): List<X509Certificate> =
    pemList.map { parseX509Certificate(it.toByteArray(Charsets.UTF_8)) }

  fun parsePrivateKeyPkcs8(bytes: ByteArray): PrivateKey {
    val parsed = parsePemBytes(bytes)
    val block = parsed.firstOrNull() ?: throw AskFormatException("Empty private key input.")
    if (block.first == "ENCRYPTED PRIVATE KEY") {
      throw AskFormatException(
        "Encrypted PKCS#8 PEM is not directly supported; decrypt it first or import via PKCS#12/JKS."
      )
    }
    val keySpec = PKCS8EncodedKeySpec(block.second)
    val algorithms = listOf("RSA", "EC", "DSA", "Ed25519")
    for (alg in algorithms) {
      try {
        return KeyFactory.getInstance(alg).generatePrivate(keySpec)
      } catch (_: Exception) {
        // try next algorithm
      }
      try {
        return KeyFactory.getInstance(alg, bcProvider).generatePrivate(keySpec)
      } catch (_: Exception) {
        // try next algorithm
      }
    }
    throw AskFormatException("Unsupported or corrupted PKCS#8 private key.")
  }

  fun parsePublicKey(bytes: ByteArray): PublicKey {
    val parsed = parsePemBytes(bytes)
    val block = parsed.firstOrNull() ?: throw AskFormatException("Empty public key input.")
    val spec = X509EncodedKeySpec(block.second)
    for (alg in listOf("RSA", "EC", "DSA", "Ed25519")) {
      try {
        return KeyFactory.getInstance(alg).generatePublic(spec)
      } catch (_: Exception) {
        // try next
      }
      try {
        return KeyFactory.getInstance(alg, bcProvider).generatePublic(spec)
      } catch (_: Exception) {
        // try next
      }
    }
    throw AskFormatException("Unsupported public key format.")
  }

  fun extractCertificateDetails(cert: X509Certificate): CertificateDetails {
    val now = Date()
    val pubKey = cert.publicKey
    val keyBits = resolvePublicKeyBits(pubKey)
    val fingerprints = certificateFingerprints(cert)
    val pubSha256 = digestHex(pubKey.encoded, "SHA-256", colonSeparated = false)
    return CertificateDetails(
      subjectDn = cert.subjectX500Principal.name,
      issuerDn = cert.issuerX500Principal.name,
      serialNumberHex = cert.serialNumber.toString(16).uppercase(),
      notBeforeIso = formatIso(cert.notBefore),
      notAfterIso = formatIso(cert.notAfter),
      isExpired = now.after(cert.notAfter),
      isNotYetValid = now.before(cert.notBefore),
      sigAlgName = cert.sigAlgName,
      publicKeyAlgorithm = pubKey.algorithm,
      publicKeyBits = keyBits,
      publicKeyFormat = pubKey.format ?: "X.509",
      publicKeySha256 = pubSha256,
      fingerprints = fingerprints,
      version = cert.version,
      publicKeyPem = toPem("PUBLIC KEY", pubKey.encoded),
      certificatePem = toPem("CERTIFICATE", cert.encoded),
    )
  }

  fun resolvePublicKeyBits(pubKey: PublicKey): Int =
    when (pubKey) {
      is RSAPublicKey -> pubKey.modulus.bitLength()
      is ECPublicKey -> pubKey.params.curve.field.fieldSize
      else -> pubKey.encoded.size * 8
    }

  fun resolveEcCurveName(pubKey: PublicKey): String? {
    if (pubKey !is ECPublicKey) return null
    val bits = pubKey.params.curve.field.fieldSize
    return when (bits) {
      256 -> "secp256r1"
      384 -> "secp384r1"
      521 -> "secp521r1"
      else -> "secp256r1"
    }
  }

  fun extractExactKeySpec(cert: X509Certificate): ExactKeySpec {
    val pub = cert.publicKey
    val rawAlg = pub.algorithm.uppercase()
    val bits = resolvePublicKeyBits(pub)
    val ecCurve = resolveEcCurveName(pub)
    val normalizedAlg =
      when {
        rawAlg.contains("EC") -> "EC"
        rawAlg.contains("DSA") && !rawAlg.contains("EC") -> "DSA"
        else -> "RSA"
      }
    val safeSigAlg =
      cert.sigAlgName.takeIf { it.isNotBlank() && !it.equals("UNKNOWN", ignoreCase = true) }
        ?: when (normalizedAlg) {
          "EC" -> if (bits >= 512) "SHA512withECDSA" else if (bits >= 384) "SHA384withECDSA" else "SHA256withECDSA"
          "DSA" -> "SHA256withDSA"
          else -> if (bits >= 4096) "SHA512withRSA" else "SHA256withRSA"
        }
    return ExactKeySpec(
      keyAlgorithm = normalizedAlg,
      keySizeBits = bits,
      sigAlgName = safeSigAlg,
      ecCurveName = ecCurve,
    )
  }

  fun generateKeyPairAndSelfSignedCert(options: CreateAskOptions): Pair<KeyPair, X509Certificate> {
    val alg = options.algorithm
    val spec =
      ExactKeySpec(
        keyAlgorithm = alg.keyAlg,
        keySizeBits = alg.keySizeBits,
        sigAlgName = alg.sigAlg,
        ecCurveName =
          when (alg) {
            KeyAlgorithm.EC_P256 -> "secp256r1"
            KeyAlgorithm.EC_P384 -> "secp384r1"
            KeyAlgorithm.EC_P521 -> "secp521r1"
            else -> null
          },
      )
    return generateKeyPairAndCertFromSpec(
      spec = spec,
      subjectDn = options.buildSubjectDn(),
      issuerDn = options.buildSubjectDn(),
      validityDays = options.validityYears.toLong().coerceIn(1L, 100L) * 365L,
    )
  }

  fun generateKeyPairAndCertFromSpec(
    spec: ExactKeySpec,
    subjectDn: String,
    issuerDn: String = subjectDn,
    validityDays: Long = 365L * 25L,
    serialNumber: BigInteger? = null,
  ): Pair<KeyPair, X509Certificate> {
    val algUpper = spec.keyAlgorithm.uppercase()
    val keyPairGen =
      when (algUpper) {
        "EC", "ECDSA" -> {
          val curve =
            spec.ecCurveName
              ?: when {
                spec.keySizeBits >= 512 -> "secp521r1"
                spec.keySizeBits >= 384 -> "secp384r1"
                else -> "secp256r1"
              }
          KeyPairGenerator.getInstance("EC", bcProvider).apply {
            initialize(ECGenParameterSpec(curve), secureRandom)
          }
        }
        "DSA" -> {
          val size = spec.keySizeBits.coerceIn(1024, 3072)
          KeyPairGenerator.getInstance("DSA", bcProvider).apply { initialize(size, secureRandom) }
        }
        else -> {
          val size = spec.keySizeBits.coerceAtLeast(1024)
          KeyPairGenerator.getInstance("RSA").apply { initialize(size, secureRandom) }
        }
      }
    val keyPair = keyPairGen.generateKeyPair()
    val now = Instant.now()
    val notBefore = Date.from(now.minusSeconds(60))
    val days = validityDays.coerceIn(1L, 36500L)
    val notAfter = Date.from(now.plusSeconds(days * 86400L))
    val serial = serialNumber ?: BigInteger(128, secureRandom).abs().max(BigInteger.ONE)
    val subject = runCatching { X500Name(subjectDn) }.getOrElse { X500Name("CN=APPSIGN") }
    val issuer = runCatching { X500Name(issuerDn) }.getOrElse { subject }

    val builder =
      JcaX509v3CertificateBuilder(
        issuer,
        serial,
        notBefore,
        notAfter,
        subject,
        keyPair.public,
      )
    val extUtils = JcaX509ExtensionUtils()
    builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.public))
    builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
    builder.addExtension(
      Extension.keyUsage,
      true,
      KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment),
    )

    val chosenSigAlg =
      runCatching {
        JcaContentSignerBuilder(spec.sigAlgName).setProvider(bcProvider).build(keyPair.private)
      }.getOrElse {
        val fallbackAlg =
          when (algUpper) {
            "EC", "ECDSA" -> "SHA256withECDSA"
            "DSA" -> "SHA256withDSA"
            else -> "SHA256withRSA"
          }
        JcaContentSignerBuilder(fallbackAlg).setProvider(bcProvider).build(keyPair.private)
      }
    val certHolder = builder.build(chosenSigAlg)
    val cert = JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certHolder)
    cert.verify(keyPair.public)
    return keyPair to cert
  }

  fun verifyPrivateKeyMatchesCertificate(privateKey: PrivateKey, certificate: X509Certificate) {
    val publicKey = certificate.publicKey
    val sigAlg =
      when (privateKey.algorithm.uppercase()) {
        "RSA" -> "SHA256withRSA"
        "EC", "ECDSA" -> "SHA256withECDSA"
        "DSA" -> "SHA256withDSA"
        else -> throw AskKeyMismatchException()
      }
    try {
      val challenge = ByteArray(32).also { secureRandom.nextBytes(it) }
      val signer = Signature.getInstance(sigAlg)
      signer.initSign(privateKey)
      signer.update(challenge)
      val sigBytes = signer.sign()

      val verifier = Signature.getInstance(sigAlg)
      verifier.initVerify(publicKey)
      verifier.update(challenge)
      if (!verifier.verify(sigBytes)) {
        throw AskKeyMismatchException()
      }
    } catch (e: AskKeyMismatchException) {
      throw e
    } catch (e: Exception) {
      throw AskKeyMismatchException()
    }
  }

  fun randomBytes(length: Int): ByteArray = ByteArray(length).also { secureRandom.nextBytes(it) }

  fun deriveAesKeyPbkdf2(passphrase: CharArray, salt: ByteArray, iterations: Int): SecretKeySpec {
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec = PBEKeySpec(passphrase, salt, iterations, 256)
    val keyBytes = factory.generateSecret(spec).encoded
    spec.clearPassword()
    return SecretKeySpec(keyBytes, "AES")
  }

  fun encryptAesGcm(plaintext: ByteArray, key: SecretKeySpec, iv: ByteArray, aad: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    cipher.updateAAD(aad)
    return cipher.doFinal(plaintext)
  }

  fun decryptAesGcm(ciphertext: ByteArray, key: SecretKeySpec, iv: ByteArray, aad: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
    cipher.updateAAD(aad)
    return cipher.doFinal(ciphertext)
  }
}
