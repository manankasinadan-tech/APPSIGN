package com.hephaistos.appsign.core.ask

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.EncryptedPrivateKeyInfo
import javax.crypto.spec.PBEKeySpec
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo as BcEncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DEROctetString

/**
 * Pure-JVM JKS (Java KeyStore v2, magic 0xFEEDFEED) codec so `.jks` files can be read and written
 * identically on both desktop/Termux JVMs and Android ART (where Sun's `"JKS"` KeyStore provider
 * is not bundled).
 */
object PureJvmJksCodec {
  private const val MAGIC = 0xFEEDFEED.toInt()
  private const val VERSION_2 = 2
  private const val ENTRY_PRIVATE_KEY = 1
  private const val ENTRY_TRUSTED_CERT = 2
  private const val WHITENER_MSG = "Mighty Aphrodite"
  private val JKS_KEY_PROTECTOR_OID = ASN1ObjectIdentifier("1.3.6.1.4.1.42.2.17.1.1")

  data class JksEntryResult(
    val alias: String,
    val privateKey: PrivateKey,
    val chain: List<X509Certificate>,
  )

  fun readPrivateKeyEntry(
    jksBytes: ByteArray,
    storePassword: CharArray,
    targetAlias: String? = null,
    keyPassword: CharArray = storePassword,
  ): JksEntryResult {
    val input = DataInputStream(ByteArrayInputStream(jksBytes))
    val magic = input.readInt()
    if (magic != MAGIC) {
      throw AskFormatException("Not a valid JKS keystore (invalid magic header).")
    }
    val version = input.readInt()
    if (version != 1 && version != VERSION_2) {
      throw AskFormatException("Unsupported JKS version: $version")
    }
    val count = input.readInt()
    if (count < 0 || count > 10_000) {
      throw AskFormatException("Invalid JKS entry count: $count")
    }

    val certFactory = CertificateFactory.getInstance("X.509")
    var found: JksEntryResult? = null
    val availableAliases = mutableListOf<String>()

    repeat(count) {
      val tag = input.readInt()
      when (tag) {
        ENTRY_PRIVATE_KEY -> {
          val alias = input.readUTF()
          availableAliases += alias
          input.readLong() // timestamp
          val protectedLen = input.readInt()
          val protectedBytes = ByteArray(protectedLen)
          input.readFully(protectedBytes)

          val chainLen = input.readInt()
          val chain = mutableListOf<X509Certificate>()
          repeat(chainLen) {
            if (version == VERSION_2) {
              input.readUTF() // cert type
            }
            val certLen = input.readInt()
            val certBytes = ByteArray(certLen)
            input.readFully(certBytes)
            chain += certFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
          }

          if (found == null && (targetAlias == null || alias.equals(targetAlias, ignoreCase = true))) {
            val privateKey = unprotectJksKey(protectedBytes, keyPassword)
            found = JksEntryResult(alias = alias, privateKey = privateKey, chain = chain)
          }
        }
        ENTRY_TRUSTED_CERT -> {
          val alias = input.readUTF()
          availableAliases += alias
          input.readLong() // timestamp
          if (version == VERSION_2) {
            input.readUTF()
          }
          val certLen = input.readInt()
          val certBytes = ByteArray(certLen)
          input.readFully(certBytes)
        }
        else -> throw AskFormatException("Unknown JKS entry tag: $tag")
      }
    }

    // Verify trailing SHA-1 integrity digest when storePassword is provided
    val remaining = ByteArray(20)
    val readDigest = input.read(remaining)
    if (readDigest == 20 && jksBytes.size >= 20) {
      val contentWithoutDigest = jksBytes.copyOfRange(0, jksBytes.size - 20)
      val expectedDigest = computeStoreDigest(storePassword, contentWithoutDigest)
      if (!MessageDigest.isEqual(expectedDigest, remaining)) {
        throw AskDecryptionException("JKS keystore integrity check failed (wrong store password or corrupted file).")
      }
    }

    return found
      ?: throw AskFormatException(
        if (targetAlias != null) {
          "Alias '$targetAlias' not found in JKS private key entries. Available: $availableAliases"
        } else {
          "No private key entry found in JKS keystore."
        }
      )
  }

  fun writePrivateKeyEntry(
    alias: String,
    privateKey: PrivateKey,
    chain: List<X509Certificate>,
    storePassword: CharArray,
    keyPassword: CharArray = storePassword,
  ): ByteArray {
    val bodyOut = ByteArrayOutputStream()
    val out = DataOutputStream(bodyOut)
    out.writeInt(MAGIC)
    out.writeInt(VERSION_2)
    out.writeInt(1) // 1 private key entry

    out.writeInt(ENTRY_PRIVATE_KEY)
    out.writeUTF(alias)
    out.writeLong(System.currentTimeMillis())

    val protectedBytes = protectJksKey(privateKey.encoded, keyPassword)
    out.writeInt(protectedBytes.size)
    out.write(protectedBytes)

    out.writeInt(chain.size)
    for (cert in chain) {
      out.writeUTF("X.509")
      val encoded = cert.encoded
      out.writeInt(encoded.size)
      out.write(encoded)
    }
    out.flush()

    val bodyBytes = bodyOut.toByteArray()
    val digest = computeStoreDigest(storePassword, bodyBytes)
    return bodyBytes + digest
  }

  private fun protectJksKey(pkcs8PlainBytes: ByteArray, password: CharArray): ByteArray {
    val salt = ByteArray(20).also { SecureRandom().nextBytes(it) }
    val pwBytes = passwordToJksBytes(password)
    val sha1 = MessageDigest.getInstance("SHA-1")

    val xorStream = ByteArrayOutputStream()
    var digest = salt
    var written = 0
    while (written < pkcs8PlainBytes.size) {
      sha1.reset()
      sha1.update(pwBytes)
      sha1.update(digest)
      digest = sha1.digest()
      val chunk = minOf(digest.size, pkcs8PlainBytes.size - written)
      for (i in 0 until chunk) {
        xorStream.write((pkcs8PlainBytes[written + i].toInt() xor digest[i].toInt()) and 0xFF)
      }
      written += chunk
    }
    val encryptedKey = xorStream.toByteArray()

    sha1.reset()
    sha1.update(pwBytes)
    sha1.update(pkcs8PlainBytes)
    val checkDigest = sha1.digest()

    val protectedBlob = salt + encryptedKey + checkDigest
    val algId = AlgorithmIdentifier(JKS_KEY_PROTECTOR_OID)
    val epki = BcEncryptedPrivateKeyInfo(algId, protectedBlob)
    return epki.encoded
  }

  private fun unprotectJksKey(epkiBytes: ByteArray, password: CharArray): PrivateKey {
    val encryptedData: ByteArray =
      try {
        val bcEpki = BcEncryptedPrivateKeyInfo.getInstance(epkiBytes)
        if (bcEpki.encryptionAlgorithm.algorithm != JKS_KEY_PROTECTOR_OID) {
          throw AskFormatException(
            "Unsupported JKS key protection OID: ${bcEpki.encryptionAlgorithm.algorithm}"
          )
        }
        bcEpki.encryptedData
      } catch (e: AskFormatException) {
        throw e
      } catch (e: Exception) {
        try {
          EncryptedPrivateKeyInfo(epkiBytes).encryptedData
        } catch (ex: Exception) {
          throw AskFormatException("Corrupted JKS encrypted private key blob.", ex)
        }
      }

    if (encryptedData.size < 41) {
      throw AskFormatException("JKS protected key blob is too short.")
    }
    val salt = encryptedData.copyOfRange(0, 20)
    val encrLen = encryptedData.size - 40
    val cipherBytes = encryptedData.copyOfRange(20, 20 + encrLen)
    val expectedCheck = encryptedData.copyOfRange(20 + encrLen, encryptedData.size)

    val pwBytes = passwordToJksBytes(password)
    val sha1 = MessageDigest.getInstance("SHA-1")

    val plain = ByteArray(encrLen)
    var digest = salt
    var offset = 0
    while (offset < encrLen) {
      sha1.reset()
      sha1.update(pwBytes)
      sha1.update(digest)
      digest = sha1.digest()
      val chunk = minOf(digest.size, encrLen - offset)
      for (i in 0 until chunk) {
        plain[offset + i] = ((cipherBytes[offset + i].toInt() xor digest[i].toInt()) and 0xFF).toByte()
      }
      offset += chunk
    }

    sha1.reset()
    sha1.update(pwBytes)
    sha1.update(plain)
    val actualCheck = sha1.digest()
    if (!MessageDigest.isEqual(actualCheck, expectedCheck)) {
      throw AskDecryptionException("Incorrect JKS key password.")
    }

    val spec = PKCS8EncodedKeySpec(plain)
    for (alg in listOf("RSA", "EC", "DSA")) {
      try {
        return KeyFactory.getInstance(alg).generatePrivate(spec)
      } catch (_: Exception) {
        // try next
      }
    }
    throw AskFormatException("Decoded JKS key is not RSA, EC, or DSA.")
  }

  private fun computeStoreDigest(password: CharArray, content: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-1")
    md.update(passwordToJksBytes(password))
    md.update(WHITENER_MSG.toByteArray(Charsets.UTF_8))
    md.update(content)
    return md.digest()
  }

  private fun passwordToJksBytes(password: CharArray): ByteArray {
    val bytes = ByteArray(password.size * 2)
    for (i in password.indices) {
      val ch = password[i].code
      bytes[i * 2] = (ch shr 8).toByte()
      bytes[i * 2 + 1] = ch.toByte()
    }
    return bytes
  }
}
