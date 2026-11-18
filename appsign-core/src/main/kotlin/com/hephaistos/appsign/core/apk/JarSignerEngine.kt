package com.hephaistos.appsign.core.apk

import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.CertificateDetails
import com.hephaistos.appsign.core.model.VerificationStatus
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.jar.Attributes
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import com.hephaistos.appsign.core.model.UnlockedKeyMaterial

data class JarVerificationResult(
  val present: Boolean,
  val verified: Boolean,
  val status: VerificationStatus,
  val signers: List<CertificateDetails>,
  val notes: List<String> = emptyList(),
)

object JarSignerEngine {

  private val sigBlockRegex = Regex("^META-INF/[^/]+\\.(SF|RSA|DSA|EC)$", RegexOption.IGNORE_CASE)

  fun hasJarSignatureEntries(zipFile: File): Boolean {
    ZipFile(zipFile).use { zip ->
      val entries = zip.entries()
      while (entries.hasMoreElements()) {
        val name = entries.nextElement().name
        if (sigBlockRegex.matches(name)) return true
      }
    }
    return false
  }

  fun verifyJar(jarFile: File): JarVerificationResult {
    if (!jarFile.exists() || !jarFile.isFile) {
      return JarVerificationResult(false, false, VerificationStatus.INVALID, emptyList(), listOf("JAR not found"))
    }
    val hasSigFiles = runCatching { hasJarSignatureEntries(jarFile) }.getOrDefault(false)
    if (!hasSigFiles) {
      return JarVerificationResult(
        present = false,
        verified = false,
        status = VerificationStatus.UNSIGNED,
        signers = emptyList(),
        notes = listOf("No META-INF JAR signature entries."),
      )
    }

    return try {
      val uniqueCerts = linkedMapOf<String, X509Certificate>()
      var codeEntriesVerified = 0
      var unsignedCodeEntries = 0

      JarFile(jarFile, true).use { jf ->
        val buffer = ByteArray(16384)
        val entries = jf.entries()
        while (entries.hasMoreElements()) {
          val entry = entries.nextElement()
          jf.getInputStream(entry).use { input ->
            while (input.read(buffer) != -1) {
              // Consume stream so JarFile validates digest & signature
            }
          }
          if (!entry.isDirectory && !entry.name.startsWith("META-INF/", ignoreCase = true)) {
            val certs = entry.certificates?.mapNotNull { it as? X509Certificate }.orEmpty()
            if (certs.isNotEmpty()) {
              codeEntriesVerified++
              val leaf = certs.first()
              val sha = CryptoSupport.certificateFingerprints(leaf).sha256
              uniqueCerts.putIfAbsent(sha, leaf)
            } else {
              unsignedCodeEntries++
            }
          }
        }
        // Fallback: extract signer certs from PKCS#7 block if archive only contains META-INF signatures
        if (uniqueCerts.isEmpty()) {
          extractCertsFromMetaInf(jarFile).forEach { cert ->
            val sha = CryptoSupport.certificateFingerprints(cert).sha256
            uniqueCerts.putIfAbsent(sha, cert)
          }
        }
      }

      val details = uniqueCerts.values.map { CryptoSupport.extractCertificateDetails(it) }
      val notes = mutableListOf<String>()
      if (unsignedCodeEntries > 0) {
        notes += "$unsignedCodeEntries unsigned entry/entries present alongside $codeEntriesVerified signed entries."
      }
      val status =
        when {
          details.isEmpty() -> VerificationStatus.UNSIGNED
          notes.isNotEmpty() -> VerificationStatus.VALID_WITH_WARNINGS
          else -> VerificationStatus.VALID
        }
      JarVerificationResult(
        present = details.isNotEmpty(),
        verified = details.isNotEmpty(),
        status = status,
        signers = details,
        notes = notes,
      )
    } catch (sec: SecurityException) {
      JarVerificationResult(
        present = true,
        verified = false,
        status = VerificationStatus.INVALID,
        signers = extractCertsFromMetaInf(jarFile).map { CryptoSupport.extractCertificateDetails(it) },
        notes = listOf("JAR signature verification failed: ${sec.message}"),
      )
    } catch (e: Exception) {
      JarVerificationResult(
        present = hasSigFiles,
        verified = false,
        status = VerificationStatus.INVALID,
        signers = emptyList(),
        notes = listOf("Failed reading JAR: ${e.message}"),
      )
    }
  }

  private fun extractCertsFromMetaInf(jarFile: File): List<X509Certificate> {
    val result = mutableListOf<X509Certificate>()
    runCatching {
      ZipFile(jarFile).use { zip ->
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
          val e = entries.nextElement()
          if (e.name.startsWith("META-INF/", ignoreCase = true) &&
            (e.name.endsWith(".RSA", true) || e.name.endsWith(".EC", true) || e.name.endsWith(".DSA", true))
          ) {
            val blockBytes = zip.getInputStream(e).use { it.readBytes() }
            val cf = java.security.cert.CertificateFactory.getInstance("X.509")
            val certs = cf.generateCertificates(blockBytes.inputStream())
            certs.mapNotNull { it as? X509Certificate }.firstOrNull()?.let { result += it }
          }
        }
      }
    }
    return result
  }

  fun signJar(inputJar: File, outputJar: File, keyMaterial: UnlockedKeyMaterial) {
    if (!inputJar.exists() || !inputJar.isFile) {
      throw IllegalArgumentException("Input JAR not found: ${inputJar.absolutePath}")
    }
    outputJar.parentFile?.mkdirs()

    val sha256 = MessageDigest.getInstance("SHA-256")
    val b64 = Base64.getEncoder()

    val manifest = Manifest()
    manifest.mainAttributes[Attributes.Name.MANIFEST_VERSION] = "1.0"
    manifest.mainAttributes[Attributes.Name("Created-By")] = "APPSIGN 1.0"

    val rawEntries = linkedMapOf<String, ByteArray>()

    ZipFile(inputJar).use { zip ->
      val origManifestEntry = zip.getEntry(JarFile.MANIFEST_NAME)
      if (origManifestEntry != null) {
        runCatching {
          val origManifest = zip.getInputStream(origManifestEntry).use { Manifest(it) }
          origManifest.mainAttributes.forEach { k, v ->
            manifest.mainAttributes[k] = v
          }
        }
      }
      val enumEntries = zip.entries()
      while (enumEntries.hasMoreElements()) {
        val entry = enumEntries.nextElement()
        if (entry.isDirectory) continue
        if (entry.name.equals(JarFile.MANIFEST_NAME, ignoreCase = true) || sigBlockRegex.matches(entry.name)) {
          continue
        }
        val bytes = zip.getInputStream(entry).use { it.readBytes() }
        rawEntries[entry.name] = bytes
        val digest = b64.encodeToString(sha256.digest(bytes))
        val attrs = Attributes()
        attrs.putValue("SHA-256-Digest", digest)
        manifest.entries[entry.name] = attrs
      }
    }

    val manifestOut = ByteArrayOutputStream()
    manifest.write(manifestOut)
    val manifestBytes = manifestOut.toByteArray()

    // Parse manifest sections to construct APPSIGN.SF
    val manifestText = manifestBytes.toString(Charsets.UTF_8).replace("\r\n", "\n")
    val sections = manifestText.split("\n\n").filter { it.isNotBlank() }
    val mainSectionBytes = ((sections.firstOrNull() ?: "") + "\n\n").replace("\n", "\r\n").toByteArray(Charsets.UTF_8)

    val sfBuilder = StringBuilder()
    sfBuilder.append("Signature-Version: 1.0\r\n")
    sfBuilder.append("Created-By: APPSIGN 1.0\r\n")
    sfBuilder.append("SHA-256-Digest-Manifest: ${b64.encodeToString(sha256.digest(manifestBytes))}\r\n")
    sfBuilder.append("SHA-256-Digest-Manifest-Main-Attributes: ${b64.encodeToString(sha256.digest(mainSectionBytes))}\r\n")
    sfBuilder.append("\r\n")

    for (section in sections.drop(1)) {
      val firstLine = section.lineSequence().firstOrNull().orEmpty()
      if (firstLine.startsWith("Name: ")) {
        val sectionWithCrlf = (section.trimEnd('\n') + "\n\n").replace("\n", "\r\n")
        val secDigest = b64.encodeToString(sha256.digest(sectionWithCrlf.toByteArray(Charsets.UTF_8)))
        sfBuilder.append(firstLine).append("\r\n")
        sfBuilder.append("SHA-256-Digest: ").append(secDigest).append("\r\n\r\n")
      }
    }

    val sfBytes = sfBuilder.toString().toByteArray(Charsets.UTF_8)

    val keyAlg = keyMaterial.privateKey.algorithm.uppercase()
    val sigAlg =
      when {
        keyAlg.contains("EC") -> "SHA256withECDSA"
        keyAlg.contains("DSA") -> "SHA256withDSA"
        else -> "SHA256withRSA"
      }
    val blockExt =
      when {
        keyAlg.contains("EC") -> "EC"
        keyAlg.contains("DSA") -> "DSA"
        else -> "RSA"
      }

    val generator = CMSSignedDataGenerator()
    val contentSigner =
      JcaContentSignerBuilder(sigAlg).setProvider(CryptoSupport.bcProvider).build(keyMaterial.privateKey)
    val digestProvider = JcaDigestCalculatorProviderBuilder().setProvider(CryptoSupport.bcProvider).build()
    generator.addSignerInfoGenerator(
      JcaSignerInfoGeneratorBuilder(digestProvider).build(contentSigner, keyMaterial.certificate)
    )
    generator.addCertificates(JcaCertStore(keyMaterial.certificateChain))
    val cmsData = generator.generate(CMSProcessableByteArray(sfBytes), false)
    val blockBytes = cmsData.encoded

    JarOutputStream(outputJar.outputStream().buffered()).use { jos ->
      jos.putNextEntry(ZipEntry(JarFile.MANIFEST_NAME))
      jos.write(manifestBytes)
      jos.closeEntry()

      jos.putNextEntry(JarEntry("META-INF/APPSIGN.SF"))
      jos.write(sfBytes)
      jos.closeEntry()

      jos.putNextEntry(JarEntry("META-INF/APPSIGN.$blockExt"))
      jos.write(blockBytes)
      jos.closeEntry()

      for ((name, bytes) in rawEntries) {
        jos.putNextEntry(JarEntry(name))
        jos.write(bytes)
        jos.closeEntry()
      }
    }
  }
}
