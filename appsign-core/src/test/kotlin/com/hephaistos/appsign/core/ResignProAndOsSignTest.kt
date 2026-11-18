package com.hephaistos.appsign.core

import com.hephaistos.appsign.core.apk.ApkSignerEngine
import com.hephaistos.appsign.core.apk.ApkVerifierEngine
import com.hephaistos.appsign.core.apk.JarSignerEngine
import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.AskMode
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.ExactKeySpec
import com.hephaistos.appsign.core.model.IdentityInput
import com.hephaistos.appsign.core.model.KeyAlgorithm
import com.hephaistos.appsign.core.model.OsReferenceFormat
import com.hephaistos.appsign.core.model.OsResignKeyStrategy
import com.hephaistos.appsign.core.model.OsTrustAction
import com.hephaistos.appsign.core.model.SignatureSchemeVersion
import com.hephaistos.appsign.core.model.SigningOptions
import com.hephaistos.appsign.core.ossign.OsResignPlan
import com.hephaistos.appsign.core.ossign.OsSignAnalyzerEngine
import com.hephaistos.appsign.core.ossign.OsSignResignEngine
import com.hephaistos.appsign.core.pro.ResignProEngine
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ResignProAndOsSignTest {

  private fun createMinimalApk(file: File, extraTag: String = "v1") {
    file.parentFile?.mkdirs()
    ZipOutputStream(FileOutputStream(file)).use { zos ->
      zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
      zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
      zos.closeEntry()
      zos.putNextEntry(ZipEntry("classes.dex"))
      zos.write("dex\n035\u0000$extraTag".toByteArray(Charsets.UTF_8))
      zos.closeEntry()
    }
  }

  private fun createMinimalApex(file: File) {
    file.parentFile?.mkdirs()
    ZipOutputStream(FileOutputStream(file)).use { zos ->
      zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
      zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
      zos.closeEntry()
      zos.putNextEntry(ZipEntry("apex_manifest.json"))
      zos.write("""{"name":"com.test.apex","version":1}""".toByteArray(Charsets.UTF_8))
      zos.closeEntry()
      zos.putNextEntry(ZipEntry("apex_payload.img"))
      zos.write(byteArrayOf(0x01, 0x02, 0x03, 0x04))
      zos.closeEntry()
    }
  }

  private fun createMinimalJar(file: File, className: String = "com/example/Test.class") {
    file.parentFile?.mkdirs()
    ZipOutputStream(FileOutputStream(file)).use { zos ->
      zos.putNextEntry(ZipEntry(className))
      zos.write(byteArrayOf(0xCA.toByte(), 0xFE.toByte(), 0xBA.toByte(), 0xBE.toByte()))
      zos.closeEntry()
    }
  }

  @Test
  fun `resignPro detects exact RSA-3072 and EC-256 multi-signer target and creates ASK-OPEN key with identity only`() {
    val tmpDir = Files.createTempDirectory("resignpro_test_").toFile()
    try {
      // Sign target APK with two signers: RSA 3072 (v1+v2+v3? note multi-signer uses v1+v2!)
      val c1 =
        AskKeyManager.createAsk(
          CreateAskOptions(
            alias = "orig-rsa3072",
            algorithm = KeyAlgorithm.RSA_3072,
            commonName = "Vendor Main",
            organization = "OEM Corp",
            validityYears = 15,
          )
        )
      val c2 =
        AskKeyManager.createAsk(
          CreateAskOptions(
            alias = "orig-ec256",
            algorithm = KeyAlgorithm.EC_P256,
            commonName = "Vendor Secondary",
            organization = "OEM Corp",
            validityYears = 10,
          )
        )
      val k1 = AskKeyManager.unlockAsk(c1, null)
      val k2 = AskKeyManager.unlockAsk(c2, null)

      val unsignedTarget = File(tmpDir, "target-unsigned.apk").also { createMinimalApk(it) }
      val targetApk = File(tmpDir, "target.apk")
      val signRes =
        ApkSignerEngine.resignWithSigners(
          unsignedTarget,
          targetApk,
          listOf(k1, k2),
          SigningOptions(enableV1 = true, enableV2 = true, enableV3 = false),
        )
      assertTrue(signRes.success)

      val profile = ResignProEngine.analyzeTarget(targetApk)
      assertTrue(profile.hasMultipleSigners)
      assertEquals(2, profile.signerProfiles.size)
      assertTrue(profile.enableV1)
      assertTrue(profile.enableV2)
      assertFalse(profile.enableV3)
      assertEquals(3072, profile.signerProfiles[0].keySpec.keySizeBits)
      assertEquals("RSA", profile.signerProfiles[0].keySpec.keyAlgorithm)
      assertEquals(256, profile.signerProfiles[1].keySpec.keySizeBits)
      assertEquals("EC", profile.signerProfiles[1].keySpec.keyAlgorithm)

      val askDir = File(tmpDir, "ask_out")
      val outApk = File(tmpDir, "resigned-pro.apk")
      val proResult =
        ResignProEngine.resignPro(
          inputApk = targetApk,
          outputApk = outApk,
          identities =
            listOf(
              IdentityInput(alias = "new-main", commonName = "New Identity A", organization = "Hephaistos"),
              IdentityInput(alias = "new-sec", commonName = "New Identity B", organization = "Hephaistos"),
            ),
          askOutputDir = askDir,
        )

      assertTrue(proResult.resignResult.success)
      assertEquals(2, proResult.generatedAskPaths.size)
      assertTrue(proResult.generatedAskPaths.all { File(it).exists() })
      assertTrue(proResult.generatedAskContainers.all { it.mode == AskMode.ASK_OPEN })

      val reProfile = ResignProEngine.analyzeTarget(outApk)
      assertTrue(reProfile.verificationReport.verified)
      assertEquals(2, reProfile.signerProfiles.size)
      assertEquals(3072, reProfile.signerProfiles[0].keySpec.keySizeBits)
      assertEquals(256, reProfile.signerProfiles[1].keySpec.keySizeBits)
      assertTrue(reProfile.signerProfiles[0].detectedSubjectDn.contains("New Identity A"))
      assertTrue(reProfile.signerProfiles[1].detectedSubjectDn.contains("New Identity B"))
    } finally {
      tmpDir.deleteRecursively()
    }
  }

  @Test
  fun `osSign analyzes dynamic groups ignores symlinks resigns XML refs and supports restore plus delete bak`() {
    val tmpDir = Files.createTempDirectory("ossign_test_").toFile()
    try {
      // Group 1 (platform): RSA 2048
      val platContainer =
        AskKeyManager.createAsk(
          CreateAskOptions(
            alias = "platform-orig",
            algorithm = KeyAlgorithm.RSA_2048,
            commonName = "Android",
            organizationalUnit = "Android",
            organization = "AOSP",
            country = "US",
          )
        )
      val platKey = AskKeyManager.unlockAsk(platContainer, null)

      // Group 2 (media): EC P-256
      val mediaContainer =
        AskKeyManager.createAsk(
          CreateAskOptions(
            alias = "media-orig",
            algorithm = KeyAlgorithm.EC_P256,
            commonName = "MediaSigner",
            organization = "AOSP",
          )
        )
      val mediaKey = AskKeyManager.unlockAsk(mediaContainer, null)

      // Create unpacked partition layout
      val privAppApk = File(tmpDir, "priv-app/SystemUI/SystemUI.apk")
      val unsignedPriv = File(tmpDir, "tmp_sysui.apk").also { createMinimalApk(it, "sysui") }
      assertTrue(
        ApkSignerEngine.resign(
            unsignedPriv,
            privAppApk,
            platKey,
            SigningOptions(enableV1 = true, enableV2 = true, enableV3 = true),
          )
          .success
      )
      unsignedPriv.delete()

      val appApk = File(tmpDir, "app/Gallery/Gallery.apk")
      val unsignedGal = File(tmpDir, "tmp_gal.apk").also { createMinimalApk(it, "gal") }
      assertTrue(
        ApkSignerEngine.resign(
            unsignedGal,
            appApk,
            mediaKey,
            SigningOptions(enableV1 = false, enableV2 = true, enableV3 = true),
          )
          .success
      )
      unsignedGal.delete()

      val apexFile = File(tmpDir, "apex/com.test.media.apex")
      val unsignedApex = File(tmpDir, "tmp_apex.apex").also { createMinimalApex(it) }
      assertTrue(
        ApkSignerEngine.resign(
            unsignedApex,
            apexFile,
            mediaKey,
            SigningOptions(enableV1 = false, enableV2 = true, enableV3 = true),
          )
          .success
      )
      unsignedApex.delete()

      val signedJar = File(tmpDir, "framework/signed-ext.jar")
      val unsignedJarSrc = File(tmpDir, "tmp_sjar.jar").also { createMinimalJar(it) }
      JarSignerEngine.signJar(unsignedJarSrc, signedJar, platKey)
      unsignedJarSrc.delete()

      val unsignedJar = File(tmpDir, "framework/framework.jar").also { createMinimalJar(it, "android/app/Activity.class") }
      val unsignedJarOrigBytes = unsignedJar.readBytes()

      // Dynamic permission XML with hex DER cert & PEM cert file
      val platHexUpper = CryptoSupport.encodeCertHexDer(platKey.certificate, uppercase = true)
      val macXml = File(tmpDir, "etc/permissions/mac_permissions.xml").apply { parentFile.mkdirs() }
      macXml.writeText(
        """
        <?xml version="1.0" encoding="utf-8"?>
        <policy>
          <signer signature="$platHexUpper">
            <seinfo value="platform"/>
          </signer>
        </policy>
        """.trimIndent(),
        Charsets.UTF_8,
      )
      val platPemFile = File(tmpDir, "etc/security/platform.x509.pem").apply { parentFile.mkdirs() }
      platPemFile.writeText(CryptoSupport.toPem("CERTIFICATE", platKey.certificate.encoded), Charsets.UTF_8)

      // Symlink pointing to SystemUI.apk + dangling symlink inside a subfolder
      val symFile = File(tmpDir, "priv-app/SystemUI/SystemUI_link.apk").toPath()
      Files.createSymbolicLink(symFile, privAppApk.toPath())
      val symDirTarget = Files.createTempDirectory("ossign_ext_target_").toFile()
      File(symDirTarget, "external.apk").also { createMinimalApk(it, "ext") }
      val symDirLink = File(tmpDir, "symlinked_dir").toPath()
      Files.createSymbolicLink(symDirLink, symDirTarget.toPath())

      try {
        // 1. VERIFY
        val inspection = OsSignAnalyzerEngine.analyzeDirectory(tmpDir)
        assertEquals(2, inspection.groups.size)
        assertEquals(4, inspection.signedArtifactsCount) // SystemUI.apk, Gallery.apk, com.test.media.apex, signed-ext.jar
        assertEquals(1, inspection.preservedUnsignedCount) // framework.jar
        assertEquals(2, inspection.symlinksIgnoredCount) // SystemUI_link.apk + symlinked_dir
        assertTrue(inspection.allPermissionReferences.any { it.format == OsReferenceFormat.XML_HEX_CERT })
        assertTrue(inspection.allPermissionReferences.any { it.format == OsReferenceFormat.PEM_CERT_BLOCK })
        assertTrue(inspection.preservedArtifacts.any { it.relativePath == "framework/framework.jar" && it.trustAction == OsTrustAction.PRESERVED_UNSIGNED })

        val sysUiOrigBytes = privAppApk.readBytes()
        val macXmlOrigText = macXml.readText(Charsets.UTF_8)

        // 2. RESIGNER with CREATE_WITH_IDENTITIES + .bak backups
        val askOutDir = File(tmpDir, "_ask_generated")
        val plan =
          OsResignPlan(
            strategy = OsResignKeyStrategy.CREATE_WITH_IDENTITIES,
            identityPerGroup =
              inspection.groups.associate { grp ->
                grp.groupId to IdentityInput(alias = "id_${grp.groupId}", commonName = "Custom ${grp.label}")
              },
            createBackups = true,
          )
        val resignReport = OsSignResignEngine.executeResign(inspection, plan, askOutDir)
        assertEquals(4, resignReport.totalSucceeded)
        assertEquals(0, resignReport.totalFailed)
        assertEquals(2, resignReport.totalReferencesUpdated) // mac_permissions.xml + platform.x509.pem
        assertNotNull(resignReport.backupManifest)
        assertEquals(2, resignReport.generatedAskPaths.size)

        // Verify symlinks were NEVER followed, modified, or turned into backups
        assertTrue(Files.isSymbolicLink(symFile))
        assertTrue(Files.isSymbolicLink(symDirLink))
        assertFalse(File("${symFile.toAbsolutePath()}${OsSignResignEngine.BACKUP_SUFFIX}").exists())

        // Verify unsigned framework.jar remained untouched
        assertTrue(unsignedJarOrigBytes.contentEquals(unsignedJar.readBytes()))

        // Verify SystemUI.apk & XML reference updated coherently
        val newVerifySysUi = ApkVerifierEngine.verify(privAppApk)
        assertTrue(newVerifySysUi.verified)
        val newPlatSha256 = newVerifySysUi.allUniqueSigners.first().fingerprints.sha256
        assertNotEquals(platKey.certificate.let { CryptoSupport.certificateFingerprints(it).sha256 }, newPlatSha256)

        val updatedXml = macXml.readText(Charsets.UTF_8)
        assertNotEquals(macXmlOrigText, updatedXml)
        assertTrue(updatedXml.contains("""<seinfo value="platform"/>"""))
        val newHexMatch = Regex("""signature="([0-9A-F]+)"""").find(updatedXml)!!.groupValues[1]
        val parsedNewXmlCert = CryptoSupport.tryParseCertificateHex(newHexMatch)!!
        assertEquals(newPlatSha256, CryptoSupport.certificateFingerprints(parsedNewXmlCert).sha256)

        // Re-running analyzeDirectory on resigned tree verifies signed JAR & updated groups
        val postInspection = OsSignAnalyzerEngine.analyzeDirectory(tmpDir)
        assertEquals(2, postInspection.groups.size)
        assertTrue(postInspection.groups.flatMap { it.artifacts }.all { it.verified })

        // 3. Test RESTORE from .bak
        val manifest = resignReport.backupManifest!!
        val (restoredCount, restoreErrors) = OsSignResignEngine.restoreFromBackups(manifest)
        assertTrue(restoreErrors.isEmpty())
        assertTrue(restoredCount >= 5)
        assertTrue(sysUiOrigBytes.contentEquals(privAppApk.readBytes()))
        assertEquals(macXmlOrigText, macXml.readText(Charsets.UTF_8))

        // 4. Re-run with CLONE_DETECTED_KEYS + test DELETE .bak
        val cloneReport =
          OsSignResignEngine.executeResign(
            inspection,
            OsResignPlan(strategy = OsResignKeyStrategy.CLONE_DETECTED_KEYS, createBackups = true),
            askOutDir,
          )
        assertEquals(4, cloneReport.totalSucceeded)
        val cloneManifest = cloneReport.backupManifest!!
        assertTrue(File(cloneManifest.entries.first().backupPath).exists())
        val (deletedCount, deleteErrors) = OsSignResignEngine.deleteBackups(cloneManifest)
        assertTrue(deleteErrors.isEmpty())
        assertEquals(cloneManifest.entries.size, deletedCount)
        assertFalse(File(cloneManifest.entries.first().backupPath).exists())
        assertTrue(Files.isSymbolicLink(symFile))
      } finally {
        symDirTarget.deleteRecursively()
      }
    } finally {
      tmpDir.deleteRecursively()
    }
  }
}
