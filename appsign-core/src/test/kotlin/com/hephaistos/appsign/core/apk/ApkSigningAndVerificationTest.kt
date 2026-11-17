package com.hephaistos.appsign.core.apk

import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.KeyAlgorithm
import com.hephaistos.appsign.core.model.SignatureSchemeVersion
import com.hephaistos.appsign.core.model.SigningOptions
import com.hephaistos.appsign.core.model.VerificationStatus
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkSigningAndVerificationTest {

  private fun createMinimalUnsignedApk(target: File) {
    ZipOutputStream(FileOutputStream(target)).use { zos ->
      zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
      zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
      zos.closeEntry()

      zos.putNextEntry(ZipEntry("classes.dex"))
      zos.write("dex\n035\u0000dummy-payload".toByteArray(Charsets.UTF_8))
      zos.closeEntry()

      zos.putNextEntry(ZipEntry("assets/hello.txt"))
      zos.write("APPSIGN test asset".toByteArray(Charsets.UTF_8))
      zos.closeEntry()
    }
  }

  @Test
  fun `sign verify batch resign and detect tampering with apksig`() {
    val tmpDir = Files.createTempDirectory("appsign_apk_test_").toFile()
    try {
      val unsignedApk = File(tmpDir, "sample.apk")
      createMinimalUnsignedApk(unsignedApk)

      // 1. Unsigned APK verification
      val unsignedReport = ApkVerifierEngine.verify(unsignedApk)
      assertFalse(unsignedReport.verified)
      assertEquals(VerificationStatus.UNSIGNED, unsignedReport.overallStatus)

      // 2. Create ASK-LOCKED key and unlock
      val ask =
        AskKeyManager.createAsk(
          CreateAskOptions(
            alias = "test-signer",
            algorithm = KeyAlgorithm.RSA_2048,
            commonName = "APPSIGN QA",
            passphrase = "test-pass".toCharArray(),
          )
        )
      val unlocked = AskKeyManager.unlockAsk(ask, "test-pass".toCharArray())

      // 3. Sign with V1 + V2 + V3 + V4 (.idsig)
      val signedApk = File(tmpDir, "sample-signed.apk")
      val resignResult =
        ApkSignerEngine.resign(
          inputApk = unsignedApk,
          outputApk = signedApk,
          keyMaterial = unlocked,
          options =
            SigningOptions(
              enableV1 = true,
              enableV2 = true,
              enableV3 = true,
              enableV4 = true,
              alignBeforeSign = true,
              minSdkVersion = 24,
            ),
        )
      assertTrue("Expected resign success, error=${resignResult.errorMessage}", resignResult.success)
      assertNotNull(resignResult.postVerifyReport)
      assertTrue(resignResult.postVerifyReport!!.verified)
      assertTrue(resignResult.v4IdsigOutputPath != null && File(resignResult.v4IdsigOutputPath!!).exists())

      // 4. Verify all schemes directly
      val verifiedReport = ApkVerifierEngine.verify(signedApk)
      assertTrue(verifiedReport.verified)
      assertTrue(verifiedReport.v4IdsigPresent)
      assertTrue(verifiedReport.schemeResults.first { it.scheme == SignatureSchemeVersion.V1 }.verified)
      assertTrue(verifiedReport.schemeResults.first { it.scheme == SignatureSchemeVersion.V2 }.verified)
      assertTrue(verifiedReport.schemeResults.first { it.scheme == SignatureSchemeVersion.V3 }.verified)
      assertTrue(verifiedReport.schemeResults.first { it.scheme == SignatureSchemeVersion.V4 }.verified)
      assertEquals(1, verifiedReport.allUniqueSigners.size)

      // 5. Tamper with a single byte in the signed APK and verify integrity failure is detected
      val bytes = signedApk.readBytes()
      bytes[bytes.size / 2] = (bytes[bytes.size / 2].toInt() xor 0xFF).toByte()
      val tamperedApk = File(tmpDir, "sample-tampered.apk")
      tamperedApk.writeBytes(bytes)
      val tamperedReport = ApkVerifierEngine.verify(tamperedApk)
      assertFalse(tamperedReport.verified)
      assertEquals(VerificationStatus.INVALID, tamperedReport.overallStatus)

      // 6. Batch resign preserves originals
      val outDir = File(tmpDir, "batch_out")
      val secondApk = File(tmpDir, "second.apk")
      createMinimalUnsignedApk(secondApk)
      val batchResults =
        ApkSignerEngine.resignBatch(
          inputApks = listOf(unsignedApk, secondApk),
          outputDir = outDir,
          keyMaterial = unlocked,
          options = SigningOptions(minSdkVersion = 24),
        )
      assertEquals(2, batchResults.size)
      assertTrue(batchResults.all { it.success })
      assertTrue(unsignedApk.exists())
      assertTrue(secondApk.exists())
    } finally {
      tmpDir.deleteRecursively()
    }
  }
}
