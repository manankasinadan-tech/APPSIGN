package com.hephaistos.appsign.cli

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppsignCliTest {

  private fun createMinimalApk(file: File) {
    ZipOutputStream(FileOutputStream(file)).use { zos ->
      zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
      zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
      zos.closeEntry()
      zos.putNextEntry(ZipEntry("classes.dex"))
      zos.write("dex\n035\u0000cli-test".toByteArray(Charsets.UTF_8))
      zos.closeEntry()
    }
  }

  private fun runCli(vararg args: String): Pair<Int, String> {
    val outBuf = ByteArrayOutputStream()
    val errBuf = ByteArrayOutputStream()
    val code = executeCli(args.toList().toTypedArray(), PrintStream(outBuf), PrintStream(errBuf))
    return code to (outBuf.toString("UTF-8") + errBuf.toString("UTF-8"))
  }

  @Test
  fun `cli end-to-end key create inspect batch resign and verify json`() {
    val tmpDir = Files.createTempDirectory("appsign_cli_test_").toFile()
    try {
      val askFile = File(tmpDir, "ci-key.ask")
      val (createCode, createOut) =
        runCli(
          "key",
          "create",
          "--alias",
          "ci-signer",
          "--alg",
          "ec256",
          "--pass",
          "ci-secret",
          "--out",
          askFile.absolutePath,
          "--json",
        )
      assertEquals("Output: $createOut", ExitCodes.OK, createCode)
      assertTrue(askFile.exists())
      assertTrue(createOut.contains("\"ASK_LOCKED\""))

      val (inspectCode, inspectOut) = runCli("key", "inspect", askFile.absolutePath, "--json")
      assertEquals(ExitCodes.OK, inspectCode)
      assertTrue(inspectOut.contains("ci-signer"))

      val apk1 = File(tmpDir, "app1.apk").also { createMinimalApk(it) }
      val apk2 = File(tmpDir, "app2.apk").also { createMinimalApk(it) }
      val outDir = File(tmpDir, "signed")

      // Unsigned verify should return VERIFICATION_FAILED (1)
      val (unsignedCode, _) = runCli("verify", apk1.absolutePath, "--json")
      assertEquals(ExitCodes.VERIFICATION_FAILED, unsignedCode)

      // Batch resign with glob pattern
      val (resignCode, resignOut) =
        runCli(
          "resign",
          File(tmpDir, "*.apk").absolutePath,
          "--key",
          askFile.absolutePath,
          "--pass",
          "ci-secret",
          "--min-sdk",
          "24",
          "--output",
          outDir.absolutePath,
          "--json",
        )
      assertEquals("Output: $resignOut", ExitCodes.OK, resignCode)
      assertTrue(File(outDir, "app1-signed.apk").exists())
      assertTrue(File(outDir, "app2-signed.apk").exists())

      // Verify signed outputs
      val (verifyCode, verifyOut) =
        runCli("verify", File(outDir, "*.apk").absolutePath, "--json")
      assertEquals("Output: $verifyOut", ExitCodes.OK, verifyCode)
      assertTrue(verifyOut.contains("\"verified\": true"))

      // RESIGNPRO on signed app1
      val signedApp1 = File(outDir, "app1-signed.apk")
      val proOutApk = File(tmpDir, "app1-pro.apk")
      val proAskDir = File(tmpDir, "pro_keys")
      val (proCode, proOut) =
        runCli(
          "resign-pro",
          signedApp1.absolutePath,
          "--alias",
          "pro-id",
          "--cn",
          "Pro Tester",
          "--ask-dir",
          proAskDir.absolutePath,
          "--output",
          proOutApk.absolutePath,
          "--json",
        )
      assertEquals("Pro output: $proOut", ExitCodes.OK, proCode)
      assertTrue(proOutApk.exists())
      assertTrue(proOut.contains("\"EC\""))

      // OS Sign verify -> resign -> restore -> clean-bak
      val osDir = File(tmpDir, "os_part").apply { mkdirs() }
      val osApp = File(osDir, "priv-app/Demo/Demo.apk").apply { parentFile.mkdirs() }
      signedApp1.copyTo(osApp, overwrite = true)
      val origBytes = osApp.readBytes()

      val (osVerifyCode, osVerifyOut) = runCli("os-sign", "verify", osDir.absolutePath, "--json")
      assertEquals("OS verify: $osVerifyOut", ExitCodes.OK, osVerifyCode)
      assertTrue(osVerifyOut.contains("\"signedArtifactsCount\": 1"))

      val manifestFile = File(tmpDir, "os-manifest.json")
      val (osResignCode, osResignOut) =
        runCli(
          "os-sign",
          "resign",
          osDir.absolutePath,
          "--strategy",
          "identities",
          "--cn",
          "OS Custom",
          "--ask-dir",
          File(tmpDir, "os_keys").absolutePath,
          "--manifest-out",
          manifestFile.absolutePath,
          "--json",
        )
      assertEquals("OS resign: $osResignOut", ExitCodes.OK, osResignCode)
      assertTrue(manifestFile.exists())
      assertTrue(File("${osApp.absolutePath}.appsign.bak").exists())

      val (restoreCode, restoreOut) = runCli("os-sign", "restore", manifestFile.absolutePath)
      assertEquals("OS restore: $restoreOut", ExitCodes.OK, restoreCode)
      assertTrue(origBytes.contentEquals(osApp.readBytes()))

      // Re-resign and test clean-bak
      val (osResign2Code, _) =
        runCli(
          "os-sign",
          "resign",
          osDir.absolutePath,
          "--strategy",
          "clone",
          "--ask-dir",
          File(tmpDir, "os_keys_clone").absolutePath,
          "--manifest-out",
          manifestFile.absolutePath,
        )
      assertEquals(ExitCodes.OK, osResign2Code)
      val (cleanCode, _) = runCli("os-sign", "clean-bak", manifestFile.absolutePath)
      assertEquals(ExitCodes.OK, cleanCode)
      assertEquals(false, File("${osApp.absolutePath}.appsign.bak").exists())
    } finally {
      tmpDir.deleteRecursively()
    }
  }
}
