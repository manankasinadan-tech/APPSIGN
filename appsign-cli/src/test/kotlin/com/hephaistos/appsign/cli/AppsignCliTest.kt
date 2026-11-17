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
    } finally {
      tmpDir.deleteRecursively()
    }
  }
}
