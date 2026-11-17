package com.hephaistos.appsign.core.ask

import com.hephaistos.appsign.core.model.AskMode
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.KeyAlgorithm
import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AskKeyManagerTest {

  @Test
  fun `create and unlock ASK-OPEN without password`() {
    val container =
      AskKeyManager.createAsk(
        CreateAskOptions(
          alias = "release-open",
          algorithm = KeyAlgorithm.RSA_2048,
          commonName = "APPSIGN Test",
          passphrase = null,
        )
      )
    assertEquals(AskMode.ASK_OPEN, container.mode)
    assertFalse(container.privateKeyPayload.encrypted)

    val json = AskKeyManager.serializeAsk(container)
    val parsed = AskKeyManager.parseAsk(json)
    val inspect = AskKeyManager.inspectAsk(parsed)
    assertNotNull(inspect.securityWarning)
    assertEquals("release-open", inspect.metadata.alias)

    val unlocked = AskKeyManager.unlockAsk(parsed, passphrase = null)
    assertEquals("RSA", unlocked.privateKey.algorithm)
    assertEquals(unlocked.certificate.publicKey.encoded.toList(), unlocked.certificateChain.first().publicKey.encoded.toList())
  }

  @Test
  fun `create unlock and reject wrong password or tampered AAD on ASK-LOCKED`() {
    val container =
      AskKeyManager.createAsk(
        CreateAskOptions(
          alias = "release-ec",
          algorithm = KeyAlgorithm.EC_P256,
          commonName = "EC Signer",
          passphrase = "s3cr3t-password".toCharArray(),
        )
      )
    assertEquals(AskMode.ASK_LOCKED, container.mode)
    assertTrue(container.privateKeyPayload.encrypted)

    // Inspect works without password
    val inspect = AskKeyManager.inspectAsk(container)
    assertEquals(AskMode.ASK_LOCKED, inspect.mode)
    assertEquals(null, inspect.securityWarning)

    // Missing password rejected
    try {
      AskKeyManager.unlockAsk(container, null)
      fail("Expected AskPasswordRequiredException")
    } catch (_: AskPasswordRequiredException) {
      // expected
    }

    // Wrong password rejected
    try {
      AskKeyManager.unlockAsk(container, "wrong-password".toCharArray())
      fail("Expected AskDecryptionException")
    } catch (_: AskDecryptionException) {
      // expected
    }

    // Correct password succeeds
    val unlocked = AskKeyManager.unlockAsk(container, "s3cr3t-password".toCharArray())
    assertEquals("EC", unlocked.privateKey.algorithm)

    // Tampered keyId breaks GCM AAD authentication
    val tampered = container.copy(keyId = "00000000-0000-0000-0000-000000000000")
    try {
      AskKeyManager.unlockAsk(tampered, "s3cr3t-password".toCharArray())
      fail("Expected AskDecryptionException on tampered AAD")
    } catch (_: AskDecryptionException) {
      // expected
    }
  }

  @Test
  fun `interoperability round-trip with PKCS12 JKS and PKCS8 plus X509`() {
    val tmpDir = Files.createTempDirectory("ask_interop_").toFile()
    try {
      val container =
        AskKeyManager.createAsk(
          CreateAskOptions(
            alias = "interop",
            algorithm = KeyAlgorithm.RSA_2048,
            passphrase = "askpw".toCharArray(),
          )
        )
      val unlocked = AskKeyManager.unlockAsk(container, "askpw".toCharArray())

      // Export & Re-import PKCS#12
      val p12File = File(tmpDir, "test.p12")
      AskKeyManager.exportToPkcs12(unlocked, p12File, "p12pass".toCharArray())
      val fromP12 = AskKeyManager.importFromPkcs12(p12File, "p12pass".toCharArray())
      assertEquals(container.metadata.fingerprints.sha256, fromP12.metadata.fingerprints.sha256)

      // Export & Re-import JKS via PureJvmJksCodec + standard JKS
      val jksFile = File(tmpDir, "test.jks")
      val jksBytes =
        PureJvmJksCodec.writePrivateKeyEntry(
          alias = "interop",
          privateKey = unlocked.privateKey,
          chain = unlocked.certificateChain,
          storePassword = "jkspass".toCharArray(),
        )
      jksFile.writeBytes(jksBytes)
      val jksRead = PureJvmJksCodec.readPrivateKeyEntry(jksBytes, "jkspass".toCharArray())
      assertEquals("interop", jksRead.alias)
      val fromJks = AskKeyManager.importFromJks(jksFile, "jkspass".toCharArray())
      assertEquals(container.metadata.fingerprints.sha256, fromJks.metadata.fingerprints.sha256)

      // Export & Re-import PKCS#8 + X.509 PEM
      val pk8File = File(tmpDir, "key.pk8")
      val certFile = File(tmpDir, "cert.pem")
      val warning = AskKeyManager.exportToPkcs8AndCert(unlocked, pk8File, certFile, pemEncoded = true)
      assertTrue(warning.contains("SECURITY WARNING"))
      val fromPem = AskKeyManager.importFromPkcs8AndCert(pk8File, certFile, alias = "pem-import")
      assertEquals(container.metadata.fingerprints.sha256, fromPem.metadata.fingerprints.sha256)
    } finally {
      tmpDir.deleteRecursively()
    }
  }
}
