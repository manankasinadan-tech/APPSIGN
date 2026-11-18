package com.example

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ApplicationProvider
import com.hephaistos.appsign.core.apk.ApkSignerEngine
import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.KeyAlgorithm
import com.hephaistos.appsign.core.model.SigningOptions
import com.hephaistos.appsign.core.ossign.OsSignResignEngine
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @get:Rule val composeTestRule = createAndroidComposeRule<MainActivity>()

  private fun createMinimalUnsignedApk(file: File) {
    file.parentFile?.mkdirs()
    ZipOutputStream(FileOutputStream(file)).use { zos ->
      zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
      zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
      zos.closeEntry()
      zos.putNextEntry(ZipEntry("classes.dex"))
      zos.write("dex\n035\u0000robolectric".toByteArray(Charsets.UTF_8))
      zos.closeEntry()
    }
  }

  @Test
  fun `app_name matches APPSIGN`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    assertEquals("APPSIGN", context.getString(R.string.app_name))
  }

  @Test
  fun `home verify resign pro key manager and settings user journeys work`() {
    composeTestRule.waitForIdle()

    // Home renders APPSIGN and all 3 hero cards (Verify, Resign, OS Sign)
    composeTestRule.onNodeWithTag("home_verify_card").assertIsDisplayed()
    composeTestRule.onNodeWithTag("home_resign_card").assertIsDisplayed()
    composeTestRule.onNodeWithTag("home_os_sign_card").performScrollTo().assertIsDisplayed()

    // Navigate to Settings and switch language to English
    composeTestRule.onNodeWithTag("nav_settings").performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("settings_lang_en").performScrollTo().performClick()
    composeTestRule.waitUntil(timeoutMillis = 5_000) {
      composeTestRule.onAllNodesWithText("Application Language").fetchSemanticsNodes().isNotEmpty()
    }
    composeTestRule.onNodeWithText("Application Language").performScrollTo().assertIsDisplayed()

    // Switch theme to Dark
    composeTestRule.onNodeWithTag("settings_theme_dark").performScrollTo().performClick()
    composeTestRule.waitForIdle()

    // Navigate to Key Manager and create an ASK-OPEN key
    composeTestRule.onNodeWithTag("nav_keys").performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("key_create_button").performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("create_ask_alias_input").performTextReplacement("ci-test-key")
    composeTestRule.onNodeWithTag("create_ask_submit_button").performClick()
    composeTestRule.waitUntil(timeoutMillis = 10_000) {
      composeTestRule.onAllNodesWithText("ci-test-key").fetchSemanticsNodes().isNotEmpty()
    }
    composeTestRule.onNodeWithText("ci-test-key").assertIsDisplayed()

    // Navigate to Verify and Resign tabs cleanly + toggle RESIGNPRO mode
    composeTestRule.onNodeWithTag("nav_verify").performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("verify_saf_picker_button").assertIsDisplayed()

    composeTestRule.onNodeWithTag("nav_resign").performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("resign_saf_apk_button").assertIsDisplayed()
    composeTestRule.onNodeWithTag("resign_mode_pro").performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("resignpro_analyze_button").performScrollTo().assertIsDisplayed()
    composeTestRule.onNodeWithTag("resignpro_cn_input_0").performScrollTo().assertIsDisplayed()
    composeTestRule.onNodeWithTag("resignpro_run_button").performScrollTo().assertIsDisplayed()
  }

  @Test
  fun `osSign verify dashboard resigner popup restore and delete bak work`() {
    val tmpDir = Files.createTempDirectory("robo_ossign_").toFile()
    try {
      val ask =
        AskKeyManager.createAsk(
          CreateAskOptions(
            alias = "robo-plat",
            algorithm = KeyAlgorithm.RSA_2048,
            commonName = "RoboPlatform",
            organization = "TestOS",
          )
        )
      val unlocked = AskKeyManager.unlockAsk(ask, null)
      val unsigned = File(tmpDir, "tmp.apk").also { createMinimalUnsignedApk(it) }
      val sysApk = File(tmpDir, "priv-app/SysDemo/SysDemo.apk")
      assertTrue(
        ApkSignerEngine.resign(
            unsigned,
            sysApk,
            unlocked,
            SigningOptions(enableV1 = true, enableV2 = true, enableV3 = true),
          )
          .success
      )
      unsigned.delete()
      val origBytes = sysApk.readBytes()

      val hexUpper = CryptoSupport.encodeCertHexDer(unlocked.certificate, uppercase = true)
      val macXml = File(tmpDir, "etc/permissions/mac_permissions.xml").apply { parentFile?.mkdirs() }
      macXml.writeText("""<policy><signer signature="$hexUpper"><seinfo value="plat"/></signer></policy>""")

      val sym = File(tmpDir, "priv-app/SysDemo/link.apk").toPath()
      Files.createSymbolicLink(sym, sysApk.toPath())

      composeTestRule.waitForIdle()
      composeTestRule.onNodeWithTag("home_os_sign_card").performScrollTo().performClick()
      composeTestRule.waitForIdle()

      composeTestRule.onNodeWithTag("ossign_path_input").performScrollTo().performTextReplacement(tmpDir.absolutePath)
      composeTestRule.onNodeWithTag("ossign_verify_button").performScrollTo().performClick()
      composeTestRule.waitUntil(timeoutMillis = 15_000) {
        composeTestRule.onAllNodesWithText("1 Key Groups").fetchSemanticsNodes().isNotEmpty()
      }

      // Open RESIGNER 3-strategy popup and run strategy 1 (CREATE_WITH_IDENTITIES)
      composeTestRule.onNodeWithTag("ossign_resign_button").performScrollTo().performClick()
      composeTestRule.waitForIdle()
      composeTestRule.onNodeWithTag("os_strategy_identities").assertIsDisplayed()
      composeTestRule.onNodeWithTag("os_strategy_existing").assertIsDisplayed()
      composeTestRule.onNodeWithTag("os_strategy_clone").assertIsDisplayed()
      composeTestRule.onNodeWithTag("os_strategy_confirm_button").performClick()

      composeTestRule.waitUntil(timeoutMillis = 20_000) {
        composeTestRule.onAllNodesWithTag("ossign_restore_bak_button").fetchSemanticsNodes().isNotEmpty()
      }
      assertTrue(File("${sysApk.absolutePath}${OsSignResignEngine.BACKUP_SUFFIX}").exists())
      assertTrue(Files.isSymbolicLink(sym))

      // Click Restore (.bak)
      composeTestRule.onNodeWithTag("ossign_restore_bak_button").performScrollTo().performClick()
      composeTestRule.waitUntil(timeoutMillis = 15_000) {
        composeTestRule.onAllNodesWithTag("ossign_restore_bak_button").fetchSemanticsNodes().isEmpty()
      }
      assertTrue(origBytes.contentEquals(sysApk.readBytes()))

      // Run Clone strategy and then click Delete .bak
      composeTestRule.onNodeWithTag("ossign_resign_button").performScrollTo().performClick()
      composeTestRule.waitForIdle()
      composeTestRule.onNodeWithTag("os_strategy_clone").performClick()
      composeTestRule.onNodeWithTag("os_strategy_confirm_button").performClick()

      composeTestRule.waitUntil(timeoutMillis = 20_000) {
        composeTestRule.onAllNodesWithTag("ossign_delete_bak_button").fetchSemanticsNodes().isNotEmpty()
      }
      composeTestRule.onNodeWithTag("ossign_delete_bak_button").performScrollTo().performClick()
      composeTestRule.waitUntil(timeoutMillis = 15_000) {
        composeTestRule.onAllNodesWithTag("ossign_delete_bak_button").fetchSemanticsNodes().isEmpty()
      }
      assertFalse(File("${sysApk.absolutePath}${OsSignResignEngine.BACKUP_SUFFIX}").exists())
      assertTrue(Files.isSymbolicLink(sym))
    } finally {
      tmpDir.deleteRecursively()
    }
  }
}
