package com.example

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @get:Rule val composeTestRule = createAndroidComposeRule<MainActivity>()

  @Test
  fun `app_name matches APPSIGN`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    assertEquals("APPSIGN", context.getString(R.string.app_name))
  }

  @Test
  fun `home verify resign key manager and settings user journeys work`() {
    composeTestRule.waitForIdle()

    // Home renders APPSIGN and both primary cards
    composeTestRule.onNodeWithTag("home_verify_card").assertIsDisplayed()
    composeTestRule.onNodeWithTag("home_resign_card").assertIsDisplayed()

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

    // Navigate to Verify and Resign tabs cleanly
    composeTestRule.onNodeWithTag("nav_verify").performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("verify_saf_picker_button").assertIsDisplayed()

    composeTestRule.onNodeWithTag("nav_resign").performClick()
    composeTestRule.waitForIdle()
    composeTestRule.onNodeWithTag("resign_saf_apk_button").assertIsDisplayed()
  }
}
