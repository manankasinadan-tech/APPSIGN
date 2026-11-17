package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.ui.theme.AppsignTheme
import com.hephaistos.appsign.android.ui.AppsignApp
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.android.ui.i18n.stringsFor
import com.hephaistos.appsign.android.ui.viewmodel.AppsignViewModel

class MainActivity : ComponentActivity() {
  private val viewModel: AppsignViewModel by viewModels { AppsignViewModel.Factory(applicationContext) }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    setContent {
      val settings by viewModel.settings.collectAsStateWithLifecycle()
      AppsignTheme(themePreference = settings.themePreference) {
        CompositionLocalProvider(LocalAppsignStrings provides stringsFor(settings.language)) {
          AppsignApp(viewModel = viewModel)
        }
      }
    }
  }

  override fun onResume() {
    super.onResume()
    viewModel.refreshStoragePermission()
  }
}
