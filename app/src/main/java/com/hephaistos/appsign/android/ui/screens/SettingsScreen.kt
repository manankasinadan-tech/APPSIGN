package com.hephaistos.appsign.android.ui.screens

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.ui.theme.ThemePreference
import com.hephaistos.appsign.android.data.repository.AppLanguage
import com.hephaistos.appsign.android.data.repository.AppSettings
import com.hephaistos.appsign.android.system.DeviceStorageHelper
import com.hephaistos.appsign.android.system.RootProbeResult
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(
  settings: AppSettings,
  hasStoragePermission: Boolean,
  rootProbe: RootProbeResult?,
  onUpdateTheme: (ThemePreference) -> Unit,
  onUpdateLanguage: (AppLanguage) -> Unit,
  onUpdateDefaultDirs: (String, String) -> Unit,
  onUpdateSigningDefaults: (Boolean, Boolean, Boolean, Boolean, Boolean, Boolean) -> Unit,
  onRefreshStoragePermission: () -> Unit,
  onProbeRoot: () -> Unit,
  onToggleRoot: (Boolean) -> Unit,
) {
  val strings = LocalAppsignStrings.current
  val context = LocalContext.current

  var browseDir by remember(settings.defaultBrowseDir) { mutableStateOf(settings.defaultBrowseDir) }
  var outputDir by remember(settings.defaultOutputDir) { mutableStateOf(settings.defaultOutputDir) }

  val allFilesLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
      onRefreshStoragePermission()
    }

  val legacyStorageLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
      onRefreshStoragePermission()
    }

  LaunchedEffect(Unit) {
    onRefreshStoragePermission()
  }

  Column(
    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Column(modifier = Modifier.fillMaxWidth().widthIn(max = 760.dp)) {
      Text(strings.settingsTitle, style = MaterialTheme.typography.headlineMedium)
      Spacer(Modifier.height(14.dp))

      // Theme Mode
      SectionCard {
        Text(strings.themeSectionTitle, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(10.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          FilterChip(
            selected = settings.themePreference == ThemePreference.SYSTEM,
            onClick = { onUpdateTheme(ThemePreference.SYSTEM) },
            label = { Text(strings.themeSystem) },
            modifier = Modifier.testTag("settings_theme_system"),
          )
          FilterChip(
            selected = settings.themePreference == ThemePreference.LIGHT,
            onClick = { onUpdateTheme(ThemePreference.LIGHT) },
            label = { Text(strings.themeLight) },
            modifier = Modifier.testTag("settings_theme_light"),
          )
          FilterChip(
            selected = settings.themePreference == ThemePreference.DARK,
            onClick = { onUpdateTheme(ThemePreference.DARK) },
            label = { Text(strings.themeDark) },
            modifier = Modifier.testTag("settings_theme_dark"),
          )
        }
      }

      Spacer(Modifier.height(12.dp))

      // Language
      SectionCard {
        Text(strings.languageSectionTitle, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(10.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          AppLanguage.entries.forEach { lang ->
            FilterChip(
              selected = settings.language == lang,
              onClick = { onUpdateLanguage(lang) },
              label = { Text(lang.label) },
              modifier = Modifier.testTag("settings_lang_${lang.code}"),
            )
          }
        }
      }

      Spacer(Modifier.height(12.dp))

      // Storage & Root Permissions
      SectionCard {
        Text(strings.permissionsSectionTitle, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(12.dp))

        // Full Storage Access
        Row(verticalAlignment = Alignment.CenterVertically) {
          Icon(Icons.Rounded.Folder, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
          Spacer(Modifier.width(10.dp))
          Column(modifier = Modifier.weight(1f)) {
            Text(strings.storagePermissionTitle, style = MaterialTheme.typography.titleSmall)
            Text(
              text = if (hasStoragePermission) strings.storagePermissionGranted else strings.storagePermissionMissing,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          }
          StatusPillBadge(
            text = if (hasStoragePermission) "ON" else "SAF",
            containerColor =
              if (hasStoragePermission) MaterialTheme.colorScheme.secondaryContainer
              else MaterialTheme.colorScheme.surfaceVariant,
            contentColor =
              if (hasStoragePermission) MaterialTheme.colorScheme.onSecondaryContainer
              else MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        Spacer(Modifier.height(10.dp))
        OutlinedButton(
          onClick = {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
              runCatching { allFilesLauncher.launch(DeviceStorageHelper.createAllFilesAccessIntent(context)) }
                .onFailure { allFilesLauncher.launch(DeviceStorageHelper.createFallbackAllFilesIntent()) }
            } else {
              legacyStorageLauncher.launch(
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE)
              )
            }
          },
          modifier = Modifier.testTag("settings_grant_storage_button"),
        ) {
          Text(strings.grantStoragePermission)
        }

        Spacer(Modifier.height(16.dp))

        // Optional Root Access
        Row(verticalAlignment = Alignment.CenterVertically) {
          Icon(Icons.Rounded.AdminPanelSettings, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
          Spacer(Modifier.width(10.dp))
          Column(modifier = Modifier.weight(1f)) {
            Text(strings.rootPermissionTitle, style = MaterialTheme.typography.titleSmall)
            Text(
              text = strings.rootPermissionDesc,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          }
          Switch(
            checked = settings.rootAccessEnabled,
            onCheckedChange = onToggleRoot,
            modifier = Modifier.testTag("settings_root_switch"),
          )
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
          OutlinedButton(onClick = onProbeRoot, modifier = Modifier.testTag("settings_probe_root_button")) {
            Text(strings.probeRootButton)
          }
          if (rootProbe != null) {
            Text(
              text =
                if (rootProbe.available) strings.rootAvailableStatus(rootProbe.identity)
                else strings.rootUnavailableStatus(rootProbe.error ?: "denied"),
              style = MaterialTheme.typography.labelSmall,
              color = if (rootProbe.available) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
              modifier = Modifier.weight(1f),
            )
          }
        }
      }

      Spacer(Modifier.height(12.dp))

      // Default Folders
      SectionCard {
        Text(strings.foldersSectionTitle, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(
          value = browseDir,
          onValueChange = { browseDir = it },
          label = { Text(strings.defaultBrowseDirLabel) },
          singleLine = true,
          modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
          value = outputDir,
          onValueChange = { outputDir = it },
          label = { Text(strings.defaultOutputDirLabel) },
          singleLine = true,
          modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(10.dp))
        Button(onClick = { onUpdateDefaultDirs(browseDir, outputDir) }) {
          Icon(Icons.Rounded.Save, contentDescription = null)
          Spacer(Modifier.width(6.dp))
          Text(strings.saveFolders)
        }
      }

      Spacer(Modifier.height(12.dp))

      // Default Signing Options
      SectionCard {
        Text(strings.signingDefaultsTitle, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(10.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          FilterChip(
            selected = settings.defaultV1,
            onClick = { onUpdateSigningDefaults(!settings.defaultV1, settings.defaultV2, settings.defaultV3, settings.defaultV31, settings.defaultV4, settings.alignBeforeSign) },
            label = { Text("v1") },
          )
          FilterChip(
            selected = settings.defaultV2,
            onClick = { onUpdateSigningDefaults(settings.defaultV1, !settings.defaultV2, settings.defaultV3, settings.defaultV31, settings.defaultV4, settings.alignBeforeSign) },
            label = { Text("v2") },
          )
          FilterChip(
            selected = settings.defaultV3,
            onClick = { onUpdateSigningDefaults(settings.defaultV1, settings.defaultV2, !settings.defaultV3, settings.defaultV31, settings.defaultV4, settings.alignBeforeSign) },
            label = { Text("v3") },
          )
          FilterChip(
            selected = settings.defaultV31,
            onClick = { onUpdateSigningDefaults(settings.defaultV1, settings.defaultV2, settings.defaultV3, !settings.defaultV31, settings.defaultV4, settings.alignBeforeSign) },
            label = { Text("v3.1") },
          )
          FilterChip(
            selected = settings.defaultV4,
            onClick = { onUpdateSigningDefaults(settings.defaultV1, settings.defaultV2, settings.defaultV3, settings.defaultV31, !settings.defaultV4, settings.alignBeforeSign) },
            label = { Text("v4") },
          )
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text(strings.zipAlignLabel, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
          Switch(
            checked = settings.alignBeforeSign,
            onCheckedChange = { onUpdateSigningDefaults(settings.defaultV1, settings.defaultV2, settings.defaultV3, settings.defaultV31, settings.defaultV4, it) },
          )
        }
      }
      Spacer(Modifier.height(24.dp))
    }
  }
}
