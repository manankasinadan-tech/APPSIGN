package com.hephaistos.appsign.android.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.EditNote
import androidx.compose.material.icons.rounded.Error
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.UploadFile
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.data.local.ManagedKeyEntity
import com.hephaistos.appsign.android.ui.components.PasswordPromptDialog
import com.hephaistos.appsign.android.ui.components.SdcardExplorerDialog
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.android.ui.viewmodel.ResignUiState
import com.hephaistos.appsign.android.ui.viewmodel.SigningKeySource
import com.hephaistos.appsign.core.model.CreateAskOptions

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ResignScreen(
  state: ResignUiState,
  managedKeys: List<ManagedKeyEntity>,
  defaultBrowseDir: String,
  hasStorageAccess: Boolean,
  onAddUris: (List<Uri>) -> Unit,
  onAddPaths: (List<String>) -> Unit,
  onSelectManagedKey: (ManagedKeyEntity) -> Unit,
  onSelectExternalKeyUri: (Uri) -> Unit,
  onCreateInlineKey: (CreateAskOptions) -> Unit,
  onUpdateSchemes: (Boolean, Boolean, Boolean, Boolean, Boolean, Boolean) -> Unit,
  onSetOutputPath: (String) -> Unit,
  onSetOutputSafTree: (Uri) -> Unit,
  onStartResign: (CharArray?) -> Unit,
  onDismissPassword: () -> Unit,
  onClearSelection: () -> Unit,
  onOpenSettings: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var showApkExplorer by remember { mutableStateOf(false) }
  var showOutputExplorer by remember { mutableStateOf(false) }
  var showCreateKeyDialog by remember { mutableStateOf(false) }

  val safApkLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
      if (uris.isNotEmpty()) onAddUris(uris)
    }

  val safExternalKeyLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
      if (uri != null) onSelectExternalKeyUri(uri)
    }

  val safTreeLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
      if (uri != null) onSetOutputSafTree(uri)
    }

  Column(
    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Column(modifier = Modifier.fillMaxWidth().widthIn(max = 760.dp)) {
      Text(strings.resignScreenTitle, style = MaterialTheme.typography.headlineMedium)
      Spacer(Modifier.height(14.dp))

      // Step 1: Select APKs
      SectionCard {
        Text(strings.stepSelectApks, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(10.dp))
        FlowRow(
          horizontalArrangement = Arrangement.spacedBy(8.dp),
          verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          OutlinedButton(
            onClick = { safApkLauncher.launch(arrayOf("application/vnd.android.package-archive", "*/*")) },
            modifier = Modifier.testTag("resign_saf_apk_button"),
          ) {
            Icon(Icons.Rounded.UploadFile, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(strings.pickSafApks)
          }
          OutlinedButton(
            onClick = { showApkExplorer = true },
            modifier = Modifier.testTag("resign_sdcard_apk_button"),
          ) {
            Icon(Icons.Rounded.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(strings.browseSdcard)
          }
        }

        if (state.targets.isNotEmpty()) {
          Spacer(Modifier.height(10.dp))
          Row(verticalAlignment = Alignment.CenterVertically) {
            Text(strings.selectedApksCount(state.targets.size), style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            TextButton(onClick = onClearSelection) {
              Icon(Icons.Rounded.DeleteSweep, contentDescription = null, modifier = Modifier.size(16.dp))
              Spacer(Modifier.width(4.dp))
              Text(strings.clearSelection)
            }
          }
          FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
          ) {
            state.targets.forEach { target ->
              AssistChip(onClick = {}, label = { Text(target.displayName, maxLines = 1, overflow = TextOverflow.Ellipsis) })
            }
          }
        }
      }

      Spacer(Modifier.height(14.dp))

      // Step 2: Signing Key
      SectionCard {
        Text(strings.stepSelectKey, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(10.dp))
        FlowRow(
          horizontalArrangement = Arrangement.spacedBy(8.dp),
          verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          OutlinedButton(
            onClick = { showCreateKeyDialog = true },
            modifier = Modifier.testTag("resign_create_key_button"),
          ) {
            Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(strings.createNewKeyInline)
          }
          OutlinedButton(
            onClick = { safExternalKeyLauncher.launch(arrayOf("*/*")) },
            modifier = Modifier.testTag("resign_import_ext_key_button"),
          ) {
            Icon(Icons.Rounded.Key, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(strings.importExternalKey)
          }
        }

        if (state.selectedKeySource is SigningKeySource.ExternalKeyFile) {
          Spacer(Modifier.height(8.dp))
          Surface(
            color = MaterialTheme.colorScheme.primaryContainer,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = "External: ${state.selectedKeySource.file.name}",
              style = MaterialTheme.typography.labelMedium,
              color = MaterialTheme.colorScheme.onPrimaryContainer,
              modifier = Modifier.padding(10.dp),
            )
          }
        }

        if (managedKeys.isNotEmpty()) {
          Spacer(Modifier.height(10.dp))
          managedKeys.forEach { key ->
            val selected =
              state.selectedKeySource is SigningKeySource.ManagedAsk &&
                state.selectedKeySource.entity.keyId == key.keyId
            Surface(
              modifier =
                Modifier.fillMaxWidth()
                  .padding(vertical = 4.dp)
                  .clickable { onSelectManagedKey(key) },
              shape = MaterialTheme.shapes.medium,
              color =
                if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
                else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
              border =
                if (selected) BorderStroke(1.dp, MaterialTheme.colorScheme.primary)
                else null,
            ) {
              Row(
                modifier = Modifier.padding(10.dp),
                verticalAlignment = Alignment.CenterVertically,
              ) {
                RadioButton(selected = selected, onClick = { onSelectManagedKey(key) })
                Spacer(Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                  Text(key.alias, style = MaterialTheme.typography.titleSmall)
                  Text(
                    "${key.algorithm} ${key.keySizeBits}-bit • ${key.mode}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                  )
                }
              }
            }
          }
        }
      }

      Spacer(Modifier.height(14.dp))

      // Step 3: Signature Schemes
      SectionCard {
        Text(strings.stepSelectSchemes, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(10.dp))
        FlowRow(
          horizontalArrangement = Arrangement.spacedBy(8.dp),
          verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          FilterChip(
            selected = state.enableV1,
            onClick = { onUpdateSchemes(!state.enableV1, state.enableV2, state.enableV3, state.enableV31, state.enableV4, state.alignBeforeSign) },
            label = { Text("v1 (JAR)") },
          )
          FilterChip(
            selected = state.enableV2,
            onClick = { onUpdateSchemes(state.enableV1, !state.enableV2, state.enableV3, state.enableV31, state.enableV4, state.alignBeforeSign) },
            label = { Text("v2") },
          )
          FilterChip(
            selected = state.enableV3,
            onClick = { onUpdateSchemes(state.enableV1, state.enableV2, !state.enableV3, state.enableV31, state.enableV4, state.alignBeforeSign) },
            label = { Text("v3") },
          )
          FilterChip(
            selected = state.enableV31,
            onClick = { onUpdateSchemes(state.enableV1, state.enableV2, state.enableV3, !state.enableV31, state.enableV4, state.alignBeforeSign) },
            label = { Text("v3.1") },
          )
          FilterChip(
            selected = state.enableV4,
            onClick = { onUpdateSchemes(state.enableV1, state.enableV2, state.enableV3, state.enableV31, !state.enableV4, state.alignBeforeSign) },
            label = { Text("v4 (.idsig)") },
          )
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text(strings.zipAlignLabel, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
          Switch(
            checked = state.alignBeforeSign,
            onCheckedChange = { onUpdateSchemes(state.enableV1, state.enableV2, state.enableV3, state.enableV31, state.enableV4, it) },
          )
        }
      }

      Spacer(Modifier.height(14.dp))

      // Step 4: Output Folder
      SectionCard {
        Text(strings.stepOutputFolder, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text(
          text = state.outputTreeLabel?.let { "SAF: $it" } ?: state.outputDirectoryPath,
          style = MaterialTheme.typography.labelMedium,
          color = MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.height(4.dp))
        Text(
          text = strings.originalsPreservedNote,
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          OutlinedButton(onClick = { safTreeLauncher.launch(null) }) {
            Text(strings.pickOutputFolder)
          }
          OutlinedButton(onClick = { showOutputExplorer = true }) {
            Text(strings.browseSdcard)
          }
        }
      }

      Spacer(Modifier.height(16.dp))

      Button(
        onClick = { onStartResign(null) },
        enabled = state.targets.isNotEmpty() && state.selectedKeySource != null && !state.isRunning,
        modifier = Modifier.fillMaxWidth().height(52.dp).testTag("resign_start_button"),
      ) {
        Icon(Icons.Rounded.EditNote, contentDescription = null)
        Spacer(Modifier.width(8.dp))
        Text(strings.startResign)
      }

      if (state.isRunning) {
        Spacer(Modifier.height(12.dp))
        SectionCard {
          Text(
            text = strings.resigningProgress(state.currentIndex, state.targets.size, state.currentFileName),
            style = MaterialTheme.typography.bodyMedium,
          )
          Spacer(Modifier.height(8.dp))
          LinearProgressIndicator(
            progress = {
              if (state.targets.isEmpty()) 0f else state.currentIndex.toFloat() / state.targets.size.toFloat()
            },
            modifier = Modifier.fillMaxWidth(),
          )
        }
      }

      if (!state.errorMessage.isNullOrBlank()) {
        Spacer(Modifier.height(12.dp))
        Surface(
          color = MaterialTheme.colorScheme.errorContainer,
          shape = MaterialTheme.shapes.medium,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Text(
            text = state.errorMessage,
            color = MaterialTheme.colorScheme.onErrorContainer,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(14.dp),
          )
        }
      }

      state.results.forEach { res ->
        Spacer(Modifier.height(12.dp))
        SectionCard {
          Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
              imageVector = if (res.success) Icons.Rounded.CheckCircle else Icons.Rounded.Error,
              contentDescription = null,
              tint = if (res.success) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
            )
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = if (res.success) strings.resignSuccess else strings.resignFailed,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
              )
              Text(res.outputPath, style = MaterialTheme.typography.labelSmall)
            }
            StatusPillBadge(
              text = "${res.durationMs} ms",
              containerColor = MaterialTheme.colorScheme.surfaceVariant,
              contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          }
          Spacer(Modifier.height(8.dp))
          Text(
            text = "${strings.postVerifyLabel}: ${res.postVerifyReport?.overallStatus ?: res.errorMessage ?: "-"}",
            style = MaterialTheme.typography.bodySmall,
          )
          Text(
            text = "ZipAligned: ${res.zipAligned} • Schemes: ${res.appliedSchemes.joinToString(", ") { it.name }}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      }
      Spacer(Modifier.height(24.dp))
    }
  }

  if (showApkExplorer) {
    SdcardExplorerDialog(
      initialDir = defaultBrowseDir,
      hasStorageAccess = hasStorageAccess,
      pickFolderMode = false,
      allowedExtensions = setOf("apk"),
      onOpenSettings = onOpenSettings,
      onSelectFiles = { paths ->
        onAddPaths(paths)
        showApkExplorer = false
      },
      onDismiss = { showApkExplorer = false },
    )
  }

  if (showOutputExplorer) {
    SdcardExplorerDialog(
      initialDir = defaultBrowseDir,
      hasStorageAccess = hasStorageAccess,
      pickFolderMode = true,
      onOpenSettings = onOpenSettings,
      onSelectFolder = { folder ->
        onSetOutputPath(folder)
        showOutputExplorer = false
      },
      onDismiss = { showOutputExplorer = false },
    )
  }

  if (state.needsKeyPasswordFor != null) {
    PasswordPromptDialog(
      title = strings.unlockPromptTitle,
      label = strings.passwordRequiredLabel,
      onConfirm = { pw -> onStartResign(pw) },
      onDismiss = onDismissPassword,
    )
  }

  if (showCreateKeyDialog) {
    CreateAskDialog(
      onCreate = { opts ->
        onCreateInlineKey(opts)
        showCreateKeyDialog = false
      },
      onDismiss = { showCreateKeyDialog = false },
    )
  }
}
