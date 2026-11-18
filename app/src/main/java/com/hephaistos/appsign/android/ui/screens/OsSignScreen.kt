package com.hephaistos.appsign.android.ui.screens

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
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.EditNote
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import com.hephaistos.appsign.android.ui.components.ExpandableAuditCard
import com.hephaistos.appsign.android.ui.components.RootFolderExplorerDialog
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.android.ui.viewmodel.OsSignUiState
import com.hephaistos.appsign.core.model.IdentityInput
import com.hephaistos.appsign.core.model.OsResignKeyStrategy
import com.hephaistos.appsign.core.model.OsSignInspectionReport
import com.hephaistos.appsign.core.model.OsSignResignReport

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun OsSignScreen(
  state: OsSignUiState,
  managedKeys: List<ManagedKeyEntity>,
  defaultBrowseDir: String,
  rootEnabled: Boolean,
  onSetDirectory: (String, Boolean) -> Unit,
  onVerify: () -> Unit,
  onOpenStrategyDialog: () -> Unit,
  onDismissStrategyDialog: () -> Unit,
  onExecuteResign: (
    strategy: OsResignKeyStrategy,
    identitiesPerGroup: Map<String, IdentityInput>,
    selectedKeysPerGroup: Map<String, ManagedKeyEntity>,
    passphrasesPerGroup: Map<String, CharArray>,
    newKeyPassphrase: CharArray?,
    createBackups: Boolean,
  ) -> Unit,
  onRestoreBackups: () -> Unit,
  onDeleteBackups: () -> Unit,
  onOpenSettings: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var showRootExplorer by remember { mutableStateOf(false) }

  Column(
    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Column(modifier = Modifier.fillMaxWidth().widthIn(max = 820.dp)) {
      Text(strings.osSignScreenTitle, style = MaterialTheme.typography.headlineMedium)
      Spacer(Modifier.height(12.dp))

      // Folder selector card (with root explorer trigger)
      SectionCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text(
            text = strings.osSelectFolderHint,
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.weight(1f),
          )
          StatusPillBadge(
            text = if (state.viaRoot || rootEnabled) "Root (su)" else "Standard",
            containerColor =
              if (state.viaRoot || rootEnabled) MaterialTheme.colorScheme.tertiaryContainer
              else MaterialTheme.colorScheme.surfaceVariant,
            contentColor =
              if (state.viaRoot || rootEnabled) MaterialTheme.colorScheme.onTertiaryContainer
              else MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(
          value = state.targetDirPath,
          onValueChange = { onSetDirectory(it, state.viaRoot) },
          placeholder = { Text("/data/local/gsi_unpacked") },
          singleLine = true,
          modifier = Modifier.fillMaxWidth().testTag("ossign_path_input"),
        )
        Spacer(Modifier.height(10.dp))
        OutlinedButton(
          onClick = { showRootExplorer = true },
          modifier = Modifier.fillMaxWidth().testTag("ossign_browse_folder_button"),
        ) {
          Icon(
            if (rootEnabled) Icons.Rounded.AdminPanelSettings else Icons.Rounded.FolderOpen,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
          )
          Spacer(Modifier.width(8.dp))
          Text(strings.osRootExplorerTitle)
        }

        Spacer(Modifier.height(12.dp))

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
          OutlinedButton(
            onClick = onVerify,
            enabled = state.targetDirPath.isNotBlank() && !state.isRunning,
            modifier = Modifier.weight(1f).height(50.dp).testTag("ossign_verify_button"),
          ) {
            Icon(Icons.Rounded.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(strings.osVerifyBtn, fontWeight = FontWeight.Bold)
          }
          Button(
            onClick = onOpenStrategyDialog,
            enabled = state.targetDirPath.isNotBlank() && !state.isRunning,
            modifier = Modifier.weight(1f).height(50.dp).testTag("ossign_resign_button"),
          ) {
            Icon(Icons.Rounded.EditNote, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(strings.osResignBtn, fontWeight = FontWeight.Bold)
          }
        }
      }

      if (state.isRunning) {
        Spacer(Modifier.height(12.dp))
        SectionCard {
          Text(
            text = "${state.progressCurrent}${if (state.progressTotal > 0) "/${state.progressTotal}" else ""} • ${state.progressLabel}",
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
          Spacer(Modifier.height(8.dp))
          if (state.progressTotal > 0) {
            LinearProgressIndicator(
              progress = { state.progressCurrent.toFloat() / state.progressTotal.toFloat() },
              modifier = Modifier.fillMaxWidth(),
            )
          } else {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
          }
        }
      }

      if (!state.statusMessage.isNullOrBlank()) {
        Spacer(Modifier.height(12.dp))
        Surface(
          color = MaterialTheme.colorScheme.secondaryContainer,
          shape = MaterialTheme.shapes.medium,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Text(
            text = state.statusMessage,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(14.dp),
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

      // Post-Resign Backup Actions: Restore & Delete .bak
      state.activeBackupManifest?.let { manifest ->
        Spacer(Modifier.height(12.dp))
        SectionCard {
          Text(
            text = "${manifest.entries.size} .appsign.bak (${manifest.rootDirectory})",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
          Spacer(Modifier.height(10.dp))
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
          ) {
            OutlinedButton(
              onClick = onRestoreBackups,
              enabled = !state.isRunning,
              modifier = Modifier.weight(1f).height(48.dp).testTag("ossign_restore_bak_button"),
            ) {
              Icon(Icons.Rounded.Restore, contentDescription = null, modifier = Modifier.size(18.dp))
              Spacer(Modifier.width(6.dp))
              Text(strings.osRestoreBakBtn, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Button(
              onClick = onDeleteBackups,
              enabled = !state.isRunning,
              colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
              modifier = Modifier.weight(1f).height(48.dp).testTag("ossign_delete_bak_button"),
            ) {
              Icon(Icons.Rounded.DeleteForever, contentDescription = null, modifier = Modifier.size(18.dp))
              Spacer(Modifier.width(6.dp))
              Text(strings.osDeleteBakBtn, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
          }
        }
      }

      state.resignReport?.let { resign ->
        Spacer(Modifier.height(14.dp))
        OsResignSummaryCard(report = resign)
      }

      state.inspectionReport?.let { report ->
        Spacer(Modifier.height(14.dp))
        OsInspectionDashboard(report = report)
      }

      Spacer(Modifier.height(24.dp))
    }
  }

  if (showRootExplorer) {
    RootFolderExplorerDialog(
      initialDir = state.targetDirPath.ifBlank { defaultBrowseDir },
      rootEnabled = rootEnabled,
      onOpenSettings = onOpenSettings,
      onSelectFolder = { selectedPath, usedRoot ->
        onSetDirectory(selectedPath, usedRoot)
        showRootExplorer = false
      },
      onDismiss = { showRootExplorer = false },
    )
  }

  if (state.showStrategyDialog) {
    OsSignStrategyDialog(
      inspection = state.inspectionReport,
      managedKeys = managedKeys,
      initialCreateBackups = state.createBackups,
      onConfirm = onExecuteResign,
      onDismiss = onDismissStrategyDialog,
    )
  }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun OsInspectionDashboard(report: OsSignInspectionReport) {
  val strings = LocalAppsignStrings.current
  SectionCard {
    Text(strings.osTrustChainTitle, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))
    FlowRow(
      horizontalArrangement = Arrangement.spacedBy(8.dp),
      verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
      StatusPillBadge(
        text = "${report.groups.size} Key Groups",
        containerColor = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
      )
      StatusPillBadge(
        text = "${report.signedArtifactsCount} Signed",
        containerColor = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
      )
      StatusPillBadge(
        text = "${report.allPermissionReferences.size} Perm Refs",
        containerColor = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
      )
      StatusPillBadge(
        text = "${report.preservedUnsignedCount} Unsigned",
        containerColor = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
      )
      StatusPillBadge(
        text = "${report.symlinksIgnoredCount} Symlinks Ignored",
        containerColor = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
    Spacer(Modifier.height(8.dp))
    report.trustChainSummary.forEach { line ->
      Text("• $line", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    if (report.warnings.isNotEmpty()) {
      Spacer(Modifier.height(8.dp))
      report.warnings.forEach { w ->
        Row(verticalAlignment = Alignment.CenterVertically) {
          Icon(Icons.Rounded.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary, modifier = Modifier.size(16.dp))
          Spacer(Modifier.width(6.dp))
          Text(w, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
        }
      }
    }
  }

  Spacer(Modifier.height(12.dp))
  Text(strings.osGroupsDashboardTitle, style = MaterialTheme.typography.titleMedium)
  Spacer(Modifier.height(8.dp))

  report.groups.forEach { grp ->
    ExpandableAuditCard(
      title = grp.label,
      subtitle = "${grp.keySpec.keyAlgorithm} ${grp.keySpec.keySizeBits}-bit • ${grp.artifacts.size} artifact(s) • ${grp.permissionReferences.size} ref(s)",
      initiallyExpanded = false,
      trailingBadge = {
        StatusPillBadge(
          text = grp.recommendedSchemes.joinToString(",") { it.name },
          containerColor = MaterialTheme.colorScheme.primaryContainer,
          contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        )
      },
    ) {
      Text("Subject: ${grp.certificate.subjectDn}", style = MaterialTheme.typography.bodySmall)
      Text("SHA-256: ${grp.sha256}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
      Spacer(Modifier.height(6.dp))
      HorizontalDivider()
      Spacer(Modifier.height(6.dp))
      grp.artifacts.forEach { art ->
        Text(
          text = "• [${art.kind.name}] ${art.relativePath} (${art.status})",
          style = MaterialTheme.typography.labelSmall,
        )
      }
      if (grp.permissionReferences.isNotEmpty()) {
        Spacer(Modifier.height(6.dp))
        Text(strings.osPermRefsTitle, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        grp.permissionReferences.forEach { ref ->
          Text(
            text = "• ${ref.relativePath} [${ref.format.name} x${ref.occurrences}]",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      }
    }
    Spacer(Modifier.height(8.dp))
  }

  if (report.preservedArtifacts.isNotEmpty()) {
    ExpandableAuditCard(
      title = "${strings.osPreservedTitle} (${report.preservedArtifacts.size})",
      subtitle = "Untouched by RESIGNER",
    ) {
      report.preservedArtifacts.forEach { art ->
        Text("• ${art.relativePath} — ${art.reason}", style = MaterialTheme.typography.labelSmall)
      }
    }
  }
}

@Composable
private fun OsResignSummaryCard(report: OsSignResignReport) {
  SectionCard {
    Row(verticalAlignment = Alignment.CenterVertically) {
      Icon(Icons.Rounded.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
      Spacer(Modifier.width(8.dp))
      Text(
        text = "OS Sign (${report.strategy.name}): ${report.totalSucceeded}/${report.totalResigned}",
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
      )
    }
    Spacer(Modifier.height(6.dp))
    Text(
      text = "Refs updated: ${report.totalReferencesUpdated} • Preserved: ${report.totalPreserved} • Symlinks ignored: ${report.symlinksIgnoredCount} • ${report.durationMs} ms",
      style = MaterialTheme.typography.bodySmall,
      color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (report.generatedAskKeys.isNotEmpty()) {
      Spacer(Modifier.height(6.dp))
      report.generatedAskKeys.forEach { ask ->
        Text(
          text = "• .ask: ${ask.metadata.alias} (${ask.mode} • ${ask.metadata.algorithm} ${ask.metadata.keySizeBits}b)",
          style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.primary,
        )
      }
    }
  }
}
