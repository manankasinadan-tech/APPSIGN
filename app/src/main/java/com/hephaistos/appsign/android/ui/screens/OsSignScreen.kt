package com.hephaistos.appsign.android.ui.screens

import android.widget.Toast
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
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.data.local.ManagedKeyEntity
import com.hephaistos.appsign.android.ui.components.ExpandableAuditCard
import com.hephaistos.appsign.android.ui.components.FingerprintRow
import com.hephaistos.appsign.android.ui.components.RootFolderExplorerDialog
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.android.ui.viewmodel.OsSignUiState
import com.hephaistos.appsign.core.model.IdentityInput
import com.hephaistos.appsign.core.model.OsArtifactKind
import com.hephaistos.appsign.core.model.OsResignKeyStrategy
import com.hephaistos.appsign.core.model.OsSignInspectionReport
import com.hephaistos.appsign.core.model.OsSignResignReport
import com.hephaistos.appsign.core.model.SignatureSchemeVersion

private enum class OsGroupFilter {
  ALL,
  WITH_REFS,
  MULTI_SCHEME,
  APEX_OR_JAR,
}

private fun isProtectedSystemPath(path: String): Boolean {
  val trimmed = path.trim()
  return trimmed.startsWith("/data/") ||
    trimmed == "/data" ||
    trimmed.startsWith("/system") ||
    trimmed.startsWith("/vendor") ||
    trimmed.startsWith("/product") ||
    trimmed.startsWith("/apex") ||
    trimmed.startsWith("/odm") ||
    trimmed.startsWith("/system_ext")
}

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
          onValueChange = { typed ->
            val autoRoot = state.viaRoot || (rootEnabled && isProtectedSystemPath(typed))
            onSetDirectory(typed, autoRoot)
          },
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
  val context = LocalContext.current
  var selectedFilter by remember(report.scannedAtIso) { mutableStateOf(OsGroupFilter.ALL) }

  val allSignedArtifacts = remember(report) { report.groups.flatMap { it.artifacts }.distinctBy { it.relativePath } }
  val apkCount = remember(allSignedArtifacts) { allSignedArtifacts.count { it.kind == OsArtifactKind.APK } }
  val apexCount = remember(allSignedArtifacts) { allSignedArtifacts.count { it.kind == OsArtifactKind.APEX } }
  val jarCount = remember(allSignedArtifacts) { allSignedArtifacts.count { it.kind == OsArtifactKind.JAR } }
  val verifiedCount = remember(allSignedArtifacts) { allSignedArtifacts.count { it.verified } }
  val multiSignerCount = remember(allSignedArtifacts) { allSignedArtifacts.count { it.allSignerSha256s.size > 1 } }
  val rotationCount = remember(allSignedArtifacts) { allSignedArtifacts.count { it.apkReport?.keyRotation?.hasRotation == true } }

  val schemeCounts = remember(allSignedArtifacts) {
    SignatureSchemeVersion.entries.mapNotNull { scheme ->
      val count = allSignedArtifacts.count { scheme in it.schemes }
      if (count > 0) scheme to count else null
    }
  }
  val roleCounts = remember(allSignedArtifacts) {
    allSignedArtifacts
      .groupingBy { it.inferredRole.ifBlank { "system" } }
      .eachCount()
      .entries
      .sortedByDescending { it.value }
  }
  val filteredGroups = remember(report.groups, selectedFilter) {
    when (selectedFilter) {
      OsGroupFilter.ALL -> report.groups
      OsGroupFilter.WITH_REFS -> report.groups.filter { it.permissionReferences.isNotEmpty() }
      OsGroupFilter.MULTI_SCHEME -> report.groups.filter { it.recommendedSchemes.size > 1 }
      OsGroupFilter.APEX_OR_JAR ->
        report.groups.filter { g -> g.artifacts.any { it.kind != OsArtifactKind.APK } }
    }
  }

  SectionCard(modifier = Modifier.testTag("ossign_inspection_dashboard")) {
    Text(strings.osTrustChainTitle, style = MaterialTheme.typography.titleMedium)
    Text(
      text = strings.osScanStatsFormat(report.durationMs, report.totalFilesVisited),
      style = MaterialTheme.typography.labelSmall,
      color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(10.dp))

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
        text = "$verifiedCount/${allSignedArtifacts.size} Valid",
        containerColor =
          if (verifiedCount == allSignedArtifacts.size) MaterialTheme.colorScheme.secondaryContainer
          else MaterialTheme.colorScheme.tertiaryContainer,
        contentColor =
          if (verifiedCount == allSignedArtifacts.size) MaterialTheme.colorScheme.onSecondaryContainer
          else MaterialTheme.colorScheme.onTertiaryContainer,
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

    Spacer(Modifier.height(10.dp))
    Text(
      text = "APK: $apkCount • APEX: $apexCount • JAR: $jarCount • Multi-signer: $multiSignerCount • Rotation: $rotationCount",
      style = MaterialTheme.typography.labelMedium,
      color = MaterialTheme.colorScheme.onSurface,
    )

    if (schemeCounts.isNotEmpty()) {
      Spacer(Modifier.height(10.dp))
      Text(
        text = strings.osSchemeBreakdownTitle,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.primary,
      )
      Spacer(Modifier.height(6.dp))
      FlowRow(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
      ) {
        schemeCounts.forEach { (scheme, count) ->
          StatusPillBadge(
            text = "${scheme.name}: $count",
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
          )
        }
      }
    }

    if (roleCounts.isNotEmpty()) {
      Spacer(Modifier.height(10.dp))
      Text(
        text = strings.osPartitionsTitle,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.primary,
      )
      Spacer(Modifier.height(6.dp))
      FlowRow(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
      ) {
        roleCounts.forEach { (role, count) ->
          StatusPillBadge(
            text = "$role ($count)",
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      }
    }

    Spacer(Modifier.height(10.dp))
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
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

  Spacer(Modifier.height(14.dp))
  Text("${strings.osGroupsDashboardTitle} (${filteredGroups.size}/${report.groups.size})", style = MaterialTheme.typography.titleMedium)
  Spacer(Modifier.height(8.dp))

  FlowRow(
    horizontalArrangement = Arrangement.spacedBy(8.dp),
    verticalArrangement = Arrangement.spacedBy(6.dp),
    modifier = Modifier.padding(bottom = 10.dp),
  ) {
    FilterChip(
      selected = selectedFilter == OsGroupFilter.ALL,
      onClick = { selectedFilter = OsGroupFilter.ALL },
      label = { Text(strings.osFilterAll) },
    )
    FilterChip(
      selected = selectedFilter == OsGroupFilter.WITH_REFS,
      onClick = { selectedFilter = OsGroupFilter.WITH_REFS },
      label = { Text(strings.osFilterWithRefs) },
    )
    FilterChip(
      selected = selectedFilter == OsGroupFilter.MULTI_SCHEME,
      onClick = { selectedFilter = OsGroupFilter.MULTI_SCHEME },
      label = { Text(strings.osFilterMultiScheme) },
    )
    FilterChip(
      selected = selectedFilter == OsGroupFilter.APEX_OR_JAR,
      onClick = { selectedFilter = OsGroupFilter.APEX_OR_JAR },
      label = { Text(strings.osFilterApexJar) },
    )
  }

  filteredGroups.forEachIndexed { idx, grp ->
    val flagBits = buildList {
      if (grp.hasMultipleSignersInMembers) add("Multi-signer")
      if (grp.hasKeyRotationInMembers) add("Rotation")
    }.joinToString(" • ")
    val subtitleText = buildString {
      append("${grp.keySpec.keyAlgorithm} ${grp.keySpec.keySizeBits}-bit • ${grp.artifacts.size} artifact(s) • ${grp.permissionReferences.size} ref(s)")
      if (flagBits.isNotBlank()) append(" • $flagBits")
    }
    ExpandableAuditCard(
      title = grp.label,
      subtitle = subtitleText,
      initiallyExpanded = idx == 0 && filteredGroups.size == 1,
      trailingBadge = {
        StatusPillBadge(
          text = grp.recommendedSchemes.joinToString("·") { it.name },
          containerColor = MaterialTheme.colorScheme.primaryContainer,
          contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        )
      },
    ) {
      Text("Subject: ${grp.certificate.subjectDn}", style = MaterialTheme.typography.bodySmall)
      Text("Issuer: ${grp.certificate.issuerDn}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
      Text("Validity: ${grp.validityDays}d (${grp.certificate.notBeforeIso.take(10)} → ${grp.certificate.notAfterIso.take(10)})", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
      Spacer(Modifier.height(6.dp))
      FingerprintRow(
        label = "SHA-256",
        value = grp.sha256,
        onCopied = { Toast.makeText(context, strings.copiedToClipboard, Toast.LENGTH_SHORT).show() },
      )
      FingerprintRow(
        label = "SHA-1",
        value = grp.certificate.fingerprints.sha1,
        onCopied = { Toast.makeText(context, strings.copiedToClipboard, Toast.LENGTH_SHORT).show() },
      )
      Spacer(Modifier.height(6.dp))
      HorizontalDivider()
      Spacer(Modifier.height(8.dp))
      grp.artifacts.take(150).forEach { art ->
        Row(
          modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Icon(
            imageVector = if (art.verified) Icons.Rounded.CheckCircle else Icons.Rounded.ErrorOutline,
            contentDescription = null,
            tint = if (art.verified) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.tertiary,
            modifier = Modifier.size(16.dp),
          )
          Spacer(Modifier.width(6.dp))
          Column(modifier = Modifier.weight(1f)) {
            Text(
              text = art.relativePath,
              style = MaterialTheme.typography.labelMedium,
              maxLines = 2,
              overflow = TextOverflow.Ellipsis,
            )
            val meta = buildString {
              append("${art.kind.name} • ${art.inferredRole}")
              if (art.schemes.isNotEmpty()) {
                append(" • [${art.schemes.joinToString(" · ") { it.name }}]")
              }
              if (art.allSignerSha256s.size > 1) {
                append(" • ${art.allSignerSha256s.size} signers")
              }
              if (art.apexHasEmbeddedPubKey) {
                append(" • apex_pubkey")
              }
            }
            Text(
              text = meta,
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          }
        }
      }
      if (grp.artifacts.size > 150) {
        Text(
          text = "... +${grp.artifacts.size - 150} more artifacts",
          style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.primary,
          modifier = Modifier.padding(top = 4.dp),
        )
      }
      if (grp.permissionReferences.isNotEmpty()) {
        Spacer(Modifier.height(8.dp))
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(Modifier.height(6.dp))
        Text(strings.osPermRefsTitle, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(4.dp))
        grp.permissionReferences.take(150).forEach { ref ->
          Text(
            text = "• ${ref.relativePath} [${ref.format.name} ×${ref.occurrences}]",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface,
          )
          if (ref.previewSnippet.isNotBlank()) {
            Text(
              text = "  ${ref.previewSnippet}",
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
        }
        if (grp.permissionReferences.size > 150) {
          Text(
            text = "... +${grp.permissionReferences.size - 150} more refs",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary,
          )
        }
      }
    }
    Spacer(Modifier.height(8.dp))
  }

  if (report.allPermissionReferences.isNotEmpty()) {
    ExpandableAuditCard(
      title = "${strings.osPermMapTitle} (${report.allPermissionReferences.size})",
      subtitle = report.allPermissionReferences.map { it.relativePath }.distinct().size.let { "$it file(s)" },
    ) {
      report.allPermissionReferences.take(150).forEach { ref ->
        Text(
          text = "• ${ref.relativePath} [${ref.format.name} ×${ref.occurrences}] → ${ref.matchedSignerSha256.take(14)}...",
          style = MaterialTheme.typography.labelSmall,
        )
        if (ref.previewSnippet.isNotBlank()) {
          Text(
            text = "  ${ref.previewSnippet}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        }
      }
      if (report.allPermissionReferences.size > 150) {
        Text(
          text = "... +${report.allPermissionReferences.size - 150} more refs",
          style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.primary,
          modifier = Modifier.padding(top = 4.dp),
        )
      }
    }
    Spacer(Modifier.height(8.dp))
  }

  if (report.preservedArtifacts.isNotEmpty()) {
    ExpandableAuditCard(
      title = "${strings.osPreservedTitle} (${report.preservedArtifacts.size})",
      subtitle = "Untouched by RESIGNER",
    ) {
      report.preservedArtifacts.take(150).forEach { art ->
        Text("• ${art.relativePath} — ${art.reason}", style = MaterialTheme.typography.labelSmall)
      }
      if (report.preservedArtifacts.size > 150) {
        Text(
          text = "... +${report.preservedArtifacts.size - 150} more preserved",
          style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.primary,
          modifier = Modifier.padding(top = 4.dp),
        )
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
