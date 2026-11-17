package com.hephaistos.appsign.android.ui.screens

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.Error
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.UploadFile
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.ui.components.ExpandableAuditCard
import com.hephaistos.appsign.android.ui.components.FingerprintRow
import com.hephaistos.appsign.android.ui.components.RootApkPickerDialog
import com.hephaistos.appsign.android.ui.components.SdcardExplorerDialog
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.android.ui.viewmodel.VerifyUiState
import com.hephaistos.appsign.core.model.ApkVerificationReport
import com.hephaistos.appsign.core.model.VerificationStatus
import com.hephaistos.appsign.core.report.ReportFormatters
import kotlinx.coroutines.launch

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun VerifyScreen(
  state: VerifyUiState,
  defaultBrowseDir: String,
  hasStorageAccess: Boolean,
  rootEnabled: Boolean,
  onAddUris: (List<android.net.Uri>) -> Unit,
  onAddPaths: (List<String>) -> Unit,
  onAddRootApk: (String) -> Unit,
  onRunVerification: () -> Unit,
  onClear: () -> Unit,
  onOpenSettings: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  val clipboard = LocalClipboardManager.current
  val snackbarHostState = remember { SnackbarHostState() }
  val scope = rememberCoroutineScope()

  var showExplorer by remember { mutableStateOf(false) }
  var showRootPicker by remember { mutableStateOf(false) }

  val safLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
      if (uris.isNotEmpty()) onAddUris(uris)
    }

  Scaffold(
    snackbarHost = { SnackbarHost(snackbarHostState) },
    containerColor = MaterialTheme.colorScheme.background,
  ) { innerPadding ->
    Column(
      modifier =
        Modifier.fillMaxSize()
          .padding(innerPadding)
          .verticalScroll(rememberScrollState())
          .padding(horizontal = 20.dp, vertical = 16.dp),
      horizontalAlignment = Alignment.CenterHorizontally,
    ) {
      Column(modifier = Modifier.fillMaxWidth().widthIn(max = 760.dp)) {
        Text(strings.verifyScreenTitle, style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(12.dp))

        // Picker Actions Card
        SectionCard {
          FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
          ) {
            OutlinedButton(
              onClick = { safLauncher.launch(arrayOf("application/vnd.android.package-archive", "*/*")) },
              modifier = Modifier.testTag("verify_saf_picker_button"),
            ) {
              Icon(Icons.Rounded.UploadFile, contentDescription = null, modifier = Modifier.size(18.dp))
              Spacer(Modifier.width(6.dp))
              Text(strings.pickSafApks)
            }
            OutlinedButton(
              onClick = { showExplorer = true },
              modifier = Modifier.testTag("verify_sdcard_picker_button"),
            ) {
              Icon(Icons.Rounded.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
              Spacer(Modifier.width(6.dp))
              Text(strings.browseSdcard)
            }
            if (rootEnabled) {
              OutlinedButton(
                onClick = { showRootPicker = true },
                modifier = Modifier.testTag("verify_root_picker_button"),
              ) {
                Icon(Icons.Rounded.AdminPanelSettings, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(strings.browseRootApps)
              }
            }
          }

          if (state.targets.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            Text(
              text = strings.selectedApksCount(state.targets.size),
              style = MaterialTheme.typography.titleSmall,
            )
            Spacer(Modifier.height(6.dp))
            FlowRow(
              horizontalArrangement = Arrangement.spacedBy(6.dp),
              verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
              state.targets.forEach { target ->
                AssistChip(
                  onClick = {},
                  label = { Text(target.displayName, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                )
              }
            }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
              Button(
                onClick = onRunVerification,
                enabled = !state.isRunning,
                modifier = Modifier.weight(1f).testTag("verify_run_button"),
              ) {
                Icon(Icons.Rounded.PlayArrow, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text(strings.runVerification)
              }
              TextButton(onClick = onClear, enabled = !state.isRunning) {
                Icon(Icons.Rounded.DeleteSweep, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text(strings.clearSelection)
              }
            }
          }
        }

        if (state.isRunning) {
          Spacer(Modifier.height(14.dp))
          SectionCard {
            Text(
              text = strings.verifyingProgress(state.currentIndex, state.targets.size, state.currentFileName),
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

        state.reports.forEach { report ->
          Spacer(Modifier.height(16.dp))
          VerificationReportView(
            report = report,
            onCopyText = {
              clipboard.setText(AnnotatedString(ReportFormatters.verificationToText(report, strings.isFrench)))
              scope.launch { snackbarHostState.showSnackbar(strings.copiedToClipboard) }
            },
            onCopyJson = {
              clipboard.setText(AnnotatedString(ReportFormatters.verificationToJson(listOf(report))))
              scope.launch { snackbarHostState.showSnackbar(strings.copiedToClipboard) }
            },
            onHashCopied = { label ->
              scope.launch { snackbarHostState.showSnackbar("${strings.copiedToClipboard}: $label") }
            },
          )
        }
        Spacer(Modifier.height(24.dp))
      }
    }
  }

  if (showExplorer) {
    SdcardExplorerDialog(
      initialDir = defaultBrowseDir,
      hasStorageAccess = hasStorageAccess,
      pickFolderMode = false,
      allowedExtensions = setOf("apk"),
      onOpenSettings = onOpenSettings,
      onSelectFiles = { paths ->
        onAddPaths(paths)
        showExplorer = false
      },
      onDismiss = { showExplorer = false },
    )
  }

  if (showRootPicker) {
    RootApkPickerDialog(
      onSelectPath = { path -> onAddRootApk(path) },
      onDismiss = { showRootPicker = false },
    )
  }
}

@Composable
private fun VerificationReportView(
  report: ApkVerificationReport,
  onCopyText: () -> Unit,
  onCopyJson: () -> Unit,
  onHashCopied: (String) -> Unit,
) {
  val strings = LocalAppsignStrings.current
  val (statusLabel, containerColor, contentColor, statusIcon) =
    when (report.overallStatus) {
      VerificationStatus.VALID ->
        Quad(
          strings.statusValid,
          MaterialTheme.colorScheme.secondaryContainer,
          MaterialTheme.colorScheme.onSecondaryContainer,
          Icons.Rounded.CheckCircle,
        )
      VerificationStatus.VALID_WITH_WARNINGS ->
        Quad(
          strings.statusValidWarnings,
          MaterialTheme.colorScheme.tertiaryContainer,
          MaterialTheme.colorScheme.onTertiaryContainer,
          Icons.Rounded.Warning,
        )
      VerificationStatus.INVALID ->
        Quad(
          strings.statusInvalid,
          MaterialTheme.colorScheme.errorContainer,
          MaterialTheme.colorScheme.onErrorContainer,
          Icons.Rounded.Error,
        )
      VerificationStatus.UNSIGNED ->
        Quad(
          strings.statusUnsigned,
          MaterialTheme.colorScheme.errorContainer,
          MaterialTheme.colorScheme.onErrorContainer,
          Icons.Rounded.Error,
        )
    }

  SectionCard {
    // Summary Banner
    Surface(
      color = containerColor,
      contentColor = contentColor,
      shape = MaterialTheme.shapes.medium,
      modifier = Modifier.fillMaxWidth(),
    ) {
      Row(
        modifier = Modifier.padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
      ) {
        Icon(statusIcon, contentDescription = statusLabel, modifier = Modifier.size(28.dp))
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
          Text(statusLabel, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
          Text(
            text = "${report.apkName} • ${report.apkSizeBytes / 1024} KB • ${report.durationMs} ms",
            style = MaterialTheme.typography.labelSmall,
          )
        }
      }
    }

    Spacer(Modifier.height(10.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
      OutlinedButton(onClick = onCopyText) { Text(strings.exportTextReport) }
      OutlinedButton(onClick = onCopyJson) { Text(strings.exportJsonReport) }
    }

    Spacer(Modifier.height(12.dp))

    // 1. Signature Schemes
    ExpandableAuditCard(
      title = strings.schemeSectionTitle,
      subtitle = report.schemeResults.filter { it.verified }.joinToString(", ") { it.scheme.name }.ifBlank { "-" },
      initiallyExpanded = true,
    ) {
      report.schemeResults.forEach { scheme ->
        Row(
          modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Text(scheme.scheme.label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
          StatusPillBadge(
            text =
              when {
                scheme.verified -> "VERIFIED"
                scheme.present -> "FAILED"
                else -> "ABSENT"
              },
            containerColor =
              when {
                scheme.verified -> MaterialTheme.colorScheme.secondaryContainer
                scheme.present -> MaterialTheme.colorScheme.errorContainer
                else -> MaterialTheme.colorScheme.surfaceVariant
              },
            contentColor =
              when {
                scheme.verified -> MaterialTheme.colorScheme.onSecondaryContainer
                scheme.present -> MaterialTheme.colorScheme.onErrorContainer
                else -> MaterialTheme.colorScheme.onSurfaceVariant
              },
          )
        }
      }
    }

    Spacer(Modifier.height(10.dp))

    // 2. Signer Certificates & Public Keys
    ExpandableAuditCard(
      title = strings.signersSectionTitle,
      subtitle = "${report.allUniqueSigners.size} signer(s)",
      initiallyExpanded = true,
    ) {
      if (report.allUniqueSigners.isEmpty()) {
        Text("-", style = MaterialTheme.typography.bodySmall)
      } else {
        report.allUniqueSigners.forEachIndexed { idx, cert ->
          if (idx > 0) Spacer(Modifier.height(10.dp))
          Text(
            text = "Signer #${idx + 1}",
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
          )
          Text("Subject: ${cert.subjectDn}", style = MaterialTheme.typography.labelMedium)
          Text("Issuer: ${cert.issuerDn}", style = MaterialTheme.typography.labelSmall)
          Text("Serial: ${cert.serialNumberHex}", style = MaterialTheme.typography.labelSmall)
          Text("Algorithm: ${cert.sigAlgName} (${cert.publicKeyAlgorithm} ${cert.publicKeyBits}-bit)", style = MaterialTheme.typography.labelSmall)
          Text("Valid: ${cert.notBeforeIso} -> ${cert.notAfterIso}", style = MaterialTheme.typography.labelSmall)
          FingerprintRow("Public Key SHA-256", cert.publicKeySha256, onHashCopied)
        }
      }
    }

    Spacer(Modifier.height(10.dp))

    // 3. Fingerprints
    if (report.allUniqueSigners.isNotEmpty()) {
      ExpandableAuditCard(title = strings.fingerprintsSectionTitle, initiallyExpanded = false) {
        report.allUniqueSigners.forEachIndexed { idx, cert ->
          if (report.allUniqueSigners.size > 1) {
            Text("Signer #${idx + 1}", style = MaterialTheme.typography.titleSmall)
          }
          FingerprintRow("SHA-256", cert.fingerprints.sha256, onHashCopied)
          FingerprintRow("SHA-1", cert.fingerprints.sha1, onHashCopied)
          FingerprintRow("MD5", cert.fingerprints.md5, onHashCopied)
        }
      }
      Spacer(Modifier.height(10.dp))
    }

    // 4. Multi-signers & Key Rotation
    ExpandableAuditCard(
      title = strings.rotationSectionTitle,
      subtitle = if (report.keyRotation.hasRotation) strings.rotationDetected else strings.noRotationDetected,
      initiallyExpanded = report.hasMultipleSigners || report.keyRotation.hasRotation,
    ) {
      if (report.hasMultipleSigners) {
        Text(strings.multiSignerDetected, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.tertiary)
      }
      if (report.keyRotation.hasRotation) {
        report.keyRotation.summary.forEach { line ->
          Text(line, style = MaterialTheme.typography.labelMedium)
        }
      } else {
        Text(strings.noRotationDetected, style = MaterialTheme.typography.bodySmall)
      }
    }

    // 5. Errors & Warnings
    if (report.errors.isNotEmpty() || report.warnings.isNotEmpty()) {
      Spacer(Modifier.height(10.dp))
      ExpandableAuditCard(
        title = strings.errorsWarningsTitle,
        subtitle = "${report.errors.size} errors, ${report.warnings.size} warnings",
        initiallyExpanded = report.errors.isNotEmpty(),
      ) {
        report.errors.forEach { err ->
          Text("• $err", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        report.warnings.forEach { warn ->
          Text("• $warn", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
        }
      }
    }
  }
}

private data class Quad<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)
