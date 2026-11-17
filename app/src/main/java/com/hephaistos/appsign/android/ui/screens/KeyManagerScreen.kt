package com.hephaistos.appsign.android.ui.screens

import android.net.Uri
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
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.LockOpen
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.data.local.ManagedKeyEntity
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.android.ui.viewmodel.KeyManagerUiState
import com.hephaistos.appsign.core.model.AskInspectResult
import com.hephaistos.appsign.core.model.AskMode
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.KeyAlgorithm

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun KeyManagerScreen(
  keys: List<ManagedKeyEntity>,
  uiState: KeyManagerUiState,
  defaultOutputDir: String,
  onCreateKey: (CreateAskOptions) -> Unit,
  onImportKeystore: (Uri, String, CharArray?, String?, Uri?, CharArray?) -> Unit,
  onInspectKey: (ManagedKeyEntity) -> Unit,
  onCloseInspect: () -> Unit,
  onRequestExport: (ManagedKeyEntity) -> Unit,
  onCloseExport: () -> Unit,
  onPerformExport: (ManagedKeyEntity, String, CharArray?, CharArray?, Uri?, String) -> Unit,
  onDeleteKey: (ManagedKeyEntity) -> Unit,
  onClearNotices: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var showCreateDialog by remember { mutableStateOf(false) }
  var showImportDialog by remember { mutableStateOf(false) }

  Column(
    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Column(modifier = Modifier.fillMaxWidth().widthIn(max = 760.dp)) {
      Text(strings.keyManagerTitle, style = MaterialTheme.typography.headlineMedium)
      Spacer(Modifier.height(12.dp))

      Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Button(
          onClick = { showCreateDialog = true },
          modifier = Modifier.testTag("key_create_button"),
        ) {
          Icon(Icons.Rounded.Add, contentDescription = null)
          Spacer(Modifier.width(6.dp))
          Text(strings.createButton)
        }
        OutlinedButton(
          onClick = { showImportDialog = true },
          modifier = Modifier.testTag("key_import_button"),
        ) {
          Icon(Icons.Rounded.FileUpload, contentDescription = null)
          Spacer(Modifier.width(6.dp))
          Text(strings.importButton)
        }
      }

      if (!uiState.lastSecurityWarning.isNullOrBlank()) {
        Spacer(Modifier.height(12.dp))
        Surface(
          color = MaterialTheme.colorScheme.tertiaryContainer,
          shape = MaterialTheme.shapes.medium,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Rounded.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.onTertiaryContainer)
            Spacer(Modifier.width(8.dp))
            Text(
              text = strings.unencryptedExportWarning,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onTertiaryContainer,
              modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onClearNotices) { Text("OK") }
          }
        }
      }

      if (!uiState.errorMessage.isNullOrBlank()) {
        Spacer(Modifier.height(10.dp))
        Surface(color = MaterialTheme.colorScheme.errorContainer, shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth()) {
          Text(uiState.errorMessage, color = MaterialTheme.colorScheme.onErrorContainer, modifier = Modifier.padding(12.dp))
        }
      }

      if (!uiState.statusMessage.isNullOrBlank()) {
        Spacer(Modifier.height(10.dp))
        Surface(color = MaterialTheme.colorScheme.secondaryContainer, shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth()) {
          Text(uiState.statusMessage, color = MaterialTheme.colorScheme.onSecondaryContainer, modifier = Modifier.padding(12.dp))
        }
      }

      Spacer(Modifier.height(14.dp))

      if (keys.isEmpty()) {
        SectionCard {
          Text(strings.noKeysSaved, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      } else {
        keys.forEach { key ->
          Spacer(Modifier.height(10.dp))
          SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
              Icon(
                imageVector = if (key.mode == AskMode.ASK_LOCKED.name) Icons.Rounded.Lock else Icons.Rounded.LockOpen,
                contentDescription = key.mode,
                tint = if (key.mode == AskMode.ASK_LOCKED.name) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.tertiary,
              )
              Spacer(Modifier.width(10.dp))
              Column(modifier = Modifier.weight(1f)) {
                Text(key.alias, style = MaterialTheme.typography.titleMedium)
                Text(
                  "${key.algorithm} ${key.keySizeBits}-bit • ${key.subjectDn}",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
              StatusPillBadge(
                text = if (key.mode == AskMode.ASK_LOCKED.name) "ASK-LOCKED" else "ASK-OPEN",
                containerColor =
                  if (key.mode == AskMode.ASK_LOCKED.name) MaterialTheme.colorScheme.secondaryContainer
                  else MaterialTheme.colorScheme.tertiaryContainer,
                contentColor =
                  if (key.mode == AskMode.ASK_LOCKED.name) MaterialTheme.colorScheme.onSecondaryContainer
                  else MaterialTheme.colorScheme.onTertiaryContainer,
              )
            }
            Spacer(Modifier.height(8.dp))
            Text("SHA-256: ${key.sha256Fingerprint}", style = MaterialTheme.typography.labelSmall)
            Spacer(Modifier.height(10.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
              OutlinedButton(onClick = { onInspectKey(key) }) {
                Icon(Icons.Rounded.Info, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(strings.inspectButton)
              }
              OutlinedButton(onClick = { onRequestExport(key) }) {
                Icon(Icons.Rounded.FileDownload, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(strings.exportButton)
              }
              IconButton(onClick = { onDeleteKey(key) }) {
                Icon(Icons.Rounded.Delete, contentDescription = strings.deleteButton, tint = MaterialTheme.colorScheme.error)
              }
            }
          }
        }
      }
      Spacer(Modifier.height(24.dp))
    }
  }

  if (showCreateDialog) {
    CreateAskDialog(
      onCreate = {
        onCreateKey(it)
        showCreateDialog = false
      },
      onDismiss = { showCreateDialog = false },
    )
  }

  if (showImportDialog) {
    ImportKeyDialog(
      onImport = { uri, fmt, pw, alias, certUri, askPw ->
        onImportKeystore(uri, fmt, pw, alias, certUri, askPw)
        showImportDialog = false
      },
      onDismiss = { showImportDialog = false },
    )
  }

  uiState.inspectingResult?.let { info ->
    InspectAskDialog(info = info, onDismiss = onCloseInspect)
  }

  uiState.exportTargetEntity?.let { entity ->
    ExportKeyDialog(
      entity = entity,
      defaultDir = defaultOutputDir,
      onExport = { fmt, unlockPw, exportPw, treeUri, dir ->
        onPerformExport(entity, fmt, unlockPw, exportPw, treeUri, dir)
      },
      onDismiss = onCloseExport,
    )
  }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun CreateAskDialog(
  onCreate: (CreateAskOptions) -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var alias by remember { mutableStateOf("release-key") }
  var selectedAlg by remember { mutableStateOf(KeyAlgorithm.RSA_2048) }
  var cn by remember { mutableStateOf("APPSIGN Signer") }
  var org by remember { mutableStateOf("APPSIGN") }
  var ou by remember { mutableStateOf("Mobile") }
  var country by remember { mutableStateOf("FR") }
  var years by remember { mutableStateOf("25") }
  var passphrase by remember { mutableStateOf("") }
  var notes by remember { mutableStateOf("") }

  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text(strings.createAskTitle) },
    text = {
      Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
        OutlinedTextField(
          value = alias,
          onValueChange = { alias = it },
          label = { Text(strings.aliasLabel) },
          singleLine = true,
          modifier = Modifier.fillMaxWidth().testTag("create_ask_alias_input"),
        )
        Spacer(Modifier.height(8.dp))
        Text(strings.algorithmLabel, style = MaterialTheme.typography.labelMedium)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
          KeyAlgorithm.entries.forEach { alg ->
            FilterChip(
              selected = selectedAlg == alg,
              onClick = { selectedAlg = alg },
              label = { Text(alg.displayName) },
            )
          }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(value = cn, onValueChange = { cn = it }, label = { Text(strings.cnLabel) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(value = org, onValueChange = { org = it }, label = { Text(strings.orgLabel) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(6.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          OutlinedTextField(value = ou, onValueChange = { ou = it }, label = { Text(strings.ouLabel) }, singleLine = true, modifier = Modifier.weight(1f))
          OutlinedTextField(value = country, onValueChange = { country = it }, label = { Text(strings.countryLabel) }, singleLine = true, modifier = Modifier.width(90.dp))
        }
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(value = years, onValueChange = { years = it.filter(Char::isDigit) }, label = { Text(strings.yearsLabel) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(
          value = passphrase,
          onValueChange = { passphrase = it },
          label = { Text(strings.passwordOptionalLabel) },
          singleLine = true,
          visualTransformation = PasswordVisualTransformation(),
          modifier = Modifier.fillMaxWidth(),
        )
        if (passphrase.isEmpty()) {
          Spacer(Modifier.height(6.dp))
          Text(
            text = strings.unencryptedExportWarning,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.tertiary,
          )
        }
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(value = notes, onValueChange = { notes = it }, label = { Text(strings.notesLabel) }, modifier = Modifier.fillMaxWidth())
      }
    },
    confirmButton = {
      Button(
        onClick = {
          onCreate(
            CreateAskOptions(
              alias = alias.trim(),
              algorithm = selectedAlg,
              commonName = cn.trim(),
              organization = org.trim(),
              organizationalUnit = ou.trim(),
              country = country.trim(),
              validityYears = years.toIntOrNull()?.coerceIn(1, 100) ?: 25,
              passphrase = if (passphrase.isBlank()) null else passphrase.toCharArray(),
              notes = notes.trim(),
            )
          )
        },
        enabled = alias.isNotBlank(),
        modifier = Modifier.testTag("create_ask_submit_button"),
      ) {
        Text(strings.createButton)
      }
    },
    dismissButton = { TextButton(onClick = onDismiss) { Text(strings.cancel) } },
  )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ImportKeyDialog(
  onImport: (Uri, String, CharArray?, String?, Uri?, CharArray?) -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var format by remember { mutableStateOf("ask") }
  var primaryUri by remember { mutableStateOf<Uri?>(null) }
  var certUri by remember { mutableStateOf<Uri?>(null) }
  var storePass by remember { mutableStateOf("") }
  var alias by remember { mutableStateOf("") }
  var askPass by remember { mutableStateOf("") }

  val mainPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> primaryUri = uri }
  val certPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> certUri = uri }

  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text(strings.importKeyTitle) },
    text = {
      Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
        Text(strings.importFormatLabel, style = MaterialTheme.typography.labelMedium)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
          listOf("ask" to ".ask", "p12" to "PKCS#12", "jks" to "JKS", "pkcs8" to "PKCS#8+X.509").forEach { (id, label) ->
            FilterChip(selected = format == id, onClick = { format = id }, label = { Text(label) })
          }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { mainPicker.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
          Text(primaryUri?.lastPathSegment ?: "Select file (${format.uppercase()})")
        }
        if (format == "pkcs8") {
          Spacer(Modifier.height(6.dp))
          OutlinedButton(onClick = { certPicker.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
            Text(certUri?.lastPathSegment ?: "Select X.509 Certificate (.pem/.der)")
          }
        }
        if (format == "p12" || format == "jks") {
          Spacer(Modifier.height(6.dp))
          OutlinedTextField(
            value = storePass,
            onValueChange = { storePass = it },
            label = { Text(strings.passwordRequiredLabel) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
          )
        }
        if (format != "ask") {
          Spacer(Modifier.height(6.dp))
          OutlinedTextField(value = alias, onValueChange = { alias = it }, label = { Text("${strings.aliasLabel} (opt)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
          Spacer(Modifier.height(6.dp))
          OutlinedTextField(
            value = askPass,
            onValueChange = { askPass = it },
            label = { Text(strings.passwordOptionalLabel) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
          )
        }
      }
    },
    confirmButton = {
      Button(
        onClick = {
          primaryUri?.let {
            onImport(
              it,
              format,
              if (storePass.isEmpty()) null else storePass.toCharArray(),
              alias.ifBlank { null },
              certUri,
              if (askPass.isBlank()) null else askPass.toCharArray(),
            )
          }
        },
        enabled = primaryUri != null && (format != "pkcs8" || certUri != null),
      ) {
        Text(strings.importButton)
      }
    },
    dismissButton = { TextButton(onClick = onDismiss) { Text(strings.cancel) } },
  )
}

@Composable
private fun InspectAskDialog(info: AskInspectResult, onDismiss: () -> Unit) {
  val strings = LocalAppsignStrings.current
  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text("${strings.inspectKeyTitle}: ${info.metadata.alias}") },
    text = {
      Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
        Text("Key ID: ${info.keyId}", style = MaterialTheme.typography.labelSmall)
        Text("Format: ASK v${info.formatVersion} (${info.mode})", style = MaterialTheme.typography.labelMedium)
        Text("Algorithm: ${info.metadata.algorithm} (${info.metadata.keySizeBits} bits)", style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(6.dp))
        Text("Subject: ${info.certificate.subjectDn}", style = MaterialTheme.typography.labelSmall)
        Text("Issuer: ${info.certificate.issuerDn}", style = MaterialTheme.typography.labelSmall)
        Text("Serial: ${info.certificate.serialNumberHex}", style = MaterialTheme.typography.labelSmall)
        Text("Valid: ${info.certificate.notBeforeIso} -> ${info.certificate.notAfterIso}", style = MaterialTheme.typography.labelSmall)
        Spacer(Modifier.height(6.dp))
        Text("SHA-256: ${info.certificate.fingerprints.sha256}", style = MaterialTheme.typography.labelSmall)
        Text("SHA-1: ${info.certificate.fingerprints.sha1}", style = MaterialTheme.typography.labelSmall)
        Text("MD5: ${info.certificate.fingerprints.md5}", style = MaterialTheme.typography.labelSmall)
        if (info.securityWarning != null) {
          Spacer(Modifier.height(8.dp))
          Text(strings.unencryptedExportWarning, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
        }
      }
    },
    confirmButton = { Button(onClick = onDismiss) { Text(strings.close) } },
  )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ExportKeyDialog(
  entity: ManagedKeyEntity,
  defaultDir: String,
  onExport: (String, CharArray?, CharArray?, Uri?, String) -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var format by remember { mutableStateOf("p12") }
  var unlockPass by remember { mutableStateOf("") }
  var exportPass by remember { mutableStateOf("") }
  var safTree by remember { mutableStateOf<Uri?>(null) }

  val treePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri -> safTree = uri }
  val isUnencryptedFormat = format == "ask-open" || format == "pkcs8"
  val needsExportPassword = format == "p12" || format == "jks" || format == "ask-locked"
  val needsUnlockPassword = entity.mode == AskMode.ASK_LOCKED.name

  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text("${strings.exportKeyTitle}: ${entity.alias}") },
    text = {
      Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
        Text(strings.exportFormatLabel, style = MaterialTheme.typography.labelMedium)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
          listOf(
            "p12" to "PKCS#12 (.p12)",
            "jks" to "JKS (.jks)",
            "ask-locked" to "ASK-LOCKED",
            "ask-open" to "ASK-OPEN",
            "pkcs8" to "PKCS#8+PEM",
          ).forEach { (id, label) ->
            FilterChip(selected = format == id, onClick = { format = id }, label = { Text(label) })
          }
        }

        if (isUnencryptedFormat) {
          Spacer(Modifier.height(8.dp))
          Surface(color = MaterialTheme.colorScheme.tertiaryContainer, shape = MaterialTheme.shapes.small) {
            Text(
              text = strings.unencryptedExportWarning,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onTertiaryContainer,
              modifier = Modifier.padding(10.dp),
            )
          }
        }

        if (needsUnlockPassword) {
          Spacer(Modifier.height(8.dp))
          OutlinedTextField(
            value = unlockPass,
            onValueChange = { unlockPass = it },
            label = { Text("Current ASK Password") },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
          )
        }
        if (needsExportPassword) {
          Spacer(Modifier.height(8.dp))
          OutlinedTextField(
            value = exportPass,
            onValueChange = { exportPass = it },
            label = { Text("Export Password") },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
          )
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { treePicker.launch(null) }, modifier = Modifier.fillMaxWidth()) {
          Text(safTree?.lastPathSegment ?: "Destination: $defaultDir (or pick SAF folder)")
        }
      }
    },
    confirmButton = {
      Button(
        onClick = {
          onExport(
            format,
            if (unlockPass.isEmpty()) null else unlockPass.toCharArray(),
            if (exportPass.isEmpty()) null else exportPass.toCharArray(),
            safTree,
            defaultDir,
          )
        },
        enabled = (!needsUnlockPassword || unlockPass.isNotEmpty()) && (!needsExportPassword || exportPass.isNotEmpty()),
      ) {
        Text(strings.exportButton)
      }
    },
    dismissButton = { TextButton(onClick = onDismiss) { Text(strings.cancel) } },
  )
}
