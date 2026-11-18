package com.hephaistos.appsign.android.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.data.local.ManagedKeyEntity
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.core.model.AskMode
import com.hephaistos.appsign.core.model.IdentityInput
import com.hephaistos.appsign.core.model.OsResignKeyStrategy
import com.hephaistos.appsign.core.model.OsSignInspectionReport

private data class GroupIdDraft(
  val alias: String,
  val cn: String,
  val org: String,
  val ou: String,
  val country: String,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OsSignStrategyDialog(
  inspection: OsSignInspectionReport?,
  managedKeys: List<ManagedKeyEntity>,
  initialCreateBackups: Boolean,
  onConfirm: (
    strategy: OsResignKeyStrategy,
    identitiesPerGroup: Map<String, IdentityInput>,
    selectedKeysPerGroup: Map<String, ManagedKeyEntity>,
    passphrasesPerGroup: Map<String, CharArray>,
    newKeyPassphrase: CharArray?,
    createBackups: Boolean,
  ) -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  val groups = inspection?.groups.orEmpty()
  var selectedStrategy by remember { mutableStateOf(OsResignKeyStrategy.CREATE_WITH_IDENTITIES) }
  var createBackups by remember { mutableStateOf(initialCreateBackups) }
  var newKeyPassphrase by remember { mutableStateOf("") }

  var defaultCn by remember { mutableStateOf("APPSIGN Custom OS") }
  var defaultOrg by remember { mutableStateOf("APPSIGN") }
  var defaultOu by remember { mutableStateOf("System") }
  var defaultCountry by remember { mutableStateOf("FR") }

  val perGroupDrafts = remember(groups) {
    mutableStateMapOf<String, GroupIdDraft>().apply {
      groups.forEachIndexed { idx, grp ->
        put(
          grp.groupId,
          GroupIdDraft(
            alias = "os_${grp.groupId}",
            cn = "Custom ${grp.label}",
            org = "APPSIGN",
            ou = "System",
            country = "FR",
          ),
        )
      }
    }
  }

  val selectedExistingMap = remember(groups, managedKeys) {
    mutableStateMapOf<String, ManagedKeyEntity>().apply {
      val firstKey = managedKeys.firstOrNull()
      if (firstKey != null) {
        groups.forEach { grp -> put(grp.groupId, firstKey) }
      }
    }
  }
  val existingPassMap = remember(groups) { mutableStateMapOf<String, String>() }

  val canConfirm =
    when (selectedStrategy) {
      OsResignKeyStrategy.CREATE_WITH_IDENTITIES ->
        if (groups.isEmpty()) defaultCn.isNotBlank()
        else groups.all { grp -> (perGroupDrafts[grp.groupId]?.cn ?: "").isNotBlank() }
      OsResignKeyStrategy.USE_EXISTING_KEYS ->
        groups.isNotEmpty() &&
          groups.all { grp ->
            val key = selectedExistingMap[grp.groupId]
            key != null && (key.mode != AskMode.ASK_LOCKED.name || !existingPassMap[grp.groupId].isNullOrEmpty())
          }
      OsResignKeyStrategy.CLONE_DETECTED_KEYS -> true
    }

  AlertDialog(
    onDismissRequest = onDismiss,
    icon = { Icon(Icons.Rounded.Key, contentDescription = null) },
    title = { Text(strings.osStrategyDialogTitle) },
    text = {
      Column(
        modifier = Modifier.fillMaxWidth().heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
      ) {
        StrategyRadioCard(
          selected = selectedStrategy == OsResignKeyStrategy.CREATE_WITH_IDENTITIES,
          title = strings.osStrategyIdentities,
          description = strings.osStrategyIdentitiesDesc,
          testTag = "os_strategy_identities",
          onClick = { selectedStrategy = OsResignKeyStrategy.CREATE_WITH_IDENTITIES },
        )
        Spacer(Modifier.height(6.dp))
        StrategyRadioCard(
          selected = selectedStrategy == OsResignKeyStrategy.USE_EXISTING_KEYS,
          title = strings.osStrategyExisting,
          description = strings.osStrategyExistingDesc,
          testTag = "os_strategy_existing",
          onClick = { selectedStrategy = OsResignKeyStrategy.USE_EXISTING_KEYS },
        )
        Spacer(Modifier.height(6.dp))
        StrategyRadioCard(
          selected = selectedStrategy == OsResignKeyStrategy.CLONE_DETECTED_KEYS,
          title = strings.osStrategyClone,
          description = strings.osStrategyCloneDesc,
          testTag = "os_strategy_clone",
          onClick = { selectedStrategy = OsResignKeyStrategy.CLONE_DETECTED_KEYS },
        )

        Spacer(Modifier.height(10.dp))
        HorizontalDivider()
        Spacer(Modifier.height(10.dp))

        when (selectedStrategy) {
          OsResignKeyStrategy.CREATE_WITH_IDENTITIES -> {
            if (groups.isEmpty()) {
              OutlinedTextField(
                value = defaultCn,
                onValueChange = { defaultCn = it },
                label = { Text(strings.cnLabel) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("os_default_cn_input"),
              )
              Spacer(Modifier.height(6.dp))
              Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                  value = defaultOrg,
                  onValueChange = { defaultOrg = it },
                  label = { Text(strings.orgLabel) },
                  singleLine = true,
                  modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                  value = defaultCountry,
                  onValueChange = { defaultCountry = it.take(2) },
                  label = { Text(strings.countryLabel) },
                  singleLine = true,
                  modifier = Modifier.width(92.dp),
                )
              }
            } else {
              groups.forEach { grp ->
                val draft = perGroupDrafts[grp.groupId] ?: GroupIdDraft("os_${grp.groupId}", grp.label, "APPSIGN", "System", "FR")
                Text(
                  text = "${grp.label} (${grp.keySpec.keyAlgorithm} ${grp.keySpec.keySizeBits}-bit)",
                  style = MaterialTheme.typography.labelMedium,
                  color = MaterialTheme.colorScheme.primary,
                  fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                  value = draft.cn,
                  onValueChange = { perGroupDrafts[grp.groupId] = draft.copy(cn = it) },
                  label = { Text(strings.cnLabel) },
                  singleLine = true,
                  modifier = Modifier.fillMaxWidth().testTag("os_group_cn_${grp.groupId}"),
                )
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                  OutlinedTextField(
                    value = draft.org,
                    onValueChange = { perGroupDrafts[grp.groupId] = draft.copy(org = it) },
                    label = { Text(strings.orgLabel) },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                  )
                  OutlinedTextField(
                    value = draft.country,
                    onValueChange = { perGroupDrafts[grp.groupId] = draft.copy(country = it.take(2)) },
                    label = { Text(strings.countryLabel) },
                    singleLine = true,
                    modifier = Modifier.width(88.dp),
                  )
                }
                Spacer(Modifier.height(8.dp))
              }
            }
            OutlinedTextField(
              value = newKeyPassphrase,
              onValueChange = { newKeyPassphrase = it },
              label = { Text(strings.passwordOptionalLabel) },
              singleLine = true,
              visualTransformation = PasswordVisualTransformation(),
              modifier = Modifier.fillMaxWidth(),
            )
          }
          OsResignKeyStrategy.USE_EXISTING_KEYS -> {
            if (managedKeys.isEmpty() || groups.isEmpty()) {
              Text(
                text = strings.osMissingKeyMapping,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
              )
            } else {
              groups.forEach { grp ->
                var menuExpanded by remember(grp.groupId) { mutableStateOf(false) }
                val chosen = selectedExistingMap[grp.groupId]
                Text(
                  text = "${grp.label} (${grp.artifacts.size} files)",
                  style = MaterialTheme.typography.labelMedium,
                  color = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.height(4.dp))
                ExposedDropdownMenuBox(
                  expanded = menuExpanded,
                  onExpandedChange = { menuExpanded = !menuExpanded },
                ) {
                  OutlinedTextField(
                    value = chosen?.let { "${it.alias} (${it.algorithm})" } ?: "-",
                    onValueChange = {},
                    readOnly = true,
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = menuExpanded) },
                    modifier = Modifier.menuAnchor(MenuAnchorType.PrimaryNotEditable, enabled = true).fillMaxWidth(),
                  )
                  ExposedDropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                    managedKeys.forEach { key ->
                      DropdownMenuItem(
                        text = { Text("${key.alias} • ${key.algorithm} ${key.keySizeBits}b (${key.mode})") },
                        onClick = {
                          selectedExistingMap[grp.groupId] = key
                          menuExpanded = false
                        },
                      )
                    }
                  }
                }
                if (chosen?.mode == AskMode.ASK_LOCKED.name) {
                  Spacer(Modifier.height(4.dp))
                  OutlinedTextField(
                    value = existingPassMap[grp.groupId].orEmpty(),
                    onValueChange = { existingPassMap[grp.groupId] = it },
                    label = { Text(strings.passwordRequiredLabel) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                  )
                }
                Spacer(Modifier.height(8.dp))
              }
            }
          }
          OsResignKeyStrategy.CLONE_DETECTED_KEYS -> {
            OutlinedTextField(
              value = newKeyPassphrase,
              onValueChange = { newKeyPassphrase = it },
              label = { Text(strings.passwordOptionalLabel) },
              singleLine = true,
              visualTransformation = PasswordVisualTransformation(),
              modifier = Modifier.fillMaxWidth(),
            )
          }
        }

        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text(strings.osBackupToggle, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
          Switch(checked = createBackups, onCheckedChange = { createBackups = it })
        }
      }
    },
    confirmButton = {
      Button(
        onClick = {
          val passChars = newKeyPassphrase.takeIf { it.isNotEmpty() }?.toCharArray()
          val idMap =
            if (groups.isEmpty()) {
              mapOf(
                "_default" to
                  IdentityInput(
                    alias = "os_key",
                    commonName = defaultCn.trim().ifBlank { "APPSIGN OS" },
                    organization = defaultOrg.trim(),
                    organizationalUnit = defaultOu.trim(),
                    country = defaultCountry.trim().ifBlank { "FR" },
                    passphrase = passChars,
                  )
              )
            } else {
              groups.associate { grp ->
                val d = perGroupDrafts[grp.groupId] ?: GroupIdDraft("os_${grp.groupId}", grp.label, "APPSIGN", "System", "FR")
                grp.groupId to
                  IdentityInput(
                    alias = d.alias,
                    commonName = d.cn.trim().ifBlank { "APPSIGN ${grp.label}" },
                    organization = d.org.trim(),
                    organizationalUnit = d.ou.trim(),
                    country = d.country.trim().ifBlank { "FR" },
                    passphrase = passChars,
                  )
              }
            }
          val passPerGroup =
            existingPassMap.mapValues { (_, v) -> v.toCharArray() }
          onConfirm(
            selectedStrategy,
            idMap,
            selectedExistingMap.toMap(),
            passPerGroup,
            passChars,
            createBackups,
          )
        },
        enabled = canConfirm,
        modifier = Modifier.testTag("os_strategy_confirm_button"),
      ) {
        Text(strings.osConfirmResign)
      }
    },
    dismissButton = { TextButton(onClick = onDismiss) { Text(strings.cancel) } },
  )
}

@Composable
private fun StrategyRadioCard(
  selected: Boolean,
  title: String,
  description: String,
  testTag: String,
  onClick: () -> Unit,
) {
  Surface(
    modifier = Modifier.fillMaxWidth().testTag(testTag).clickable(onClick = onClick),
    shape = MaterialTheme.shapes.medium,
    color =
      if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
      else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
    border = if (selected) BorderStroke(1.dp, MaterialTheme.colorScheme.primary) else null,
  ) {
    Row(modifier = Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
      RadioButton(selected = selected, onClick = onClick)
      Spacer(Modifier.width(6.dp))
      Column {
        Text(title, style = MaterialTheme.typography.titleSmall)
        Text(description, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
      }
    }
  }
}
