package com.hephaistos.appsign.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoAwesome
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.android.ui.viewmodel.ResignUiState
import com.hephaistos.appsign.core.model.IdentityInput

private data class ProIdentityDraft(
  val alias: String,
  val cn: String,
  val org: String,
  val ou: String,
  val country: String,
  val passphrase: String,
)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ResignProPanel(
  state: ResignUiState,
  onAnalyzeTarget: () -> Unit,
  onRunResignPro: (List<IdentityInput>) -> Unit,
) {
  val strings = LocalAppsignStrings.current
  val profile = state.analyzedProProfile
  val signerCount = (profile?.signerProfiles?.size ?: 1).coerceAtLeast(1)

  val drafts =
    remember(signerCount) {
      mutableStateListOf<ProIdentityDraft>().apply {
        repeat(signerCount) { idx ->
          add(
            ProIdentityDraft(
              alias = if (signerCount > 1) "pro_signer_${idx + 1}" else "resignpro_key",
              cn = if (signerCount > 1) "Signer ${idx + 1}" else "",
              org = "APPSIGN",
              ou = "Security",
              country = "FR",
              passphrase = "",
            )
          )
        }
      }
    }

  SectionCard {
    Row(verticalAlignment = Alignment.CenterVertically) {
      Icon(Icons.Rounded.AutoAwesome, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
      Spacer(Modifier.width(8.dp))
      Text("RESIGNPRO", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
      Spacer(Modifier.weight(1f))
      StatusPillBadge(
        text = "ASK-OPEN",
        containerColor = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
      )
    }
    Spacer(Modifier.height(6.dp))
    Text(
      text = strings.resignProDesc,
      style = MaterialTheme.typography.bodySmall,
      color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(10.dp))
    OutlinedButton(
      onClick = onAnalyzeTarget,
      enabled = state.targets.isNotEmpty() && !state.isAnalyzingPro,
      modifier = Modifier.testTag("resignpro_analyze_button"),
    ) {
      if (state.isAnalyzingPro) {
        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
        Spacer(Modifier.width(8.dp))
      } else {
        Icon(Icons.Rounded.Security, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
      }
      Text(strings.resignProAnalyzeBtn)
    }
  }

  if (profile != null) {
    Spacer(Modifier.height(12.dp))
    SectionCard {
      Text(strings.resignProProfileTitle, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
      Spacer(Modifier.height(8.dp))
      FlowRow(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
      ) {
        profile.detectedSchemes.forEach { scheme ->
          StatusPillBadge(
            text = scheme.name,
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
          )
        }
        StatusPillBadge(
          text = "zipalign=${profile.wasZipAligned}",
          containerColor = MaterialTheme.colorScheme.surfaceVariant,
          contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        profile.minSdkVersion?.let { sdk ->
          StatusPillBadge(
            text = "minSdk=$sdk",
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        if (profile.hasMultipleSigners) {
          StatusPillBadge(
            text = "${profile.signerProfiles.size} Signers",
            containerColor = MaterialTheme.colorScheme.tertiaryContainer,
            contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
          )
        }
      }

      profile.signerProfiles.forEach { sp ->
        Spacer(Modifier.height(10.dp))
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(Modifier.height(8.dp))
        Text(
          text = "#${sp.signerIndex + 1} • ${sp.keySpec.keyAlgorithm} ${sp.keySpec.keySizeBits}-bit (${sp.keySpec.sigAlgName})",
          style = MaterialTheme.typography.labelLarge,
          color = MaterialTheme.colorScheme.primary,
        )
        if (!sp.keySpec.ecCurveName.isNullOrBlank()) {
          Text(
            text = "Curve: ${sp.keySpec.ecCurveName} • Validity: ${sp.validityDays} days",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        } else {
          Text(
            text = "Validity: ${sp.validityDays} days",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        Text(
          text = "DN: ${sp.detectedSubjectDn}",
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
          text = "SHA-256: ${sp.detectedSha256}",
          style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
      }
    }
  }

  Spacer(Modifier.height(12.dp))

  // Identity-only input form
  SectionCard {
    Text(strings.resignProIdentityTitle, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))
    drafts.forEachIndexed { idx, draft ->
      if (signerCount > 1) {
        Text(
          text = "Signer #${idx + 1}",
          style = MaterialTheme.typography.titleSmall,
          color = MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.height(4.dp))
      }
      OutlinedTextField(
        value = draft.alias,
        onValueChange = { drafts[idx] = draft.copy(alias = it) },
        label = { Text(strings.aliasLabel) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().testTag("resignpro_alias_input_$idx"),
      )
      Spacer(Modifier.height(6.dp))
      OutlinedTextField(
        value = draft.cn,
        onValueChange = { drafts[idx] = draft.copy(cn = it) },
        label = { Text(strings.cnLabel) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().testTag("resignpro_cn_input_$idx"),
      )
      Spacer(Modifier.height(6.dp))
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
          value = draft.org,
          onValueChange = { drafts[idx] = draft.copy(org = it) },
          label = { Text(strings.orgLabel) },
          singleLine = true,
          modifier = Modifier.weight(1f),
        )
        OutlinedTextField(
          value = draft.country,
          onValueChange = { drafts[idx] = draft.copy(country = it.take(2)) },
          label = { Text(strings.countryLabel) },
          singleLine = true,
          modifier = Modifier.width(100.dp),
        )
      }
      Spacer(Modifier.height(6.dp))
      OutlinedTextField(
        value = draft.ou,
        onValueChange = { drafts[idx] = draft.copy(ou = it) },
        label = { Text(strings.ouLabel) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
      )
      Spacer(Modifier.height(6.dp))
      OutlinedTextField(
        value = draft.passphrase,
        onValueChange = { drafts[idx] = draft.copy(passphrase = it) },
        label = { Text(strings.passwordOptionalLabel) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth(),
      )
      if (idx < drafts.lastIndex) {
        Spacer(Modifier.height(10.dp))
        HorizontalDivider()
        Spacer(Modifier.height(10.dp))
      }
    }
  }

  Spacer(Modifier.height(14.dp))

  val allCnReady = drafts.all { it.cn.isNotBlank() }
  Button(
    onClick = {
      val inputs =
        drafts.map { d ->
          IdentityInput(
            alias = d.alias.trim().ifBlank { "resignpro_key" },
            commonName = d.cn.trim(),
            organization = d.org.trim(),
            organizationalUnit = d.ou.trim(),
            country = d.country.trim().ifBlank { "FR" },
            passphrase = d.passphrase.takeIf { it.isNotEmpty() }?.toCharArray(),
          )
        }
      onRunResignPro(inputs)
    },
    enabled = state.targets.isNotEmpty() && allCnReady && !state.isRunning,
    modifier = Modifier.fillMaxWidth().height(52.dp).testTag("resignpro_run_button"),
  ) {
    Icon(Icons.Rounded.Key, contentDescription = null)
    Spacer(Modifier.width(8.dp))
    Text(strings.resignProRunBtn)
  }

  state.proResult?.let { pro ->
    Spacer(Modifier.height(12.dp))
    Surface(
      color = MaterialTheme.colorScheme.secondaryContainer,
      shape = MaterialTheme.shapes.medium,
      modifier = Modifier.fillMaxWidth(),
    ) {
      Column(modifier = Modifier.padding(14.dp)) {
        Text(
          text = strings.resignProSavedAskTitle,
          style = MaterialTheme.typography.titleSmall,
          fontWeight = FontWeight.Bold,
          color = MaterialTheme.colorScheme.onSecondaryContainer,
        )
        Spacer(Modifier.height(6.dp))
        pro.generatedAskContainers.forEachIndexed { idx, ask ->
          val p = pro.generatedAskPaths.getOrNull(idx).orEmpty()
          Text(
            text = "${ask.metadata.alias} • ${ask.mode} • ${ask.metadata.algorithm} ${ask.metadata.keySizeBits}-bit",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
          )
          Text(
            text = p,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
          )
        }
      }
    }
  }
}
