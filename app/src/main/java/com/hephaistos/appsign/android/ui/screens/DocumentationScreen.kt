package com.hephaistos.appsign.android.ui.screens

import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.ui.components.ExpandableAuditCard
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import kotlinx.coroutines.launch

@Composable
fun DocumentationScreen() {
  val strings = LocalAppsignStrings.current
  val clipboard = LocalClipboardManager.current
  val snackbarHostState = remember { SnackbarHostState() }
  val scope = rememberCoroutineScope()
  var query by remember { mutableStateOf("") }

  val filteredSections =
    remember(query, strings.docSections) {
      if (query.isBlank()) {
        strings.docSections
      } else {
        strings.docSections.filter {
          it.title.contains(query, ignoreCase = true) ||
            it.summary.contains(query, ignoreCase = true) ||
            it.body.contains(query, ignoreCase = true) ||
            (it.codeSnippet?.contains(query, ignoreCase = true) == true)
        }
      }
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
        Text(strings.docsTitle, style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
          value = query,
          onValueChange = { query = it },
          leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
          label = { Text(strings.docsSearchHint) },
          singleLine = true,
          modifier = Modifier.fillMaxWidth().testTag("docs_search_input"),
        )

        Spacer(Modifier.height(14.dp))

        filteredSections.forEachIndexed { idx, section ->
          ExpandableAuditCard(
            title = section.title,
            subtitle = section.summary,
            initiallyExpanded = idx == 0 || query.isNotBlank(),
          ) {
            Text(section.body, style = MaterialTheme.typography.bodyMedium)
            if (!section.codeSnippet.isNullOrBlank()) {
              Spacer(Modifier.height(10.dp))
              Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth(),
              ) {
                Row(
                  modifier = Modifier.padding(12.dp),
                  verticalAlignment = Alignment.Top,
                ) {
                  Text(
                    text = section.codeSnippet,
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.weight(1f),
                  )
                  Spacer(Modifier.width(8.dp))
                  IconButton(
                    onClick = {
                      clipboard.setText(AnnotatedString(section.codeSnippet))
                      scope.launch { snackbarHostState.showSnackbar(strings.copiedToClipboard) }
                    }
                  ) {
                    Icon(
                      Icons.Rounded.ContentCopy,
                      contentDescription = "Copy commands",
                      tint = MaterialTheme.colorScheme.primary,
                      modifier = Modifier.size(18.dp),
                    )
                  }
                }
              }
            }
          }
          Spacer(Modifier.height(10.dp))
        }
        Spacer(Modifier.height(24.dp))
      }
    }
  }
}
