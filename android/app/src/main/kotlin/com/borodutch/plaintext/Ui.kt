package com.borodutch.plaintext

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/** A screen with a back (or close) button and a title. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Screen(
    title: String,
    onBack: (() -> Unit)?,
    close: Boolean = false,
    actions: @Composable () -> Unit = {},
    bottom: @Composable () -> Unit = {},
    content: @Composable (Modifier) -> Unit,
) {
    Scaffold(
        containerColor = P.bg,
        topBar = {
            TopAppBar(
                title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = {
                    if (onBack != null) IconButton(onClick = onBack) {
                        Icon(if (close) Icons.Rounded.Close else Icons.AutoMirrored.Rounded.ArrowBack, if (close) "Close" else "Back")
                    }
                },
                actions = { actions() },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = P.bg, titleContentColor = P.fg),
            )
        },
        bottomBar = bottom,
    ) { pad -> content(Modifier.padding(pad).fillMaxSize()) }
}

/** An onboarding step: big title, explanation, fields, and the actions pinned at the bottom. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StepPage(
    title: String,
    subtitle: String? = null,
    onBack: (() -> Unit)?,
    actions: @Composable ColumnScope.() -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        containerColor = P.bg,
        topBar = {
            CenterAlignedTopAppBar(
                title = {},
                navigationIcon = { if (onBack != null) IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(containerColor = P.bg),
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().imePadding(), horizontalAlignment = Alignment.CenterHorizontally) {
            Column(
                Modifier.weight(1f).widthIn(max = 560.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp),
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                Text(title, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = P.fg)
                if (subtitle != null) Text(subtitle, color = P.muted, style = MaterialTheme.typography.bodyLarge)
                content()
            }
            Column(
                Modifier.widthIn(max = 560.dp).fillMaxWidth().navigationBarsPadding().padding(horizontal = 24.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) { actions() }
        }
    }
}

enum class Input { Text, Username, Url, Password, Secret, Number }

/**
 * A labeled text field. [Input.Password] and [Input.Secret] hide what's typed (with an eye to show it) and tell the
 * keyboard not to learn or suggest it; [Input.Secret] is monospace (Secret Keys, codes).
 */
@Composable
fun Field(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    kind: Input = Input.Text,
    placeholder: String? = null,
    note: String? = null,
    mono: Boolean = false,
    singleLine: Boolean = true,
    revealed: Boolean? = null,
    onDone: (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
) {
    val secret = kind == Input.Password || kind == Input.Secret
    var show by remember { mutableStateOf(false) }
    val visible = revealed ?: show
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            label = { Text(label) },
            placeholder = placeholder?.let { { Text(it, color = P.muted) } },
            singleLine = singleLine,
            textStyle = if (mono || kind == Input.Secret || (secret && visible)) TextStyle(fontFamily = Mono) else TextStyle.Default,
            visualTransformation = if (secret && !visible) PasswordVisualTransformation() else VisualTransformation.None,
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.None,
                autoCorrectEnabled = kind == Input.Text,
                keyboardType = when (kind) {
                    Input.Password, Input.Secret -> KeyboardType.Password
                    Input.Url -> KeyboardType.Uri
                    Input.Number -> KeyboardType.Number
                    Input.Username -> KeyboardType.Ascii
                    Input.Text -> KeyboardType.Text
                },
                imeAction = if (onDone != null) ImeAction.Done else ImeAction.Default,
            ),
            keyboardActions = KeyboardActions(onDone = { onDone?.invoke() }),
            trailingIcon = trailing ?: if (secret && revealed == null) {
                {
                    IconButton(onClick = { show = !show }) {
                        Icon(if (show) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility, if (show) "Hide" else "Show", tint = P.muted)
                    }
                }
            } else null,
            shape = RoundedCornerShape(8.dp),
            colors = OutlinedTextFieldDefaults.colors(
                unfocusedContainerColor = P.surface, focusedContainerColor = P.surface,
                unfocusedBorderColor = P.line, focusedBorderColor = P.accent,
                focusedLabelColor = P.accent, unfocusedLabelColor = P.muted,
            ),
            modifier = Modifier.fillMaxWidth(),
        )
        if (note != null) Text(note, color = P.muted, style = MaterialTheme.typography.bodySmall)
    }
}

/** `alex@vault.example.com` */
fun accountLabel(server: String, username: String) = "$username@${server.substringAfter("://")}"

fun dateText(ms: Long): String = java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT).format(java.util.Date(ms))
fun dayText(seconds: Long): String = java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(seconds * 1000))

@Composable
fun RowSpaced(content: @Composable () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) { content() }
}
