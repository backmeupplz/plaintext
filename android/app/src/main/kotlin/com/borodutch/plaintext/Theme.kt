package com.borodutch.plaintext

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import uniffi.plaintext_ffi.passwordStrength

/** UI.md's tokens. */
@Immutable
data class Palette(
    val bg: Color,
    val surface: Color,
    val code: Color,
    val line: Color,
    val fg: Color,
    val muted: Color,
    val accent: Color,
    val accentFg: Color,
    val warn: Color,
    val danger: Color,
    val dark: Boolean,
)

private val Light = Palette(
    bg = Color(0xFFFBFBF8), surface = Color(0xFFF3F2EC), code = Color(0xFFEFEEE7), line = Color(0xFFE4E3DC),
    fg = Color(0xFF1B1B19), muted = Color(0xFF66665F), accent = Color(0xFF1F7A4D), accentFg = Color(0xFFFFFFFF),
    warn = Color(0xFFB4561C), danger = Color(0xFFB42318), dark = false,
)
private val Dark = Palette(
    bg = Color(0xFF111110), surface = Color(0xFF191917), code = Color(0xFF1D1D1B), line = Color(0xFF282825),
    fg = Color(0xFFECEBE5), muted = Color(0xFF9A9991), accent = Color(0xFF4CC38A), accentFg = Color(0xFF0D1F16),
    warn = Color(0xFFF0A060), danger = Color(0xFFF97066), dark = true,
)

val LocalPalette = staticCompositionLocalOf { Light }
val P: Palette @Composable get() = LocalPalette.current
val Mono = FontFamily.Monospace

@Composable
fun PlaintextTheme(content: @Composable () -> Unit) {
    val p = if (isSystemInDarkTheme()) Dark else Light
    val scheme = (if (p.dark) darkColorScheme() else lightColorScheme()).copy(
        primary = p.accent, onPrimary = p.accentFg, primaryContainer = p.surface, onPrimaryContainer = p.fg,
        secondary = p.accent, onSecondary = p.accentFg, secondaryContainer = p.code, onSecondaryContainer = p.fg,
        background = p.bg, onBackground = p.fg, surface = p.bg, onSurface = p.fg,
        surfaceVariant = p.surface, onSurfaceVariant = p.muted, surfaceContainer = p.surface,
        surfaceContainerLow = p.surface, surfaceContainerHigh = p.surface, surfaceContainerHighest = p.code,
        surfaceContainerLowest = p.bg, outline = p.line, outlineVariant = p.line, error = p.danger,
        inverseSurface = p.fg, inverseOnSurface = p.bg, inversePrimary = p.accent,
    )
    CompositionLocalProvider(LocalPalette provides p) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

/** `plain` + `text`, monospace and bold. */
@Composable
fun Wordmark(size: TextUnit = 28.sp) {
    val p = P
    Text(
        buildAnnotatedString {
            withStyle(SpanStyle(color = p.fg)) { append("plain") }
            withStyle(SpanStyle(color = p.accent)) { append("text") }
        },
        fontFamily = Mono, fontWeight = FontWeight.Bold, fontSize = size,
        modifier = Modifier.clearAndSetSemantics { contentDescription = "Plaintext" },
    )
}

/** The first letter of a title on a tint derived from it: never a fetched favicon. */
@Composable
fun Monogram(title: String, size: Int = 40) {
    val p = P
    val hue = ((title.lowercase().fold(7) { h, c -> h * 31 + c.code } and 0x7fffffff) % 360).toFloat()
    val tile = Color.hsv(hue, 0.32f, 0.78f).copy(alpha = if (p.dark) 0.22f else 0.35f)
    val ink = Color.hsv(hue, if (p.dark) 0.35f else 0.55f, if (p.dark) 0.9f else 0.42f)
    Box(
        Modifier.size(size.dp).clip(RoundedCornerShape((size / 4).dp)).background(tile).clearAndSetSemantics {},
        contentAlignment = Alignment.Center,
    ) {
        Text(title.trim().take(1).uppercase().ifEmpty { "?" }, color = ink, fontWeight = FontWeight.SemiBold, fontSize = (size * 0.45).sp)
    }
}

@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, busy: Boolean = false, icon: ImageVector? = null) {
    Button(
        onClick = onClick, enabled = enabled && !busy, shape = RoundedCornerShape(8.dp),
        modifier = modifier.fillMaxWidth().heightIn(min = 52.dp),
    ) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(20.dp), color = P.accentFg, strokeWidth = 2.dp)
        } else {
            if (icon != null) { Icon(icon, null, Modifier.size(20.dp)); Spacer(Modifier.width(8.dp)) }
            Text(text, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
fun SecondaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, icon: ImageVector? = null) {
    OutlinedButton(
        onClick = onClick, enabled = enabled, shape = RoundedCornerShape(8.dp), border = BorderStroke(1.dp, P.line),
        colors = ButtonDefaults.outlinedButtonColors(containerColor = P.surface, contentColor = P.fg),
        modifier = modifier.fillMaxWidth().heightIn(min = 52.dp),
    ) {
        if (icon != null) { Icon(icon, null, Modifier.size(20.dp), tint = P.accent); Spacer(Modifier.width(8.dp)) }
        Text(text, fontWeight = FontWeight.Medium)
    }
}

/** A short explanation or warning with an icon. */
@Composable
fun Note(text: String, color: Color = P.warn, icon: ImageVector = Icons.Rounded.Info) {
    Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Icon(icon, null, tint = color, modifier = Modifier.size(18.dp).padding(top = 2.dp))
        Text(text, color = color, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
fun ErrorNote(text: String?) {
    if (text != null) Note(text, P.danger)
}

/** Secrets and codes: monospace on the `code` tint. */
@Composable
fun CodeBlock(text: String, modifier: Modifier = Modifier, style: TextStyle = MaterialTheme.typography.titleMedium) {
    Text(
        text, fontFamily = Mono, style = style, color = P.fg,
        modifier = modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(P.code).padding(14.dp),
    )
}

/** Label (muted) above value. */
@Composable
fun LabeledValue(label: String, value: String, mono: Boolean = true) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(label, color = P.muted, style = MaterialTheme.typography.labelLarge)
        Text(value, color = P.fg, fontFamily = if (mono) Mono else null, style = MaterialTheme.typography.bodyLarge)
    }
}

/** Weak, fair, good, strong, from Rust's estimate. */
@Composable
fun StrengthMeter(password: String) {
    if (password.isEmpty()) return
    val s = passwordStrength(password)
    val level = s.level.toInt()
    val (label, color) = when (level) {
        0 -> "Weak" to P.danger
        1 -> "Fair" to P.warn
        2 -> "Good" to P.accent
        else -> "Strong" to P.accent
    }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        LinearProgressIndicator(
            progress = { (level + 1) / 4f }, color = color, trackColor = P.line,
            modifier = Modifier.weight(1f).heightIn(min = 6.dp).clip(RoundedCornerShape(3.dp)),
        )
        Text("$label · ${s.bits.toInt()} bits", color = P.muted, style = MaterialTheme.typography.labelMedium)
    }
}

/** A rounded card on `surface`. */
@Composable
fun Card(modifier: Modifier = Modifier, selected: Boolean = false, content: @Composable () -> Unit) {
    Box(
        modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(P.surface)
            .border(1.dp, if (selected) P.accent else P.line, RoundedCornerShape(12.dp)),
    ) { content() }
}

@Composable
fun EmptyState(icon: ImageVector, text: String, content: @Composable () -> Unit = {}) {
    Column(
        Modifier.fillMaxWidth().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(icon, null, tint = P.accent, modifier = Modifier.size(44.dp))
        Text(text, color = P.muted, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
        content()
    }
}

@Composable
fun SectionTitle(text: String) {
    Text(text, color = P.muted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(start = 16.dp, top = 20.dp, bottom = 8.dp, end = 16.dp))
}
