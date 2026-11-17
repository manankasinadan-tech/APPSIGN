package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

enum class ThemePreference {
  SYSTEM,
  LIGHT,
  DARK,
}

private val AppsignDarkColorScheme =
  darkColorScheme(
    primary = CyanElectric,
    onPrimary = ObsidianBg,
    primaryContainer = CyanSoftContainerDark,
    onPrimaryContainer = CyanElectric,
    secondary = VerifiedEmerald,
    onSecondary = ObsidianBg,
    secondaryContainer = VerifiedEmeraldContainerDark,
    onSecondaryContainer = VerifiedEmerald,
    tertiary = WarningAmber,
    onTertiary = ObsidianBg,
    tertiaryContainer = WarningAmberContainerDark,
    onTertiaryContainer = WarningAmber,
    error = TamperCrimson,
    onError = ObsidianTextPrimary,
    errorContainer = TamperCrimsonContainerDark,
    onErrorContainer = TamperCrimson,
    background = ObsidianBg,
    onBackground = ObsidianTextPrimary,
    surface = ObsidianSurface,
    onSurface = ObsidianTextPrimary,
    surfaceVariant = ObsidianSurfaceHigh,
    onSurfaceVariant = ObsidianTextSecondary,
    outline = ObsidianBorder,
    outlineVariant = ObsidianBorder,
  )

private val AppsignLightColorScheme =
  lightColorScheme(
    primary = CyanDeep,
    onPrimary = AlabasterSurface,
    primaryContainer = CyanSoftContainerLight,
    onPrimaryContainer = CyanDeep,
    secondary = VerifiedEmerald,
    onSecondary = AlabasterSurface,
    secondaryContainer = VerifiedEmeraldContainerLight,
    onSecondaryContainer = Color(0xFF065F46),
    tertiary = WarningAmber,
    onTertiary = AlabasterTextPrimary,
    tertiaryContainer = WarningAmberContainerLight,
    onTertiaryContainer = Color(0xFF92400E),
    error = TamperCrimson,
    onError = AlabasterSurface,
    errorContainer = TamperCrimsonContainerLight,
    onErrorContainer = Color(0xFF991B1B),
    background = AlabasterBg,
    onBackground = AlabasterTextPrimary,
    surface = AlabasterSurface,
    onSurface = AlabasterTextPrimary,
    surfaceVariant = AlabasterSurfaceLow,
    onSurfaceVariant = AlabasterTextSecondary,
    outline = AlabasterBorder,
    outlineVariant = AlabasterBorder,
  )

val AppsignShapes =
  Shapes(
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(24.dp),
  )

@Composable
fun AppsignTheme(
  themePreference: ThemePreference = ThemePreference.SYSTEM,
  content: @Composable () -> Unit,
) {
  val useDark =
    when (themePreference) {
      ThemePreference.SYSTEM -> isSystemInDarkTheme()
      ThemePreference.LIGHT -> false
      ThemePreference.DARK -> true
    }

  val colorScheme = if (useDark) AppsignDarkColorScheme else AppsignLightColorScheme

  MaterialTheme(
    colorScheme = colorScheme,
    typography = AppsignTypography,
    shapes = AppsignShapes,
    content = content,
  )
}
