/*
 * SPDX-FileCopyrightText: 2025 The Calyx Institute
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package com.aurora.store.compose.composables

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.dimensionResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.aurora.store.BuildConfig
import com.aurora.store.R

/**
 * Composable for displaying package details in a list for blacklisting
 * @param icon Icon for the package
 * @param displayName User-readable name of the package
 * @param packageName Name of the package
 * @param versionName versionName of the package
 * @param versionCode versionCode of the package
 * @param isChecked Whether the app is blacklisted
 * @param onClick Callback when the composable is clicked
 */
@Composable
fun BlackListComposable(
    icon: Bitmap,
    displayName: String,
    packageName: String,
    versionName: String,
    versionCode: Long,
    isChecked: Boolean = false,
    onClick: () -> Unit = {}
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(
                horizontal = dimensionResource(R.dimen.padding_medium),
                vertical = dimensionResource(R.dimen.padding_xsmall)
            ),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(modifier = Modifier.weight(1F)) {
            Image(
                bitmap = icon.asImageBitmap(),
                contentDescription = null,
                modifier = Modifier.requiredSize(dimensionResource(R.dimen.icon_size_medium))
            )
            Column(
                modifier = Modifier.padding(horizontal = dimensionResource(R.dimen.margin_small)),
            ) {
                Text(
                    text = displayName,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = packageName,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = stringResource(R.string.version, versionName, versionCode),
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.sp)
                )
            }
        }
        Checkbox(checked = isChecked, onCheckedChange = { onClick() })
    }
}

@Preview(showBackground = true)
@Composable
private fun BlackListComposablePreview() {
    BlackListComposable(
        icon = ColorDrawable(Color.TRANSPARENT).toBitmap(56, 56),
        displayName = LocalContext.current.getString(R.string.app_name),
        packageName = BuildConfig.APPLICATION_ID,
        versionName = BuildConfig.VERSION_NAME,
        versionCode = BuildConfig.VERSION_CODE.toLong(),
        isChecked = true
    )
}
