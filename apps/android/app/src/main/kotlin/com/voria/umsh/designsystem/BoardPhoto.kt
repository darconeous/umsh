package com.voria.umsh.designsystem

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.services.radio.BoardCatalog

/**
 * A radio's board photo by its model identifier, in a tonal tile; the radio
 * glyph when the model is unknown or has no photo. Decorative: the model's
 * name is always beside it.
 */
@Composable
fun BoardPhoto(modelId: Int?, modifier: Modifier = Modifier, glyphSize: Dp = 24.dp) {
    val context = LocalContext.current
    val photo = remember(modelId) {
        val catalog = BoardCatalog.bundled(context)
        BoardCatalog.photo(context, catalog.board(modelId))
    }
    Box(
        modifier.background(MaterialTheme.colorScheme.surfaceContainerHighest, MaterialTheme.shapes.small),
        contentAlignment = Alignment.Center,
    ) {
        if (photo != null) {
            Image(
                painterResource(photo),
                contentDescription = null,
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize().padding(2.dp),
            )
        } else {
            Icon(
                painterResource(R.drawable.ic_sensors),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(glyphSize),
            )
        }
    }
}

/** The model's name from the board list, or null for a model it does not know. */
@Composable
fun boardName(modelId: Int?): String? {
    val context = LocalContext.current
    return remember(modelId) { BoardCatalog.bundled(context).board(modelId)?.name }
}
