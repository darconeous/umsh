package com.voria.umsh.services.radio

import android.annotation.SuppressLint
import android.content.Context
import androidx.annotation.DrawableRes
import com.voria.umsh.services.mobilecore.AppLog
import java.io.IOException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/**
 * The radio boards UMSH knows, by the model identifier a radio advertises
 * and reports (`docs/hardware/boards.json`, staged into the app's assets
 * by the build with each board's photo; iOS reads the same file).
 */
class BoardCatalog(val boards: List<Board>) {
    @Serializable
    data class Board(
        val id: String,
        @SerialName("model_id") val modelId: Int,
        val name: String,
        val vendor: String,
        /** The photo's name, as iOS's asset catalog has it (`board-t1000e`). */
        val photo: String,
    ) {
        /** The staged drawable's name: the photo's, with resource-safe separators. */
        val drawableName: String get() = photo.replace('-', '_')
    }

    @Serializable
    private data class File(val boards: List<Board>)

    private val byModel = boards.associateBy { it.modelId }

    fun board(modelId: Int?): Board? = modelId?.let(byModel::get)

    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        val Empty = BoardCatalog(emptyList())

        fun parse(text: String): BoardCatalog = BoardCatalog(json.decodeFromString<File>(text).boards)

        @Volatile
        private var bundled: BoardCatalog? = null

        /** The app's own copy, read once per process; empty (every radio "Unknown model") if unreadable. */
        fun bundled(context: Context): BoardCatalog = bundled ?: synchronized(this) {
            bundled ?: load(context).also { bundled = it }
        }

        private fun load(context: Context): BoardCatalog = try {
            context.assets.open(ASSET).use { parse(it.readBytes().decodeToString()) }
        } catch (error: IOException) {
            AppLog.e(TAG, "board list unread: ${error.javaClass.simpleName}")
            Empty
        } catch (error: SerializationException) {
            AppLog.e(TAG, "board list unreadable: ${error.javaClass.simpleName}")
            Empty
        } catch (error: IllegalArgumentException) {
            AppLog.e(TAG, "board list unreadable: ${error.javaClass.simpleName}")
            Empty
        }

        /** [board]'s photo, staged by the build as a `nodpi` drawable; null when it is not there. */
        @SuppressLint("DiscouragedApi") // Named by the board list; the build keeps every `board_*`.
        @DrawableRes
        fun photo(context: Context, board: Board?): Int? {
            board ?: return null
            return context.resources.getIdentifier(board.drawableName, "drawable", context.packageName).takeIf { it != 0 }
        }

        const val ASSET = "boards.json"
        private const val TAG = "umsh.radio"
    }
}
