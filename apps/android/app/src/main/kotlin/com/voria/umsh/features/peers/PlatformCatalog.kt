package com.voria.umsh.features.peers

import android.content.Context
import androidx.annotation.StringRes
import com.voria.umsh.R
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.radio.BoardCatalog
import java.io.IOException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/** The outline a device on Nearby is drawn with (`nearby-exchange.svg` 7). */
enum class MeetGlyphKind { Phone, Tablet, Computer, Board }

/** What Nearby calls a device of some model, and how it draws it. */
data class MeetModel(
    val glyph: MeetGlyphKind,
    /** The name as a resource, for the platforms whose names are words to translate. */
    @StringRes val nameRes: Int?,
    /** The name as the catalogs spell it: a product's or a board's own; null when neither knows the model. */
    val name: String?,
)

/**
 * The host platforms UMSH knows, by the model identifier a phone or
 * computer reports in its Hellos (`docs/hardware/platforms.json`, staged
 * into the app's assets by the build; iOS reads the same file), with the
 * boards (`BoardCatalog`) for every other model. The file's symbols are
 * SF Symbols names; Android maps them to its own outlines here.
 */
class PlatformCatalog(val platforms: List<Platform>, private val boards: BoardCatalog) {
    @Serializable
    data class Platform(
        val id: String,
        @SerialName("model_id") val modelId: Int,
        val name: String,
        /** iOS's SF Symbols name. */
        val symbol: String,
    )

    @Serializable
    private data class File(val platforms: List<Platform>)

    private val byModel = platforms.associateBy { it.modelId }

    /** What [model] is called and drawn as: a platform, a board (a handheld radio's outline), or neither. */
    fun model(model: Int): MeetModel {
        byModel[model]?.let { platform ->
            return MeetModel(glyph(platform.symbol), NAMES[platform.id], platform.name)
        }
        return MeetModel(MeetGlyphKind.Board, null, boards.board(model)?.name)
    }

    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        /**
         * Platforms whose names are words rather than product names, so a
         * translation can say them; any other takes the file's spelling.
         */
        private val NAMES = mapOf(
            "android-phone" to R.string.meet_platform_android_phone,
            "android-tablet" to R.string.meet_platform_android_tablet,
            "computer" to R.string.meet_platform_computer,
        )

        /** The SF Symbols names the file uses, as outlines. Anything else is a radio. */
        fun glyph(symbol: String): MeetGlyphKind = when {
            symbol == "iphone" || symbol == "smartphone" -> MeetGlyphKind.Phone
            symbol.startsWith("ipad") -> MeetGlyphKind.Tablet
            symbol == "laptopcomputer" || symbol == "desktopcomputer" -> MeetGlyphKind.Computer
            else -> MeetGlyphKind.Board
        }

        fun parse(text: String, boards: BoardCatalog): PlatformCatalog =
            PlatformCatalog(json.decodeFromString<File>(text).platforms, boards)

        @Volatile
        private var bundled: PlatformCatalog? = null

        /** The app's own copy, read once per process; with no platforms (every device a radio) if unreadable. */
        fun bundled(context: Context): PlatformCatalog = bundled ?: synchronized(this) {
            bundled ?: load(context).also { bundled = it }
        }

        private fun load(context: Context): PlatformCatalog {
            val boards = BoardCatalog.bundled(context)
            val failure = try {
                return context.assets.open(ASSET).use { parse(it.readBytes().decodeToString(), boards) }
            } catch (error: IOException) {
                error
            } catch (error: SerializationException) {
                error
            } catch (error: IllegalArgumentException) {
                error
            }
            AppLog.e(TAG, "platform list unreadable: ${failure.javaClass.simpleName}")
            return PlatformCatalog(emptyList(), boards)
        }

        const val ASSET = "platforms.json"
        private const val TAG = "umsh.meet"
    }
}
