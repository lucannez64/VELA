package com.vela.android.ui.components

// Generated from the Instrument reference (docs/mobile-redesign-instrument.html).
// Same 24-unit line icons as the prototype, so the app and design match 1:1.

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.graphics.vector.group
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

private fun icon(name: String, strokeWidth: Float, vararg parts: Triple<String, Boolean, Float>): ImageVector =
    ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).apply {
        parts.forEach { (d, filled, tx) ->
            group(translationX = tx) {
                addPath(addPathNodes(d), fill = if (filled) SolidColor(Color.Black) else null,
                    stroke = SolidColor(Color.Black), strokeLineWidth = strokeWidth,
                    strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round)
            }
        }
    }.build()

object InstrumentIcons {
    val Trash: ImageVector by lazy { icon("trash", 1.6f, Triple("M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 10v7M14 10v7", false, 0.0f)) }
    val Arrow: ImageVector by lazy { icon("arrow", 1.6f, Triple("M7 17 17 7M8.5 7H17v8.5", false, 0.0f)) }
    val Card: ImageVector by lazy { icon("card", 1.6f, Triple("M5.5,5.5h13a2.5,2.5 0 0,1 2.5,2.5v8a2.5,2.5 0 0,1 -2.5,2.5h-13a2.5,2.5 0 0,1 -2.5,-2.5v-8a2.5,2.5 0 0,1 2.5,-2.5Z", false, 0.0f), Triple("M3 10h18M7 15h3", false, 0.0f)) }
    val Chev: ImageVector by lazy { icon("chev", 1.6f, Triple("m9 6 6 6-6 6", false, 0.0f)) }
    val Copy: ImageVector by lazy { icon("copy", 1.6f, Triple("M11,8.5h6a2.5,2.5 0 0,1 2.5,2.5v6a2.5,2.5 0 0,1 -2.5,2.5h-6a2.5,2.5 0 0,1 -2.5,-2.5v-6a2.5,2.5 0 0,1 2.5,-2.5Z", false, 0.0f), Triple("M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2", false, 0.0f)) }
    val Device: ImageVector by lazy { icon("device", 1.6f, Triple("M5,5h9a2,2 0 0,1 2,2v6a2,2 0 0,1 -2,2h-9a2,2 0 0,1 -2,-2v-6a2,2 0 0,1 2,-2Z", false, 0.0f), Triple("M6 19h7", false, 0.0f), Triple("M18.7,9h1.6a1.2,1.2 0 0,1 1.2,1.2v7.6a1.2,1.2 0 0,1 -1.2,1.2h-1.6a1.2,1.2 0 0,1 -1.2,-1.2v-7.6a1.2,1.2 0 0,1 1.2,-1.2Z", false, 0.0f)) }
    val Dice: ImageVector by lazy { icon("dice", 1.6f, Triple("M8,4h8a4,4 0 0,1 4,4v8a4,4 0 0,1 -4,4h-8a4,4 0 0,1 -4,-4v-8a4,4 0 0,1 4,-4Z", false, 0.0f), Triple("M8.1,9a0.9,0.9 0 1,0 1.8,0a0.9,0.9 0 1,0 -1.8,0Z", true, 0.0f), Triple("M14.1,15a0.9,0.9 0 1,0 1.8,0a0.9,0.9 0 1,0 -1.8,0Z", true, 0.0f), Triple("M14.1,9a0.9,0.9 0 1,0 1.8,0a0.9,0.9 0 1,0 -1.8,0Z", true, 0.0f), Triple("M8.1,15a0.9,0.9 0 1,0 1.8,0a0.9,0.9 0 1,0 -1.8,0Z", true, 0.0f)) }
    val Dots: ImageVector by lazy { icon("dots", 1.6f, Triple("M4.8,12a1.2,1.2 0 1,0 2.4,0a1.2,1.2 0 1,0 -2.4,0Z", true, 0.0f), Triple("M10.8,12a1.2,1.2 0 1,0 2.4,0a1.2,1.2 0 1,0 -2.4,0Z", true, 0.0f), Triple("M16.8,12a1.2,1.2 0 1,0 2.4,0a1.2,1.2 0 1,0 -2.4,0Z", true, 0.0f)) }
    val Ext: ImageVector by lazy { icon("ext", 1.6f, Triple("M9 4.5a2 2 0 0 1 4 0V6h4v4h1.5a2 2 0 0 1 0 4H17v5H6v-4h1.5a2 2 0 0 0 0-4H6V6h3z", false, 0.0f)) }
    val Eye: ImageVector by lazy { icon("eye", 1.6f, Triple("M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z", false, 0.0f), Triple("M9.2,12a2.8,2.8 0 1,0 5.6,0a2.8,2.8 0 1,0 -5.6,0Z", false, 0.0f)) }
    val Eyeoff: ImageVector by lazy { icon("eyeoff", 1.6f, Triple("M4 4l16 16M10 6c.6-.1 1.3-.2 2-.2 6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.6 3.4M6.5 7.6C4 9.4 2.5 12 2.5 12S6 18.5 12 18.5c1.8 0 3.3-.5 4.6-1.3", false, 0.0f)) }
    val Gear: ImageVector by lazy { icon("gear", 1.6f, Triple("M9,12a3,3 0 1,0 6,0a3,3 0 1,0 -6,0Z", false, 0.0f), Triple("M12 3.5v2.2M12 18.3v2.2M3.5 12h2.2M18.3 12h2.2M6 6l1.6 1.6M16.4 16.4 18 18M6 18l1.6-1.6M16.4 7.6 18 6", false, 0.0f)) }
    val Globe: ImageVector by lazy { icon("globe", 1.6f, Triple("M3.5,12a8.5,8.5 0 1,0 17,0a8.5,8.5 0 1,0 -17,0Z", false, 0.0f), Triple("M3.5 12h17M12 3.5c2.5 2.6 2.5 14.4 0 17M12 3.5c-2.5 2.6-2.5 14.4 0 17", false, 0.0f)) }
    val Grid: ImageVector by lazy { icon("grid", 1.6f, Triple("M5.6,4h3.3a1.6,1.6 0 0,1 1.6,1.6v3.3a1.6,1.6 0 0,1 -1.6,1.6h-3.3a1.6,1.6 0 0,1 -1.6,-1.6v-3.3a1.6,1.6 0 0,1 1.6,-1.6Z", false, 0.0f), Triple("M15.1,4h3.3a1.6,1.6 0 0,1 1.6,1.6v3.3a1.6,1.6 0 0,1 -1.6,1.6h-3.3a1.6,1.6 0 0,1 -1.6,-1.6v-3.3a1.6,1.6 0 0,1 1.6,-1.6Z", false, 0.0f), Triple("M5.6,13.5h3.3a1.6,1.6 0 0,1 1.6,1.6v3.3a1.6,1.6 0 0,1 -1.6,1.6h-3.3a1.6,1.6 0 0,1 -1.6,-1.6v-3.3a1.6,1.6 0 0,1 1.6,-1.6Z", false, 0.0f), Triple("M15.1,13.5h3.3a1.6,1.6 0 0,1 1.6,1.6v3.3a1.6,1.6 0 0,1 -1.6,1.6h-3.3a1.6,1.6 0 0,1 -1.6,-1.6v-3.3a1.6,1.6 0 0,1 1.6,-1.6Z", false, 0.0f)) }
    val Key: ImageVector by lazy { icon("key", 1.6f, Triple("M4,15a4,4 0 1,0 8,0a4,4 0 1,0 -8,0Z", false, 0.0f), Triple("m11 12 8.5-8.5M16.5 6.5l2.5 2.5M14 9l2 2", false, 0.0f)) }
    val Lock: ImageVector by lazy { icon("lock", 1.6f, Triple("M7.5,10.5h9a2.5,2.5 0 0,1 2.5,2.5v5a2.5,2.5 0 0,1 -2.5,2.5h-9a2.5,2.5 0 0,1 -2.5,-2.5v-5a2.5,2.5 0 0,1 2.5,-2.5Z", false, 0.0f), Triple("M8 10.5V8a4 4 0 0 1 8 0v2.5", false, 0.0f)) }
    val Moon: ImageVector by lazy { icon("moon", 1.6f, Triple("M19.5 14.5A8 8 0 0 1 9.5 4.5a8 8 0 1 0 10 10z", false, 0.0f)) }
    val Note: ImageVector by lazy { icon("note", 1.6f, Triple("M6 3.5h8l4 4v13H6z", false, 0.0f), Triple("M14 3.5v4h4M9 12h6M9 15.5h6", false, 0.0f)) }
    val Palette: ImageVector by lazy { icon("palette", 1.6f, Triple("M12 3.5a8.5 8.5 0 0 0 0 17c1.2 0 1.8-.8 1.8-1.7 0-1.2-1-1.5-1-2.6 0-.9.7-1.6 1.6-1.6h2.1a4 4 0 0 0 4-4C20.5 6.8 16.7 3.5 12 3.5z", false, 0.0f), Triple("M6.7,11a1.1,1.1 0 1,0 2.2,0a1.1,1.1 0 1,0 -2.2,0Z", true, 0.0f), Triple("M9.4,7.4a1.1,1.1 0 1,0 2.2,0a1.1,1.1 0 1,0 -2.2,0Z", true, 0.0f), Triple("M13.9,7.6a1.1,1.1 0 1,0 2.2,0a1.1,1.1 0 1,0 -2.2,0Z", true, 0.0f)) }
    val Pen: ImageVector by lazy { icon("pen", 1.6f, Triple("M4 20h4L19 9l-4-4L4 16z", false, 0.0f), Triple("m13.5 6.5 4 4", false, 0.0f)) }
    val Phone: ImageVector by lazy { icon("phone", 1.6f, Triple("M9.5,3h5a2.5,2.5 0 0,1 2.5,2.5v13a2.5,2.5 0 0,1 -2.5,2.5h-5a2.5,2.5 0 0,1 -2.5,-2.5v-13a2.5,2.5 0 0,1 2.5,-2.5Z", false, 0.0f), Triple("M11 18h2", false, 0.0f)) }
    val Plus: ImageVector by lazy { icon("plus", 1.6f, Triple("M12 5v14M5 12h14", false, 0.0f)) }
    val Pulse: ImageVector by lazy { icon("pulse", 1.6f, Triple("M3 12h4l2.5-6 5 12 2.5-6h4", false, 0.0f)) }
    val Refresh: ImageVector by lazy { icon("refresh", 1.6f, Triple("M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4", false, 0.0f)) }
    val Search: ImageVector by lazy { icon("search", 1.6f, Triple("M4.5,11a6.5,6.5 0 1,0 13,0a6.5,6.5 0 1,0 -13,0Z", false, 0.0f), Triple("m20 20-4.2-4.2", false, 0.0f)) }
    val Share: ImageVector by lazy { icon("share", 1.6f, Triple("M14.5,6a2.5,2.5 0 1,0 5,0a2.5,2.5 0 1,0 -5,0Z", false, 0.0f), Triple("M4.5,12a2.5,2.5 0 1,0 5,0a2.5,2.5 0 1,0 -5,0Z", false, 0.0f), Triple("M14.5,18a2.5,2.5 0 1,0 5,0a2.5,2.5 0 1,0 -5,0Z", false, 0.0f), Triple("m9.2 10.8 5.6-3.4M9.2 13.2l5.6 3.4", false, 0.0f)) }
    val Shield: ImageVector by lazy { icon("shield", 1.6f, Triple("M12 3.5 5 6v5.5c0 4.4 3 7.8 7 9 4-1.2 7-4.6 7-9V6z", false, 0.0f), Triple("m9 12 2 2 4-4", false, 0.0f)) }
    val Spark: ImageVector by lazy { icon("spark", 1.6f, Triple("M12 3c.6 4.6 2.4 6.4 7 7-4.6.6-6.4 2.4-7 7-.6-4.6-2.4-6.4-7-7 4.6-.6 6.4-2.4 7-7zM19 16c.2 1.6.9 2.3 2.5 2.5-1.6.2-2.3.9-2.5 2.5-.2-1.6-.9-2.3-2.5-2.5 1.6-.2 2.3-.9 2.5-2.5z", false, 0.0f)) }
    val Star: ImageVector by lazy { icon("star", 1.6f, Triple("m12 4 2.4 4.9 5.4.8-3.9 3.8.9 5.4-4.8-2.6-4.8 2.6.9-5.4L4.2 9.7l5.4-.8z", false, 0.0f)) }
    val Sun: ImageVector by lazy { icon("sun", 1.6f, Triple("M8,12a4,4 0 1,0 8,0a4,4 0 1,0 -8,0Z", false, 0.0f), Triple("M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4", false, 0.0f)) }
    val User: ImageVector by lazy { icon("user", 1.6f, Triple("M8.2,8.5a3.8,3.8 0 1,0 7.6,0a3.8,3.8 0 1,0 -7.6,0Z", false, 0.0f), Triple("M4.5 20c1.2-3.6 4-5.3 7.5-5.3s6.3 1.7 7.5 5.3", false, 0.0f)) }
    val Vault: ImageVector by lazy { icon("vault", 1.6f, Triple("M6.5,4.5h11a3,3 0 0,1 3,3v9a3,3 0 0,1 -3,3h-11a3,3 0 0,1 -3,-3v-9a3,3 0 0,1 3,-3Z", false, 0.0f), Triple("M8.8,12a3.2,3.2 0 1,0 6.4,0a3.2,3.2 0 1,0 -6.4,0Z", false, 0.0f), Triple("M12 8.8v-1M12 16.2v-1M15.2 12h1M7.8 12h1", false, 0.0f)) }
    val X: ImageVector by lazy { icon("x", 1.6f, Triple("M6 6l12 12M18 6 6 18", false, 0.0f)) }
    val Back: ImageVector by lazy { icon("back", 1.5f, Triple("m14 6-6 6 6 6M8 12h12", false, 0.0f)) }
    val Check: ImageVector by lazy { icon("check", 1.5f, Triple("m5 12 4 4L19 6", false, 0.0f)) }
    val Fingerprint: ImageVector by lazy { icon("fingerprint", 1.5f, Triple("M5 10a7 7 0 0 1 14 0M3 12v2m18-2v2M8 11a4 4 0 0 1 8 0v4c0 2-1 4-2 6M11 21c1-3 2-6 1-10M5 13c0 3-1 5-2 6M8 14c0 3-1 5-2 7M19 15c0 2-1 4-2 6", false, 0.0f)) }
    val Link: ImageVector by lazy { icon("link", 1.5f, Triple("m10 13 4-4M8 16l-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0M13 8l1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0", false, 1.0f)) }
    val Mail: ImageVector by lazy { icon("mail", 1.5f, Triple("M6,5h12a3,3 0 0,1 3,3v8a3,3 0 0,1 -3,3h-12a3,3 0 0,1 -3,-3v-8a3,3 0 0,1 3,-3Z", false, 0.0f), Triple("m4 7 8 6 8-6", false, 0.0f)) }
}
