package com.vela.android.favicon

import android.util.Base64
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

private data class CacheEntry(val dataUrl: String, val fetchedAt: Long)

object FaviconFetcher {
    private const val TTL_MS = 24 * 60 * 60 * 1000L
    private val cache = ConcurrentHashMap<String, CacheEntry>()

    fun clearCache() = cache.clear()

    fun fetchDataUrl(url: String): String? {
        val domain = normalizeDomain(url) ?: return null

        val now = System.currentTimeMillis()
        cache[domain]?.let { entry ->
            if (now - entry.fetchedAt < TTL_MS) return entry.dataUrl
        }

        val dataUrl = fetchForDomain(domain)
        dataUrl?.let { cache[domain] = CacheEntry(it, now) }
        return dataUrl
    }

    private fun fetchForDomain(domain: String): String? {
        val candidates = listOf(
            "https://icons.duckduckgo.com/ip3/$domain.ico",
            "https://$domain/favicon.ico",
            "https://$domain/favicon.svg",
            "https://$domain/favicon.png",
            "https://$domain/apple-touch-icon.png",
        )

        candidates.forEach { candidate ->
            fetchImageDataUrl(candidate)?.let { return it }
        }

        val base = "https://$domain"
        discoverFaviconFromHtml(base)?.let { found ->
            fetchImageDataUrl(found)?.let { return it }
        }

        return null
    }

    private fun discoverFaviconFromHtml(base: String): String? {
        val html = try {
            val conn = URL(base).openConnection() as HttpURLConnection
            conn.apply {
                requestMethod = "GET"
                setRequestProperty("User-Agent", "VELA Mobile/1.0")
                connectTimeout = 6000
                readTimeout = 6000
                instanceFollowRedirects = true
            }
            if (conn.responseCode !in 200..299) return null
            conn.inputStream.use { it.bufferedReader().readText() }
        } catch (_: Exception) {
            return null
        }

        val baseUrl = URL(base)

        val linkTags = LINK_ICON_REGEX.findAll(html)
        var best: Pair<String, Int>? = null

        linkTags.forEach { match ->
            val tag = match.value
            val rel = REL_REGEX.find(tag)?.groupValues?.get(1)?.lowercase() ?: return@forEach
            if (!(rel.contains("icon"))) return@forEach

            val href = HREF_REGEX.find(tag)?.groupValues?.get(1) ?: return@forEach
            val resolved = resolveUrl(baseUrl, href) ?: return@forEach

            val relScore = when {
                rel.contains("apple-touch-icon") -> 30
                rel.contains("shortcut") -> 10
                else -> 20
            }

            val sizes = SIZES_REGEX.find(tag)?.groupValues?.get(1)
            val sizeScore = sizes?.split("x")?.firstOrNull()?.toIntOrNull() ?: 0

            val typeScore = when {
                resolved.endsWith(".svg") || resolved.contains("svg+xml") -> 100
                resolved.endsWith(".png") -> 50
                else -> 0
            }

            val total = relScore + sizeScore + typeScore
            if (best == null || total > best.second) {
                best = resolved to total
            }
        }

        return best?.first
    }

    private fun fetchImageDataUrl(url: String): String? {
        val (contentType, bytes) = try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.apply {
                requestMethod = "GET"
                setRequestProperty("User-Agent", "VELA Mobile/1.0")
                connectTimeout = 6000
                readTimeout = 6000
                instanceFollowRedirects = true
            }
            if (conn.responseCode !in 200..299) return null
            val ct = conn.contentType
            val data = conn.inputStream.use { it.readBytes() }
            ct to data
        } catch (_: Exception) {
            return null
        }

        val detectedType = detectImageContentType(contentType, bytes) ?: return null
        val base64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
        return "data:$detectedType;base64,$base64"
    }

    private fun detectImageContentType(contentType: String?, bytes: ByteArray): String? {
        contentType?.let { raw ->
            val ct = raw.split(";").firstOrNull()?.trim()?.lowercase() ?: return@let
            if (ct.startsWith("text/html") || ct.startsWith("text/plain")) return null
        }

        if (bytes.isEmpty()) return null

        if (bytes.size >= 8 && bytes.copyOf(8).contentEquals(PNG_MAGIC)) {
            return "image/png"
        }
        if (bytes.size >= 6 && (
            bytes.copyOf(6).contentEquals(GIF87A_MAGIC) ||
            bytes.copyOf(6).contentEquals(GIF89A_MAGIC)
        )) {
            return "image/gif"
        }
        if (bytes.size >= 3 && bytes[0] == 0xff.toByte() && bytes[1] == 0xd8.toByte() && bytes[2] == 0xff.toByte()) {
            return "image/jpeg"
        }
        if (bytes.size >= 12 && bytes.copyOf(4).contentEquals(RIFF_MAGIC) && bytes.copyOfRange(8, 12).contentEquals(WEBP_MAGIC)) {
            return "image/webp"
        }
        if (bytes.size >= 4 && bytes[0] == 0x00.toByte() && bytes[1] == 0x00.toByte() && bytes[2] == 0x01.toByte() && bytes[3] == 0x00.toByte()) {
            return "image/x-icon"
        }

        val body = bytes.dropWhile { it.toInt().toChar().isWhitespace() }.toByteArray()
        if (body.size >= 5 && body.copyOf(5).contentEquals(XML_MAGIC)) return "image/svg+xml"
        if (body.size >= 4 && body.copyOf(4).contentEquals(SVG_MAGIC)) return "image/svg+xml"
        if (body.size >= 14 && body.copyOf(14).contentEquals(DOCTYPE_SVG_MAGIC)) return "image/svg+xml"

        return contentType
            ?.split(";")
            ?.firstOrNull()
            ?.trim()
            ?.takeIf { it.startsWith("image/") }
    }

    private fun normalizeDomain(url: String): String? {
        val normalized = if (url.contains("://")) url else "https://$url"
        val host = try {
            URI(normalized).host?.trim()?.lowercase()
        } catch (_: Exception) {
            null
        } ?: return null
        if (host.isEmpty()) return null
        return host
    }

    private fun resolveUrl(base: URL, href: String): String? {
        return try {
            URL(base, href).toString()
        } catch (_: Exception) {
            null
        }
    }

    private val PNG_MAGIC = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)
    private val GIF87A_MAGIC = "GIF87a".toByteArray(Charsets.US_ASCII)
    private val GIF89A_MAGIC = "GIF89a".toByteArray(Charsets.US_ASCII)
    private val RIFF_MAGIC = "RIFF".toByteArray(Charsets.US_ASCII)
    private val WEBP_MAGIC = "WEBP".toByteArray(Charsets.US_ASCII)
    private val XML_MAGIC = "<?xml".toByteArray(Charsets.US_ASCII)
    private val SVG_MAGIC = "<svg".toByteArray(Charsets.US_ASCII)
    private val DOCTYPE_SVG_MAGIC = "<!DOCTYPE svg".toByteArray(Charsets.US_ASCII)

    private val LINK_ICON_REGEX = Regex("""<link[^>]*rel=["'][^"']*icon[^"']*["'][^>]*>""", RegexOption.IGNORE_CASE)
    private val REL_REGEX = Regex("""rel=["']([^"']+)["']""")
    private val HREF_REGEX = Regex("""href=["']([^"']+)["']""")
    private val SIZES_REGEX = Regex("""sizes=["']([^"']+)["']""")
}
