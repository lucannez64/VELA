import Foundation
import UIKit

final class FaviconService {
    static let shared = FaviconService()

    private struct CacheEntry {
        let dataUrl: String
        let fetchedAt: Date
    }

    private let ttl: TimeInterval = 24 * 60 * 60
    private var cache: [String: CacheEntry] = [:]
    private let lock = NSLock()

    func clearCache() {
        lock.lock()
        cache.removeAll()
        lock.unlock()
    }

    func fetchDataUrl(for url: String) async -> String? {
        guard let domain = Self.normalizeDomain(url) else { return nil }

        lock.lock()
        if let entry = cache[domain], Date().timeIntervalSince(entry.fetchedAt) < ttl {
            lock.unlock()
            return entry.dataUrl
        }
        lock.unlock()

        let dataUrl = await fetchForDomain(domain)

        if let dataUrl = dataUrl {
            lock.lock()
            cache[domain] = CacheEntry(dataUrl: dataUrl, fetchedAt: Date())
            lock.unlock()
        }

        return dataUrl
    }

    private func fetchForDomain(_ domain: String) async -> String? {
        let candidates = [
            "https://icons.duckduckgo.com/ip3/\(domain).ico",
            "https://\(domain)/favicon.ico",
            "https://\(domain)/favicon.svg",
            "https://\(domain)/favicon.png",
            "https://\(domain)/apple-touch-icon.png",
        ]

        for candidate in candidates {
            if let dataUrl = await fetchImageDataUrl(candidate) {
                return dataUrl
            }
        }

        let base = "https://\(domain)"
        if let found = await discoverFaviconFromHtml(base),
           let dataUrl = await fetchImageDataUrl(found) {
            return dataUrl
        }

        return nil
    }

    private func discoverFaviconFromHtml(_ base: String) async -> String? {
        guard let baseUrl = URL(string: base) else { return nil }

        var request = URLRequest(url: baseUrl)
        request.setValue("VELA Mobile/1.0", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 6

        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode),
              let html = String(data: data, encoding: .utf8) else {
            return nil
        }

        let linkTags = html.matches(for: #"<link[^>]*rel=["'][^"']*icon[^"']*["'][^>]*>"#, options: .caseInsensitive)

        var best: (url: String, score: Int)?

        for tag in linkTags {
            guard let rel = tag.firstMatch(for: #"rel=["']([^"']+)["']"#)?.lowercased(), rel.contains("icon") else { continue }
            guard let href = tag.firstMatch(for: #"href=["']([^"']+)["']"#) else { continue }
            guard let resolved = URL(string: href, relativeTo: baseUrl)?.absoluteString else { continue }

            let relScore: Int
            if rel.contains("apple-touch-icon") {
                relScore = 30
            } else if rel.contains("shortcut") {
                relScore = 10
            } else {
                relScore = 20
            }

            let sizes = tag.firstMatch(for: #"sizes=["']([^"']+)["']"#)
            let sizeScore = sizes?.split(separator: "x").first.flatMap { Int($0) } ?? 0

            let typeScore: Int
            if resolved.hasSuffix(".svg") || resolved.contains("svg+xml") {
                typeScore = 100
            } else if resolved.hasSuffix(".png") {
                typeScore = 50
            } else {
                typeScore = 0
            }

            let total = relScore + sizeScore + typeScore
            if best == nil || total > best!.score {
                best = (resolved, total)
            }
        }

        return best?.url
    }

    private func fetchImageDataUrl(_ urlString: String) async -> String? {
        guard let url = URL(string: urlString) else { return nil }

        var request = URLRequest(url: url)
        request.setValue("VELA Mobile/1.0", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 6

        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode),
              !data.isEmpty else {
            return nil
        }

        let contentType = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Type")
        guard let detectedType = Self.detectImageContentType(contentType: contentType, data: data) else {
            return nil
        }

        let base64 = data.base64EncodedString()
        return "data:\(detectedType);base64,\(base64)"
    }

    private static func detectImageContentType(contentType: String?, data: Data) -> String? {
        if let raw = contentType {
            let ct = raw.split(separator: ";").first.map(String.init)?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
            if ct.hasPrefix("text/html") || ct.hasPrefix("text/plain") {
                return nil
            }
        }

        if data.isEmpty { return nil }

        let pngMagic = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        if data.count >= 8, data.prefix(8) == pngMagic {
            return "image/png"
        }

        let gif87a = "GIF87a".data(using: .ascii)!
        let gif89a = "GIF89a".data(using: .ascii)!
        if data.count >= 6, data.prefix(6) == gif87a || data.prefix(6) == gif89a {
            return "image/gif"
        }

        if data.count >= 3, data[0] == 0xFF, data[1] == 0xD8, data[2] == 0xFF {
            return "image/jpeg"
        }

        let riff = "RIFF".data(using: .ascii)!
        let webp = "WEBP".data(using: .ascii)!
        if data.count >= 12, data.prefix(4) == riff, data.subdata(in: 8..<12) == webp {
            return "image/webp"
        }

        if data.count >= 4, data[0] == 0x00, data[1] == 0x00, data[2] == 0x01, data[3] == 0x00 {
            return "image/x-icon"
        }

        let trimmed = data.drop(while: { $0 == 0x20 || $0 == 0x09 || $0 == 0x0A || $0 == 0x0D })
        let xml = "<?xml".data(using: .ascii)!
        let svg = "<svg".data(using: .ascii)!
        let doctypeSvg = "<!DOCTYPE svg".data(using: .ascii)!
        if trimmed.count >= 5, trimmed.prefix(5) == xml { return "image/svg+xml" }
        if trimmed.count >= 4, trimmed.prefix(4) == svg { return "image/svg+xml" }
        if trimmed.count >= 14, trimmed.prefix(14) == doctypeSvg { return "image/svg+xml" }

        if let raw = contentType,
           let ct = raw.split(separator: ";").first.map(String.init)?.trimmingCharacters(in: .whitespaces),
           ct.lowercased().hasPrefix("image/") {
            return ct
        }

        return nil
    }

    private static func normalizeDomain(_ url: String) -> String? {
        let normalized = url.contains("://") ? url : "https://\(url)"
        guard let host = URL(string: normalized)?.host else { return nil }
        let trimmed = host.trimmingCharacters(in: .whitespaces).lowercased()
        return trimmed.isEmpty ? nil : trimmed
    }
}

private extension String {
    func matches(for pattern: String, options: NSRegularExpression.Options = []) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else { return [] }
        let range = NSRange(startIndex..., in: self)
        return regex.matches(in: self, options: [], range: range).map {
            String(self[Range($0.range, in: self)!])
        }
    }

    func firstMatch(for pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return nil }
        let range = NSRange(startIndex..., in: self)
        guard let match = regex.firstMatch(in: self, options: [], range: range) else { return nil }
        guard match.numberOfRanges > 1 else { return nil }
        let groupRange = Range(match.range(at: 1), in: self)
        return groupRange.map { String(self[$0]) }
    }
}
