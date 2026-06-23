import SwiftUI

struct FaviconImage: View {
    let url: String?
    let fallback: String
    let size: CGFloat
    let cornerRadius: CGFloat

    @State private var dataUrl: String?

    init(url: String?, fallback: String, size: CGFloat = 36, cornerRadius: CGFloat = 8) {
        self.url = url
        self.fallback = fallback
        self.size = size
        self.cornerRadius = cornerRadius
    }

    var body: some View {
        Group {
            if let dataUrl = dataUrl, let uiImage = image(from: dataUrl) {
                Image(uiImage: uiImage)
                    .resizable()
                    .scaledToFill()
                    .frame(width: size, height: size)
                    .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            } else {
                ZStack {
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(.green.opacity(0.2))
                        .frame(width: size, height: size)
                    Image(systemName: fallback)
                        .font(.system(size: size * 0.45, weight: .semibold))
                        .foregroundStyle(.green)
                }
            }
        }
        .task(id: url) {
            dataUrl = nil
            if let url = url, !url.isEmpty {
                dataUrl = await FaviconService.shared.fetchDataUrl(for: url)
            }
        }
    }

    private func image(from dataUrl: String) -> UIImage? {
        guard let commaIndex = dataUrl.range(of: "base64,")?.upperBound else { return nil }
        let base64 = String(dataUrl[commaIndex...])
        guard !base64.isEmpty,
              let data = Data(base64Encoded: base64, options: .ignoreUnknownCharacters),
              let image = UIImage(data: data) else {
            return nil
        }
        return image
    }
}
