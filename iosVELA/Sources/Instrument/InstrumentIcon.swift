import SwiftUI

/// One stroke (and optional fill) of a 24-unit Instrument icon. `d` holds
/// absolute `M x y`, `L x y`, `C x1 y1 x2 y2 x y` and `Z` commands only.
struct InstrumentIconPart {
    let d: String
    let filled: Bool
    let tx: CGFloat
}

/// Draws one icon part scaled from the 24×24 artboard into its frame.
struct InstrumentIconShape: Shape {
    let d: String
    let tx: CGFloat

    func path(in rect: CGRect) -> Path {
        let scale = min(rect.width, rect.height) / 24
        let originX = rect.midX - 12 * scale
        let originY = rect.midY - 12 * scale
        let tokens = d.split(separator: " ")
        var index = 0
        var path = Path()

        func next() -> CGFloat {
            guard index < tokens.count, let value = Double(tokens[index]) else {
                index += 1
                return 0
            }
            index += 1
            return CGFloat(value)
        }
        func point() -> CGPoint {
            let x = next()
            let y = next()
            return CGPoint(x: originX + (x + tx) * scale, y: originY + y * scale)
        }

        while index < tokens.count {
            let command = tokens[index]
            index += 1
            switch command {
            case "M":
                path.move(to: point())
            case "L":
                path.addLine(to: point())
            case "C":
                let c1 = point()
                let c2 = point()
                let end = point()
                path.addCurve(to: end, control1: c1, control2: c2)
            case "Z":
                path.closeSubpath()
            default:
                break
            }
        }
        return path
    }
}

/// An Instrument line icon, identical to the prototype's SVG set.
struct InstrumentIcon: View {
    let name: InstrumentIconName
    var size: CGFloat = 18
    var color: Color? = nil

    @Environment(\.ink) private var ink

    var body: some View {
        let tint = color ?? ink.text
        let width = name.strokeWidth * size / 24
        ZStack {
            ForEach(0..<name.parts.count, id: \.self) { i in
                InstrumentIconShape(d: name.parts[i].d, tx: name.parts[i].tx)
                    .fill(name.parts[i].filled ? tint : Color.clear)
                InstrumentIconShape(d: name.parts[i].d, tx: name.parts[i].tx)
                    .stroke(tint, style: StrokeStyle(lineWidth: width, lineCap: .round, lineJoin: .round))
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
