import SwiftUI

// Generated from docs/mobile-redesign-instrument.html (same data as Android
// InstrumentIcons.kt). Paths are pre-flattened to absolute M/L/C/Z commands.

enum InstrumentIconName: String, CaseIterable {
    case trash
    case arrow
    case card
    case chev
    case copy
    case device
    case dice
    case dots
    case ext
    case eye
    case eyeoff
    case gear
    case globe
    case grid
    case key
    case lock
    case moon
    case note
    case palette
    case pen
    case phone
    case plus
    case pulse
    case refresh
    case search
    case share
    case shield
    case spark
    case star
    case sun
    case user
    case vault
    case x
    case back
    case check
    case fingerprint
    case link
    case mail
}

extension InstrumentIconName {
    var strokeWidth: CGFloat {
        switch self {
        case .trash: return 1.6
        case .arrow: return 1.6
        case .card: return 1.6
        case .chev: return 1.6
        case .copy: return 1.6
        case .device: return 1.6
        case .dice: return 1.6
        case .dots: return 1.6
        case .ext: return 1.6
        case .eye: return 1.6
        case .eyeoff: return 1.6
        case .gear: return 1.6
        case .globe: return 1.6
        case .grid: return 1.6
        case .key: return 1.6
        case .lock: return 1.6
        case .moon: return 1.6
        case .note: return 1.6
        case .palette: return 1.6
        case .pen: return 1.6
        case .phone: return 1.6
        case .plus: return 1.6
        case .pulse: return 1.6
        case .refresh: return 1.6
        case .search: return 1.6
        case .share: return 1.6
        case .shield: return 1.6
        case .spark: return 1.6
        case .star: return 1.6
        case .sun: return 1.6
        case .user: return 1.6
        case .vault: return 1.6
        case .x: return 1.6
        case .back: return 1.5
        case .check: return 1.5
        case .fingerprint: return 1.5
        case .link: return 1.5
        case .mail: return 1.5
        }
    }

    var parts: [InstrumentIconPart] {
        switch self {
        case .trash: return [InstrumentIconPart(d: "M 4 7 L 20 7 M 9 7 L 9 4 L 15 4 L 15 7 M 6 7 L 7 20 L 17 20 L 18 7 M 10 10 L 10 17 M 14 10 L 14 17", filled: false, tx: 0)]
        case .arrow: return [InstrumentIconPart(d: "M 7 17 L 17 7 M 8.5 7 L 17 7 L 17 15.5", filled: false, tx: 0)]
        case .card: return [InstrumentIconPart(d: "M 5.5 5.5 L 18.5 5.5 C 19.881 5.5 21 6.619 21 8 L 21 16 C 21 17.381 19.881 18.5 18.5 18.5 L 5.5 18.5 C 4.119 18.5 3 17.381 3 16 L 3 8 C 3 6.619 4.119 5.5 5.5 5.5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 3 10 L 21 10 M 7 15 L 10 15", filled: false, tx: 0)]
        case .chev: return [InstrumentIconPart(d: "M 9 6 L 15 12 L 9 18", filled: false, tx: 0)]
        case .copy: return [InstrumentIconPart(d: "M 11 8.5 L 17 8.5 C 18.381 8.5 19.5 9.619 19.5 11 L 19.5 17 C 19.5 18.381 18.381 19.5 17 19.5 L 11 19.5 C 9.619 19.5 8.5 18.381 8.5 17 L 8.5 11 C 8.5 9.619 9.619 8.5 11 8.5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 15.5 8.5 L 15.5 6.5 C 15.5 5.395 14.605 4.5 13.5 4.5 L 6.5 4.5 C 5.395 4.5 4.5 5.395 4.5 6.5 L 4.5 13.5 C 4.5 14.605 5.395 15.5 6.5 15.5 L 8.5 15.5", filled: false, tx: 0)]
        case .device: return [InstrumentIconPart(d: "M 5 5 L 14 5 C 15.105 5 16 5.895 16 7 L 16 13 C 16 14.105 15.105 15 14 15 L 5 15 C 3.895 15 3 14.105 3 13 L 3 7 C 3 5.895 3.895 5 5 5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 6 19 L 13 19", filled: false, tx: 0), InstrumentIconPart(d: "M 18.7 9 L 20.3 9 C 20.963 9 21.5 9.537 21.5 10.2 L 21.5 17.8 C 21.5 18.463 20.963 19 20.3 19 L 18.7 19 C 18.037 19 17.5 18.463 17.5 17.8 L 17.5 10.2 C 17.5 9.537 18.037 9 18.7 9 Z", filled: false, tx: 0)]
        case .dice: return [InstrumentIconPart(d: "M 8 4 L 16 4 C 18.209 4 20 5.791 20 8 L 20 16 C 20 18.209 18.209 20 16 20 L 8 20 C 5.791 20 4 18.209 4 16 L 4 8 C 4 5.791 5.791 4 8 4 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 8.1 9 C 8.1 9.497 8.503 9.9 9 9.9 C 9.497 9.9 9.9 9.497 9.9 9 C 9.9 8.503 9.497 8.1 9 8.1 C 8.503 8.1 8.1 8.503 8.1 9 Z", filled: true, tx: 0), InstrumentIconPart(d: "M 14.1 15 C 14.1 15.497 14.503 15.9 15 15.9 C 15.497 15.9 15.9 15.497 15.9 15 C 15.9 14.503 15.497 14.1 15 14.1 C 14.503 14.1 14.1 14.503 14.1 15 Z", filled: true, tx: 0), InstrumentIconPart(d: "M 14.1 9 C 14.1 9.497 14.503 9.9 15 9.9 C 15.497 9.9 15.9 9.497 15.9 9 C 15.9 8.503 15.497 8.1 15 8.1 C 14.503 8.1 14.1 8.503 14.1 9 Z", filled: true, tx: 0), InstrumentIconPart(d: "M 8.1 15 C 8.1 15.497 8.503 15.9 9 15.9 C 9.497 15.9 9.9 15.497 9.9 15 C 9.9 14.503 9.497 14.1 9 14.1 C 8.503 14.1 8.1 14.503 8.1 15 Z", filled: true, tx: 0)]
        case .dots: return [InstrumentIconPart(d: "M 4.8 12 C 4.8 12.429 5.029 12.825 5.4 13.039 C 5.771 13.254 6.229 13.254 6.6 13.039 C 6.971 12.825 7.2 12.429 7.2 12 C 7.2 11.337 6.663 10.8 6 10.8 C 5.337 10.8 4.8 11.337 4.8 12 Z", filled: true, tx: 0), InstrumentIconPart(d: "M 10.8 12 C 10.8 12.663 11.337 13.2 12 13.2 C 12.663 13.2 13.2 12.663 13.2 12 C 13.2 11.337 12.663 10.8 12 10.8 C 11.337 10.8 10.8 11.337 10.8 12 Z", filled: true, tx: 0), InstrumentIconPart(d: "M 16.8 12 C 16.8 12.429 17.029 12.825 17.4 13.039 C 17.771 13.254 18.229 13.254 18.6 13.039 C 18.971 12.825 19.2 12.429 19.2 12 C 19.2 11.571 18.971 11.175 18.6 10.961 C 18.229 10.746 17.771 10.746 17.4 10.961 C 17.029 11.175 16.8 11.571 16.8 12 Z", filled: true, tx: 0)]
        case .ext: return [InstrumentIconPart(d: "M 9 4.5 C 9 3.395 9.895 2.5 11 2.5 C 12.105 2.5 13 3.395 13 4.5 L 13 6 L 17 6 L 17 10 L 18.5 10 C 19.605 10 20.5 10.895 20.5 12 C 20.5 13.105 19.605 14 18.5 14 L 17 14 L 17 19 L 6 19 L 6 15 L 7.5 15 C 8.605 15 9.5 14.105 9.5 13 C 9.5 11.895 8.605 11 7.5 11 L 6 11 L 6 6 L 9 6 Z", filled: false, tx: 0)]
        case .eye: return [InstrumentIconPart(d: "M 2.5 12 C 2.5 12 6 5.5 12 5.5 C 18 5.5 21.5 12 21.5 12 C 21.5 12 18 18.5 12 18.5 C 6 18.5 2.5 12 2.5 12 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 9.2 12 C 9.2 13.546 10.454 14.8 12 14.8 C 13.546 14.8 14.8 13.546 14.8 12 C 14.8 10.454 13.546 9.2 12 9.2 C 10.454 9.2 9.2 10.454 9.2 12 Z", filled: false, tx: 0)]
        case .eyeoff: return [InstrumentIconPart(d: "M 4 4 L 20 20 M 10 6 C 10.6 5.9 11.3 5.8 12 5.8 C 18 5.8 21.5 12.3 21.5 12.3 C 20.78 13.538 19.906 14.681 18.9 15.7 M 6.5 7.6 C 4 9.4 2.5 12 2.5 12 C 2.5 12 6 18.5 12 18.5 C 13.8 18.5 15.3 18 16.6 17.2", filled: false, tx: 0)]
        case .gear: return [InstrumentIconPart(d: "M 9 12 C 9 13.657 10.343 15 12 15 C 13.657 15 15 13.657 15 12 C 15 10.343 13.657 9 12 9 C 10.343 9 9 10.343 9 12 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 12 3.5 L 12 5.7 M 12 18.3 L 12 20.5 M 3.5 12 L 5.7 12 M 18.3 12 L 20.5 12 M 6 6 L 7.6 7.6 M 16.4 16.4 L 18 18 M 6 18 L 7.6 16.4 M 16.4 7.6 L 18 6", filled: false, tx: 0)]
        case .globe: return [InstrumentIconPart(d: "M 3.5 12 C 3.5 16.694 7.306 20.5 12 20.5 C 16.694 20.5 20.5 16.694 20.5 12 C 20.5 7.306 16.694 3.5 12 3.5 C 7.306 3.5 3.5 7.306 3.5 12 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 3.5 12 L 20.5 12 M 12 3.5 C 14.5 6.1 14.5 17.9 12 20.5 M 12 3.5 C 9.5 6.1 9.5 17.9 12 20.5", filled: false, tx: 0)]
        case .grid: return [InstrumentIconPart(d: "M 5.6 4 L 8.9 4 C 9.784 4 10.5 4.716 10.5 5.6 L 10.5 8.9 C 10.5 9.784 9.784 10.5 8.9 10.5 L 5.6 10.5 C 4.716 10.5 4 9.784 4 8.9 L 4 5.6 C 4 4.716 4.716 4 5.6 4 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 15.1 4 L 18.4 4 C 19.284 4 20 4.716 20 5.6 L 20 8.9 C 20 9.784 19.284 10.5 18.4 10.5 L 15.1 10.5 C 14.216 10.5 13.5 9.784 13.5 8.9 L 13.5 5.6 C 13.5 4.716 14.216 4 15.1 4 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 5.6 13.5 L 8.9 13.5 C 9.784 13.5 10.5 14.216 10.5 15.1 L 10.5 18.4 C 10.5 19.284 9.784 20 8.9 20 L 5.6 20 C 4.716 20 4 19.284 4 18.4 L 4 15.1 C 4 14.216 4.716 13.5 5.6 13.5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 15.1 13.5 L 18.4 13.5 C 19.284 13.5 20 14.216 20 15.1 L 20 18.4 C 20 19.284 19.284 20 18.4 20 L 15.1 20 C 14.216 20 13.5 19.284 13.5 18.4 L 13.5 15.1 C 13.5 14.216 14.216 13.5 15.1 13.5 Z", filled: false, tx: 0)]
        case .key: return [InstrumentIconPart(d: "M 4 15 C 4 17.209 5.791 19 8 19 C 10.209 19 12 17.209 12 15 C 12 12.791 10.209 11 8 11 C 5.791 11 4 12.791 4 15 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 11 12 L 19.5 3.5 M 16.5 6.5 L 19 9 M 14 9 L 16 11", filled: false, tx: 0)]
        case .lock: return [InstrumentIconPart(d: "M 7.5 10.5 L 16.5 10.5 C 17.881 10.5 19 11.619 19 13 L 19 18 C 19 19.381 17.881 20.5 16.5 20.5 L 7.5 20.5 C 6.119 20.5 5 19.381 5 18 L 5 13 C 5 11.619 6.119 10.5 7.5 10.5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 8 10.5 L 8 8 C 8 5.791 9.791 4 12 4 C 14.209 4 16 5.791 16 8 L 16 10.5", filled: false, tx: 0)]
        case .moon: return [InstrumentIconPart(d: "M 19.5 14.5 C 16.667 15.372 13.585 14.607 11.489 12.511 C 9.393 10.415 8.628 7.333 9.5 4.5 C 5.86 5.621 3.515 9.152 3.894 12.941 C 4.272 16.73 7.27 19.728 11.059 20.106 C 14.848 20.485 18.379 18.14 19.5 14.5 Z", filled: false, tx: 0)]
        case .note: return [InstrumentIconPart(d: "M 6 3.5 L 14 3.5 L 18 7.5 L 18 20.5 L 6 20.5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 14 3.5 L 14 7.5 L 18 7.5 M 9 12 L 15 12 M 9 15.5 L 15 15.5", filled: false, tx: 0)]
        case .palette: return [InstrumentIconPart(d: "M 12 3.5 C 7.306 3.5 3.5 7.306 3.5 12 C 3.5 16.694 7.306 20.5 12 20.5 C 13.2 20.5 13.8 19.7 13.8 18.8 C 13.8 17.6 12.8 17.3 12.8 16.2 C 12.8 15.3 13.5 14.6 14.4 14.6 L 16.5 14.6 C 18.709 14.6 20.5 12.809 20.5 10.6 C 20.5 6.8 16.7 3.5 12 3.5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 6.7 11 C 6.7 11.608 7.192 12.1 7.8 12.1 C 8.408 12.1 8.9 11.608 8.9 11 C 8.9 10.392 8.408 9.9 7.8 9.9 C 7.192 9.9 6.7 10.392 6.7 11 Z", filled: true, tx: 0), InstrumentIconPart(d: "M 9.4 7.4 C 9.4 8.008 9.892 8.5 10.5 8.5 C 11.108 8.5 11.6 8.008 11.6 7.4 C 11.6 7.007 11.39 6.644 11.05 6.447 C 10.71 6.251 10.29 6.251 9.95 6.447 C 9.61 6.644 9.4 7.007 9.4 7.4 Z", filled: true, tx: 0), InstrumentIconPart(d: "M 13.9 7.6 C 13.9 8.208 14.392 8.7 15 8.7 C 15.608 8.7 16.1 8.208 16.1 7.6 C 16.1 7.207 15.89 6.844 15.55 6.647 C 15.21 6.451 14.79 6.451 14.45 6.647 C 14.11 6.844 13.9 7.207 13.9 7.6 Z", filled: true, tx: 0)]
        case .pen: return [InstrumentIconPart(d: "M 4 20 L 8 20 L 19 9 L 15 5 L 4 16 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 13.5 6.5 L 17.5 10.5", filled: false, tx: 0)]
        case .phone: return [InstrumentIconPart(d: "M 9.5 3 L 14.5 3 C 15.881 3 17 4.119 17 5.5 L 17 18.5 C 17 19.881 15.881 21 14.5 21 L 9.5 21 C 8.119 21 7 19.881 7 18.5 L 7 5.5 C 7 4.119 8.119 3 9.5 3 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 11 18 L 13 18", filled: false, tx: 0)]
        case .plus: return [InstrumentIconPart(d: "M 12 5 L 12 19 M 5 12 L 19 12", filled: false, tx: 0)]
        case .pulse: return [InstrumentIconPart(d: "M 3 12 L 7 12 L 9.5 6 L 14.5 18 L 17 12 L 21 12", filled: false, tx: 0)]
        case .refresh: return [InstrumentIconPart(d: "M 19.5 12 C 19.503 15.578 16.978 18.66 13.469 19.361 C 9.96 20.062 6.445 18.187 5.073 14.882 C 3.701 11.577 4.855 7.763 7.829 5.773 C 10.803 3.783 14.768 4.171 17.3 6.7 M 19.5 4.5 L 19.5 8.5 L 15.5 8.5", filled: false, tx: 0)]
        case .search: return [InstrumentIconPart(d: "M 4.5 11 C 4.5 14.59 7.41 17.5 11 17.5 C 14.59 17.5 17.5 14.59 17.5 11 C 17.5 7.41 14.59 4.5 11 4.5 C 7.41 4.5 4.5 7.41 4.5 11 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 20 20 L 15.8 15.8", filled: false, tx: 0)]
        case .share: return [InstrumentIconPart(d: "M 14.5 6 C 14.5 7.381 15.619 8.5 17 8.5 C 18.381 8.5 19.5 7.381 19.5 6 C 19.5 4.619 18.381 3.5 17 3.5 C 15.619 3.5 14.5 4.619 14.5 6 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 4.5 12 C 4.5 13.381 5.619 14.5 7 14.5 C 8.381 14.5 9.5 13.381 9.5 12 C 9.5 10.619 8.381 9.5 7 9.5 C 5.619 9.5 4.5 10.619 4.5 12 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 14.5 18 C 14.5 19.381 15.619 20.5 17 20.5 C 18.381 20.5 19.5 19.381 19.5 18 C 19.5 16.619 18.381 15.5 17 15.5 C 15.619 15.5 14.5 16.619 14.5 18 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 9.2 10.8 L 14.8 7.4 M 9.2 13.2 L 14.8 16.6", filled: false, tx: 0)]
        case .shield: return [InstrumentIconPart(d: "M 12 3.5 L 5 6 L 5 11.5 C 5 15.9 8 19.3 12 20.5 C 16 19.3 19 15.9 19 11.5 L 19 6 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 9 12 L 11 14 L 15 10", filled: false, tx: 0)]
        case .spark: return [InstrumentIconPart(d: "M 12 3 C 12.6 7.6 14.4 9.4 19 10 C 14.4 10.6 12.6 12.4 12 17 C 11.4 12.4 9.6 10.6 5 10 C 9.6 9.4 11.4 7.6 12 3 Z M 19 16 C 19.2 17.6 19.9 18.3 21.5 18.5 C 19.9 18.7 19.2 19.4 19 21 C 18.8 19.4 18.1 18.7 16.5 18.5 C 18.1 18.3 18.8 17.6 19 16 Z", filled: false, tx: 0)]
        case .star: return [InstrumentIconPart(d: "M 12 4 L 14.4 8.9 L 19.8 9.7 L 15.9 13.5 L 16.8 18.9 L 12 16.3 L 7.2 18.9 L 8.1 13.5 L 4.2 9.7 L 9.6 8.9 Z", filled: false, tx: 0)]
        case .sun: return [InstrumentIconPart(d: "M 8 12 C 8 14.209 9.791 16 12 16 C 14.209 16 16 14.209 16 12 C 16 9.791 14.209 8 12 8 C 9.791 8 8 9.791 8 12 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 12 2.5 L 12 4.5 M 12 19.5 L 12 21.5 M 2.5 12 L 4.5 12 M 19.5 12 L 21.5 12 M 5.3 5.3 L 6.7 6.7 M 17.3 17.3 L 18.7 18.7 M 5.3 18.7 L 6.7 17.3 M 17.3 6.7 L 18.7 5.3", filled: false, tx: 0)]
        case .user: return [InstrumentIconPart(d: "M 8.2 8.5 C 8.2 10.599 9.901 12.3 12 12.3 C 14.099 12.3 15.8 10.599 15.8 8.5 C 15.8 6.401 14.099 4.7 12 4.7 C 9.901 4.7 8.2 6.401 8.2 8.5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 4.5 20 C 5.7 16.4 8.5 14.7 12 14.7 C 15.5 14.7 18.3 16.4 19.5 20", filled: false, tx: 0)]
        case .vault: return [InstrumentIconPart(d: "M 6.5 4.5 L 17.5 4.5 C 19.157 4.5 20.5 5.843 20.5 7.5 L 20.5 16.5 C 20.5 18.157 19.157 19.5 17.5 19.5 L 6.5 19.5 C 4.843 19.5 3.5 18.157 3.5 16.5 L 3.5 7.5 C 3.5 5.843 4.843 4.5 6.5 4.5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 8.8 12 C 8.8 13.767 10.233 15.2 12 15.2 C 13.767 15.2 15.2 13.767 15.2 12 C 15.2 10.233 13.767 8.8 12 8.8 C 10.233 8.8 8.8 10.233 8.8 12 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 12 8.8 L 12 7.8 M 12 16.2 L 12 15.2 M 15.2 12 L 16.2 12 M 7.8 12 L 8.8 12", filled: false, tx: 0)]
        case .x: return [InstrumentIconPart(d: "M 6 6 L 18 18 M 18 6 L 6 18", filled: false, tx: 0)]
        case .back: return [InstrumentIconPart(d: "M 14 6 L 8 12 L 14 18 M 8 12 L 20 12", filled: false, tx: 0)]
        case .check: return [InstrumentIconPart(d: "M 5 12 L 9 16 L 19 6", filled: false, tx: 0)]
        case .fingerprint: return [InstrumentIconPart(d: "M 5 10 C 5 6.134 8.134 3 12 3 C 15.866 3 19 6.134 19 10 M 3 12 L 3 14 M 21 12 L 21 14 M 8 11 C 8 8.791 9.791 7 12 7 C 14.209 7 16 8.791 16 11 L 16 15 C 16 17 15 19 14 21 M 11 21 C 12 18 13 15 12 11 M 5 13 C 5 16 4 18 3 19 M 8 14 C 8 17 7 19 6 21 M 19 15 C 19 17 18 19 17 21", filled: false, tx: 0)]
        case .link: return [InstrumentIconPart(d: "M 10 13 L 14 9 M 8 16 L 7 17 C 5.343 18.657 2.657 18.657 1 17 C -0.657 15.343 -0.657 12.657 1 11 L 5 7 C 5.759 6.139 6.852 5.646 8 5.646 C 9.148 5.646 10.241 6.139 11 7 M 13 8 L 14 7 C 15.657 5.343 18.343 5.343 20 7 C 21.657 8.657 21.657 11.343 20 13 L 16 17 C 15.241 17.861 14.148 18.354 13 18.354 C 11.852 18.354 10.759 17.861 10 17", filled: false, tx: 1)]
        case .mail: return [InstrumentIconPart(d: "M 6 5 L 18 5 C 19.657 5 21 6.343 21 8 L 21 16 C 21 17.657 19.657 19 18 19 L 6 19 C 4.343 19 3 17.657 3 16 L 3 8 C 3 6.343 4.343 5 6 5 Z", filled: false, tx: 0), InstrumentIconPart(d: "M 4 7 L 12 13 L 20 7", filled: false, tx: 0)]
        }
    }
}
