import Foundation

/// One card value the AutoFill extension can insert.
///
/// iOS's credential-provider extension inserts a single string per request
/// (`completeRequest(withTextToInsert:)`), so a card is offered as its number,
/// expiry, CVV and cardholder separately rather than as a whole-form fill.
struct CardInsertable: Identifiable, Equatable {
    let id: String
    let label: String
    let value: String
}

enum CardInsert {
    /// Every stored card, expanded into its individually-insertable values.
    /// Live in `Shared` so the AutoFill extension and the app's tests share one
    /// implementation.
    static func insertables(from items: [VaultItem]) -> [CardInsertable] {
        var out: [CardInsertable] = []
        for card in items where card.kind == .creditCard {
            if let number = card.number, !number.isEmpty {
                out.append(CardInsertable(
                    id: "\(card.id)-number",
                    label: "\(card.name) · Card number",
                    value: number
                ))
            }
            if let exp = card.exp, !exp.isEmpty {
                out.append(CardInsertable(
                    id: "\(card.id)-exp",
                    label: "\(card.name) · Expiry",
                    value: exp
                ))
            }
            if let cvv = card.cvv, !cvv.isEmpty {
                out.append(CardInsertable(
                    id: "\(card.id)-cvv",
                    label: "\(card.name) · CVV",
                    value: cvv
                ))
            }
            if let holder = card.cardholderName, !holder.isEmpty {
                out.append(CardInsertable(
                    id: "\(card.id)-name",
                    label: "\(card.name) · Cardholder",
                    value: holder
                ))
            }
        }
        return out
    }
}
