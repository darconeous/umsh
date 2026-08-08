import SwiftUI
import UIKit

/// Why the composer cannot accept a message, and what to call the way out of
/// it. Both strings come from the thread view, which is what knows the radio's
/// state; the composer only knows it has nothing to offer but an explanation.
struct ComposerBlock: Equatable {
    let reason: String
    let actionLabel: String
}

/// Where a message is written: a capsule field floating over the transcript,
/// or — with nothing able to carry a message — the reason and the way to fix
/// it.
///
/// The field is replaced rather than disabled, because a composer that takes
/// text it will not send invites the reader to write something that quietly
/// goes nowhere. What they actually need is a radio, and from here that is one
/// tap away.
struct MessageComposer: View {
    @Binding var draft: String
    /// Names who is being written to, in the empty field.
    let placeholder: String
    /// How well the conversation being written to is protected. The send
    /// button carries the same colour the message will land in, so the answer
    /// is in front of the writer before they send rather than after.
    let security: ConversationSecurity
    let blocked: ComposerBlock?
    /// Whether a send this instant would go somewhere. False in the transient
    /// link states — a reconnect, an attach in progress — where the field
    /// stays put so typing is not interrupted, and only the send button waits.
    let canSend: Bool
    let send: () async -> Void

    @Environment(\.openRadioDetail) private var openRadioDetail

    /// Whether there is anything worth sending, which is also what decides
    /// whether the send button exists at all.
    private var hasDraft: Bool {
        !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        Group {
            if let blocked {
                unavailable(blocked)
            } else {
                field
            }
        }
        .padding(.horizontal, 12)
        // Room above the field for the bar to fade out in. The bar is anchored
        // to the bottom edge, so this is what makes it taller; what sets how
        // low the controls sit is the padding beneath them. The few points
        // kept there are not cosmetic: on a home-button phone the bottom safe
        // area is zero, and with the keyboard up its top edge is the inset on
        // any phone — this is all that keeps the field off both.
        .padding(.top, 28)
        .padding(.bottom, 4)
        // The bar floats over the transcript, carrying on down through the
        // home indicator rather than leaving a bare strip where the tab bar
        // used to be, and fading upward so the messages passing under it are
        // not cut off at a line.
        .fadingBar(edge: .bottom)
    }

    private var field: some View {
        ZStack(alignment: .topLeading) {
            HardwareAwareMessageEditor(
                text: $draft,
                trailingTextInset: 34,
                onHardwareReturn: { Task { await send() } }
            )
            if draft.isEmpty {
                Text(placeholder)
                    .foregroundStyle(.tertiary)
                    .padding(.horizontal, HardwareAwareMessageEditor.leadingTextInset)
                    .padding(.vertical, HardwareAwareMessageEditor.verticalTextInset)
                    .allowsHitTesting(false)
            }
        }
        .background {
            Capsule()
                .stroke(Color(uiColor: .separator), lineWidth: 0.5)
        }
        .overlay(alignment: .bottomTrailing) {
            // Absent rather than disabled while the field is empty, as in
            // Messages: the button arriving is what says the message is ready
            // to go, and a permanently dimmed control says nothing at all.
            if hasDraft {
                Button {
                    Task { await send() }
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 28))
                        // Dimmed rather than removed while the link is in
                        // flux: absence means "nothing to send", and there is
                        // something to send — it just has to wait a moment.
                        .foregroundStyle(
                            .white,
                            canSend ? security.tint : Color(uiColor: .systemGray3)
                        )
                }
                // The glyph is the button. Left to the default style it picks
                // up the system's own background — a grey rounded square sitting
                // behind the circle, which reads as a second control.
                .buttonStyle(.plain)
                .disabled(!canSend)
                .padding(2)
                .transition(.scale.combined(with: .opacity))
                .accessibilityLabel(canSend ? "Send" : "Send unavailable while the radio connects")
            }
        }
        .animation(.spring(duration: 0.2), value: hasDraft)
    }

    private func unavailable(_ blocked: ComposerBlock) -> some View {
        VStack(spacing: 8) {
            Text(blocked.reason)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(blocked.actionLabel) { openRadioDetail() }
                .buttonStyle(.bordered)
                .controlSize(.small)
        }
        .frame(maxWidth: .infinity)
    }
}

/// UITextView keeps the software keyboard's Return key as a newline while
/// making physical-keyboard Return a send shortcut. SwiftUI's multiline
/// TextField consumes physical Return before `onKeyPress`, so it cannot
/// reliably express this distinction on its own.
struct HardwareAwareMessageEditor: UIViewRepresentable {
    /// Where the text starts inside the field, matched by the placeholder so
    /// the prompt sits exactly where the first character will.
    static let leadingTextInset: CGFloat = 12
    static let verticalTextInset: CGFloat = 7

    @Binding var text: String
    /// Room kept clear at the trailing edge for the send button, which sits
    /// inside the field rather than beside it.
    var trailingTextInset: CGFloat = 4
    let onHardwareReturn: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    func makeUIView(context: Context) -> HardwareAwareTextView {
        let textView = HardwareAwareTextView()
        textView.delegate = context.coordinator
        textView.backgroundColor = .clear
        textView.font = .preferredFont(forTextStyle: .body)
        textView.adjustsFontForContentSizeCategory = true
        textView.textContainerInset = textInsets
        textView.isScrollEnabled = true
        textView.onHardwareReturn = onHardwareReturn
        // A focused text view with a hardware keyboard attached raises the
        // shortcut bar, docked across the bottom of the window. On the Mac
        // runtime that bar lives outside this app's window and its frame never
        // reaches the safe area, so nothing moves out from under it and it
        // settles on top of the composer. Emptying the assistant item collapses
        // it. What that costs is the undo/redo/paste shortcuts, which only ever
        // appeared on the platforms that also had the collision.
        textView.inputAssistantItem.leadingBarButtonGroups = []
        textView.inputAssistantItem.trailingBarButtonGroups = []
        return textView
    }

    func updateUIView(_ textView: HardwareAwareTextView, context: Context) {
        if textView.text != text {
            textView.text = text
        }
        if textView.textContainerInset != textInsets {
            textView.textContainerInset = textInsets
        }
        textView.onHardwareReturn = onHardwareReturn
    }

    private var textInsets: UIEdgeInsets {
        UIEdgeInsets(
            top: Self.verticalTextInset,
            left: Self.leadingTextInset,
            bottom: Self.verticalTextInset,
            right: trailingTextInset
        )
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        uiView: HardwareAwareTextView,
        context: Context
    ) -> CGSize? {
        guard let width = proposal.width else { return nil }
        let measured = uiView.sizeThatFits(
            CGSize(width: width, height: .greatestFiniteMagnitude)
        )
        let lineHeight = uiView.font?.lineHeight ?? 17
        let minimumHeight = lineHeight + 14
        let maximumHeight = lineHeight * 6 + 14
        return CGSize(
            width: width,
            height: min(max(measured.height, minimumHeight), maximumHeight)
        )
    }

    final class Coordinator: NSObject, UITextViewDelegate {
        @Binding private var text: String

        init(text: Binding<String>) {
            _text = text
        }

        func textViewDidChange(_ textView: UITextView) {
            text = textView.text
        }
    }
}

final class HardwareAwareTextView: UITextView {
    var onHardwareReturn: (() -> Void)?

    override var keyCommands: [UIKeyCommand]? {
        // While an IME composition is in progress (marked text), Return
        // commits the composition. Stealing it would send a half-composed
        // message; queried per keypress, so stepping aside here hands the key
        // back to the system for exactly those moments.
        guard markedTextRange == nil else { return super.keyCommands }
        let send = UIKeyCommand(
            input: "\r",
            modifierFlags: [],
            action: #selector(sendFromHardwareKeyboard)
        )
        send.wantsPriorityOverSystemBehavior = true

        let newline = UIKeyCommand(
            input: "\r",
            modifierFlags: [.shift],
            action: #selector(insertNewlineFromHardwareKeyboard)
        )
        newline.wantsPriorityOverSystemBehavior = true
        return [send, newline]
    }

    @objc private func sendFromHardwareKeyboard() {
        onHardwareReturn?()
    }

    @objc private func insertNewlineFromHardwareKeyboard() {
        insertText("\n")
    }
}

struct MessageEditSheet: View {
    let originalBody: String
    @Binding var text: String
    let save: (String) async -> Void
    let cancel: () -> Void

    @FocusState private var editorFocused: Bool

    private var trimmed: String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        NavigationStack {
            TextEditor(text: $text)
                .focused($editorFocused)
                .padding(8)
                .navigationTitle("Edit Message")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { cancel() }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Save") {
                            Task { await save(trimmed) }
                        }
                        .disabled(trimmed.isEmpty || trimmed == originalBody)
                    }
                }
                .onAppear { editorFocused = true }
        }
        .presentationDetents([.medium, .large])
    }
}
