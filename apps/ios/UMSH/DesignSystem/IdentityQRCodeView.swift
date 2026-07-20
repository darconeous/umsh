import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

/// Renders a UMSH identity URI as a scannable QR code with the shareable
/// URI and a copy control underneath.
struct IdentityShareView: View {
    let uri: String
    @State private var copied = false

    var body: some View {
        VStack(spacing: 12) {
            IdentityQRCodeView(uri: uri)
            Text(uri)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                UIPasteboard.general.string = uri
                copied = true
            } label: {
                Label(copied ? "Copied" : "Copy Identity URI",
                      systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }
}

/// The QR code itself. Generation runs off the render path and the result is
/// cached per URI so scrolling the containing list stays cheap.
struct IdentityQRCodeView: View {
    let uri: String
    @State private var image: UIImage?

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
            } else {
                Image(systemName: "qrcode")
                    .resizable()
                    .scaledToFit()
                    .foregroundStyle(.quaternary)
            }
        }
        .frame(width: 200, height: 200)
        .accessibilityLabel("Identity QR code")
        .task(id: uri) {
            let uri = uri
            image = await Task.detached(priority: .userInitiated) {
                Self.qrImage(for: uri)
            }.value
        }
    }

    private nonisolated static func qrImage(for uri: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(uri.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        guard let cgImage = CIContext().createCGImage(output, from: output.extent) else {
            return nil
        }
        return UIImage(cgImage: cgImage)
    }
}
