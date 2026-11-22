import CoreTransferable
import SwiftUI
import UMSHMobileCore
import UniformTypeIdentifiers

/// This launch's log lines and the versions support asks for, with an
/// export through the share sheet. The page is the export's preview.
struct DiagnosticsView: View {
    let radio: RadioSnapshot

    private enum Read: Equatable {
        case reading
        case read([DiagnosticsEntry])
        case unreadable
    }

    private enum Filter: Hashable {
        case all, errors
    }

    @State private var read: Read = .reading
    @State private var filter: Filter = .all

    var body: some View {
        List {
            versions
            log
        }
        .navigationTitle(Text("Diagnostics", comment: "Title of the page that shows this launch's log and the app's and radio's versions."))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if case let .read(entries) = read {
                    ShareLink(
                        item: DiagnosticsExport(radio: radio, entries: entries),
                        preview: SharePreview(Text("Diagnostics", comment: "Title of the page that shows this launch's log and the app's and radio's versions."))
                    ) {
                        Text("Export", comment: "Button: shares this launch's diagnostics log as a text file.")
                    }
                    .accessibilityIdentifier("diagnostics.export")
                } else {
                    Button {} label: {
                        Text("Export", comment: "Button: shares this launch's diagnostics log as a text file.")
                    }
                    .disabled(true)
                    .accessibilityIdentifier("diagnostics.export")
                }
            }
        }
        .task { await reload() }
        .refreshable { await reload() }
    }

    private var versions: some View {
        Section {
            LabeledContent {
                Text(verbatim: DiagnosticsHeader.appVersion)
            } label: {
                Text(verbatim: "UMSH")
            }
            LabeledContent {
                Text(verbatim: String(mobileApiVersion()))
            } label: {
                Text("Core API", comment: "Diagnostics row: the version of the app's mesh core interface.")
            }
            if let provisioning = radio.provisioning {
                if let firmware = provisioning.deviceVersion {
                    LabeledContent {
                        Text(verbatim: firmware)
                    } label: {
                        Text("Radio firmware", comment: "Diagnostics row: the firmware version the companion radio reports.")
                    }
                }
                if let model = provisioning.deviceModel {
                    LabeledContent {
                        Text(verbatim: model)
                    } label: {
                        Text("Radio model", comment: "Diagnostics row: the hardware the companion radio reports.")
                    }
                }
                if let ulcp = provisioning.protocolVersion {
                    LabeledContent {
                        Text(verbatim: "\(ulcp.major).\(ulcp.minor)")
                    } label: {
                        Text(verbatim: "ULCP")
                    }
                }
                LabeledContent {
                    Text(provisioning.capabilityCount, format: .number)
                } label: {
                    Text("Capabilities", comment: "Row label: how many optional features the radio says it supports.")
                }
            }
        } header: {
            Text("Versions", comment: "Diagnostics section header: the app's, core's and radio's versions.")
        }
    }

    private var log: some View {
        Section {
            Picker(selection: $filter) {
                Text("All", comment: "Diagnostics log filter: every line.").tag(Filter.all)
                Text("Errors", comment: "Diagnostics log filter: only error and fault lines.").tag(Filter.errors)
            } label: {
                Text("Show", comment: "Label of a list filter picker: Map, Peers, and the Diagnostics log.")
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityIdentifier("diagnostics.filter")

            switch read {
            case .reading:
                ProgressView()
                    .frame(maxWidth: .infinity)
            case .unreadable:
                Text("The log can't be read.", comment: "Shown on the Diagnostics page when the system log store will not open.")
                    .foregroundStyle(.secondary)
            case let .read(entries):
                let shown = entries.reversed().filter { filter == .all || $0.level.isError }
                if shown.isEmpty {
                    ContentUnavailableView {
                        Label {
                            Text("No Log Entries", comment: "Shown on the Diagnostics page when there are no log lines to show.")
                        } icon: {
                            Image(systemName: "doc.text")
                        }
                    }
                } else {
                    ForEach(shown) { entry in
                        DiagnosticsEntryRow(entry: entry)
                    }
                }
            }
        } header: {
            Text("Log", comment: "Diagnostics section header: the lines the app logged since it launched.")
        }
    }

    private func reload() async {
        do {
            read = .read(try await DiagnosticsLog.read(since: DiagnosticsLog.launchDate))
        } catch {
            read = .unreadable
        }
    }
}

private struct DiagnosticsEntryRow: View {
    let entry: DiagnosticsEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                if entry.level.isError {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .accessibilityLabel(Text("Error", comment: "Accessibility label of the mark on an error line in the diagnostics log."))
                }
                Text(entry.date, format: .dateTime.hour().minute().second())
                Text(verbatim: entry.category)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .font(.caption.monospaced())
            .foregroundStyle(.secondary)
            Text(verbatim: entry.message)
                .font(.caption.monospaced())
                .foregroundStyle(entry.level.isError ? AnyShapeStyle(.red) : AnyShapeStyle(.primary))
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("diagnostics.entry")
    }
}

/// The export, written when the share sheet asks for it, so its header
/// says when it was made.
struct DiagnosticsExport: Transferable, Sendable {
    let radio: RadioSnapshot
    let entries: [DiagnosticsEntry]

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .plainText) { export in
            let header = DiagnosticsHeader(radio: export.radio, launched: DiagnosticsLog.launchDate, exported: .now)
            let folder = URL.temporaryDirectory.appending(path: "Diagnostics", directoryHint: .isDirectory)
            return SentTransferredFile(try DiagnosticsLog.write(header: header, entries: export.entries, into: folder))
        }
    }
}
