import TunnelKitCore
import WireGuardKitGo
import TunnelKitWireGuardCore
import TunnelKitWireGuardManager
import WireGuardKit
import __TunnelKitUtils
import SwiftyBeaver

// SPDX-License-Identifier: MIT
// Copyright © 2018-2021 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import os

open class WireGuardTunnelProvider: NEPacketTunnelProvider {
    
    private var cfg: WireGuard.ProviderConfiguration!

    /// The number of milliseconds between data count updates. Set to 0 to disable updates (default).
    public var dataCountInterval = 0

    /// Once the tunnel starts, enable this property to update connection stats
    private var tunnelIsStarted = false

    private let tunnelQueue = DispatchQueue(label: WireGuardTunnelProvider.description(), qos: .utility)

    private lazy var adapter: WireGuardAdapter = {
        return WireGuardAdapter(with: self){ logLevel, message in
            wg_log(logLevel.osLogLevel, message: message)
        }
    }()

    open override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {

        // BEGIN: TunnelKit

        guard let tunnelProviderProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
            fatalError("Not a NETunnelProviderProtocol")
        }
        guard let providerConfiguration = tunnelProviderProtocol.providerConfiguration else {
            fatalError("Missing providerConfiguration")
        }

        let tunnelConfiguration: TunnelConfiguration
        do {
            cfg = try fromDictionary(WireGuard.ProviderConfiguration.self, providerConfiguration)
            tunnelConfiguration = cfg.configuration.tunnelConfiguration
        } catch {
            completionHandler(TunnelKitWireGuardError.savedProtocolConfigurationIsInvalid)
            return
        }

        configureLogging()

        // END: TunnelKit

        // Start the tunnel
        adapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
            guard let self else {
                completionHandler(nil)
                return
            }

            guard let adapterError = adapterError else {
                let interfaceName = self.adapter.interfaceName ?? "unknown"

                wg_log(.info, message: "Tunnel interface is \(interfaceName)")
                self.tunnelQueue.async {
                    self.tunnelIsStarted = true
                    self.refreshDataCount()
                }
                completionHandler(nil)
                #if os(macOS)
                // CopVPN: with includeAllNetworks (Kill switch) macOS drops traffic while
                // the tunnel comes up, which can eat WireGuard's first handshake and cost its
                // 5 s retry before any traffic flows. Re-apply the peers once the tunnel is
                // up: a fresh peer isn't handshake-rate-limited, so the next packet
                // re-handshakes straight away. Only when no handshake has completed:
                // re-applying drops a working session's keys, and its new handshake can be
                // lost while the settings re-apply — a 5 s outage right after connecting.
                if tunnelProviderProtocol.includeAllNetworks {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in
                        self?.adapter.getRuntimeConfiguration { runtime in
                            guard let self, !WireGuard.hasHandshake(runtimeConfiguration: runtime) else { return }
                            self.adapter.update(tunnelConfiguration: tunnelConfiguration) { error in
                                if let error {
                                    wg_log(.error, message: "Handshake refresh failed: \(error.localizedDescription)")
                                }
                            }
                        }
                    }
                }
                #endif
                return
            }

            switch adapterError {
            case .cannotLocateTunnelFileDescriptor:
                wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
                self.cfg._appexSetLastError(.couldNotDetermineFileDescriptor)
                completionHandler(TunnelKitWireGuardError.couldNotDetermineFileDescriptor)

            case .dnsResolution(let dnsErrors):
                let hostnamesWithDnsResolutionFailure = dnsErrors.map(\.address)
                    .joined(separator: ", ")
                wg_log(.error, message: "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure)")
                self.cfg._appexSetLastError(.dnsResolutionFailure)
                completionHandler(TunnelKitWireGuardError.dnsResolutionFailure)

            case .setNetworkSettings(let error):
                wg_log(.error, message: "Starting tunnel failed with setTunnelNetworkSettings returning \(error.localizedDescription)")
                self.cfg._appexSetLastError(.couldNotSetNetworkSettings)
                completionHandler(TunnelKitWireGuardError.couldNotSetNetworkSettings)

            case .startWireGuardBackend(let errorCode):
                wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
                self.cfg._appexSetLastError(.couldNotStartBackend)
                completionHandler(TunnelKitWireGuardError.couldNotStartBackend)

            case .invalidState:
                // Must never happen
                fatalError()
            }
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wg_log(.info, staticMessage: "Stopping tunnel")

        adapter.stop { [weak self] error in

            // BEGIN: TunnelKit

            guard let self else {
                completionHandler()
                return
            }
            // CopVPN: finish synchronously and report the stop BEFORE the macOS exit(0)
            // below. Completing on tunnelQueue.async let the process exit first, so
            // macOS logged "died unexpectedly" and waited its 5 s exit timer on every
            // disconnect. Upstream wireguard-apple calls completionHandler() first too.
            self.tunnelQueue.sync {
                self.cfg._appexSetLastError(nil)
                self.tunnelIsStarted = false
            }
            if let error = error {
                wg_log(.error, message: "Failed to stop WireGuard adapter: \(error.localizedDescription)")
            }
            completionHandler()

            // END: TunnelKit

            #if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
            #endif
        }
    }

    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else {
            return
        }

        if messageData.count == 1 && messageData[0] == 0 {
            adapter.getRuntimeConfiguration { settings in
                var data: Data?
                if let settings = settings {
                    data = settings.data(using: .utf8)!
                }
                completionHandler(data)
            }
        } else if let newCfg = WireGuard.ProviderConfiguration.fromSwitchMessage(messageData) {
            // CopVPN: switch servers IN PLACE. update() swaps keys, peers, addresses and
            // DNS on the live tunnel (replace_peers), so traffic never leaves it — the
            // app's stop/start switch exposed the real IP for ~1.3 s with Kill switch off.
            adapter.update(tunnelConfiguration: newCfg.configuration.tunnelConfiguration) { [weak self] error in
                if let error {
                    wg_log(.error, message: "In-place switch failed: \(error)")
                    completionHandler(nil)
                    return
                }
                self?.tunnelQueue.async { self?.cfg = newCfg }
                completionHandler(Data([WireGuard.ProviderConfiguration.switchMessageTag]))
            }
        } else {
            completionHandler(nil)
        }
    }

    // MARK: Data counter (tunnel queue)

    // XXX: thread-safety here is poor, but we know that:
    //
    // - dataCountInterval is virtually constant, set on tunnel creation
    // - cfg only modifies UserDefaults, which is thread-safe
    // - adapter, used in fetchDataCount, is thread-safe
    //
    private func refreshDataCount() {
        guard dataCountInterval > 0 else {
            return
        }

        tunnelQueue.schedule(after: DispatchTimeInterval.milliseconds(dataCountInterval)) { [weak self] in
            self?.refreshDataCount()
        }

        guard tunnelIsStarted else {
            cfg._appexSetDataCount(nil)
            return
        }
        fetchDataCount { [weak self] result in
            guard let self else {
                return
            }
            switch result {
            case .success(let dataCount):
                self.cfg._appexSetDataCount(dataCount)
            case .failure(let error):
                wg_log(.error, message: "Failed to refresh data count \(error.localizedDescription)")
            }
        }
    }
}

private extension WireGuardTunnelProvider {
    enum StatsError: Error {
         case parseFailure
    }

    func configureLogging() {
        let logLevel: SwiftyBeaver.Level = (cfg.shouldDebug ? .debug : .info)
        let logFormat = cfg.debugLogFormat ?? "$Dyyyy-MM-dd HH:mm:ss.SSS$d $L $N.$F:$l - $M"

        if cfg.shouldDebug {
            let console = ConsoleDestination()
            console.useNSLog = true
            console.minLevel = logLevel
            console.format = logFormat
            SwiftyBeaver.addDestination(console)
        }

        let file = FileDestination(logFileURL: cfg._appexDebugLogURL)
        file.minLevel = logLevel
        file.format = logFormat
        file.logFileMaxSize = 20000
        SwiftyBeaver.addDestination(file)

        // store path for clients
        cfg._appexSetDebugLogPath()
    }

    func fetchDataCount(completiondHandler: @escaping (Result<DataCount, Error>) -> Void) {
        adapter.getRuntimeConfiguration { configurationString in
            if let configurationString = configurationString,
               let wireGuardDataCount = DataCount.from(wireGuardString: configurationString) {
                completiondHandler(.success(wireGuardDataCount))
            } else {
                completiondHandler(.failure(StatsError.parseFailure))
            }
         }
    }
}
//extension WireGuardTunnelProvider: WireGuardAdapterDelegate {
//    public func adapterShouldReassert(_ adapter: WireGuardAdapter, reasserting: Bool) {
//        self.reasserting = reasserting
//    }
//
//    public func adapterShouldSetNetworkSettings(_ adapter: WireGuardAdapter, settings: NEPacketTunnelNetworkSettings, completionHandler: (((any Error)?) -> Void)?) {
//        setTunnelNetworkSettings(settings, completionHandler: completionHandler)
//    }
//}
extension WireGuardLogLevel {
    var osLogLevel: OSLogType {
        switch self {
        case .verbose:
            return .debug
        case .error:
            return .error
        }
    }
}
