//
//  NETunnelInterface.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 8/27/17.
//  Copyright (c) 2024 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

import Foundation
import NetworkExtension
import TunnelKitCore
import SwiftyBeaver

private let log = SwiftyBeaver.self

/// `TunnelInterface` implementation via NetworkExtension.
public class NETunnelInterface: TunnelInterface {
    private weak var impl: NEPacketTunnelFlow?

    /// CopVPN: offered each packet the device sends. A non-nil reply goes back to the device and the
    /// packet never enters the tunnel (on-device DNS blocking, "Block ads & trackers"). Set by the
    /// tunnel extension before the tunnel starts; nil passes everything, as before.
    public static var outboundFilter: ((Data) -> Data?)?

    /// CopVPN: rewrites each packet the device sends before it enters the tunnel, and each packet
    /// the tunnel delivers before the device sees it: a server switch keeps the tunnel's first
    /// address and maps it to the new server's here, so the system never re-applies its network
    /// settings (which briefly lets traffic out beside the tunnel). nil passes packets unchanged.
    public static var outboundTransform: ((Data) -> Data)?
    public static var inboundTransform: ((Data) -> Data)?

    public init(impl: NEPacketTunnelFlow) {
        self.impl = impl
    }

    // MARK: TunnelInterface

    public var isPersistent: Bool {
        return false
    }

    // MARK: IOInterface

    public func setReadHandler(queue: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {
        loopReadPackets(queue, handler)
    }

    private func loopReadPackets(_ queue: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {

        // WARNING: runs in NEPacketTunnelFlow queue
        impl?.readPackets { [weak self] (packets, _) in
            queue.sync {
                self?.loopReadPackets(queue, handler)
                let packets = NETunnelInterface.outboundTransform.map { packets.map($0) } ?? packets
                guard let filter = NETunnelInterface.outboundFilter else {
                    handler(packets, nil)
                    return
                }
                var passed: [Data] = []
                var replies: [Data] = []
                for packet in packets {
                    if let reply = filter(packet) { replies.append(reply) } else { passed.append(packet) }
                }
                if !replies.isEmpty { self?.writePackets(replies, completionHandler: nil) }
                if !passed.isEmpty { handler(passed, nil) }
            }
        }
    }

    public func writePacket(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        let packet = NETunnelInterface.inboundTransform?(packet) ?? packet
        let protocolNumber = IPHeader.protocolNumber(inPacket: packet)
        impl?.writePackets([packet], withProtocols: [protocolNumber])
        completionHandler?(nil)
    }

    public func writePackets(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let packets = NETunnelInterface.inboundTransform.map { packets.map($0) } ?? packets
        let protocols = packets.map {
            IPHeader.protocolNumber(inPacket: $0)
        }
        impl?.writePackets(packets, withProtocols: protocols)
        completionHandler?(nil)
    }
}
