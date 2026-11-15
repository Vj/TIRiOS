'use strict';

/*
 * Observe outbound connect() calls in the Frida-attached app process.
 *
 * These events are not HTTP requests and are not one-to-one mitmproxy flow
 * identifiers. TIRiOS correlates them conservatively by destination and time.
 */
if (ObjC.available) {
    const bundleIdentifier = () => {
        try {
            const bundle = ObjC.classes.NSBundle.mainBundle();
            return bundle.bundleIdentifier().toString();
        } catch (_) {
            return '';
        }
    };

    const bytesAt = (address, length) => {
        const raw = new Uint8Array(address.readByteArray(length));
        return Array.from(raw);
    };

    const ipv4 = (bytes) => bytes.slice(4, 8).join('.');
    const ipv6 = (bytes) => {
        const words = [];
        for (let i = 8; i < 24; i += 2) {
            words.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
        }
        return words.join(':');
    };

    const connectPtr = Module.findExportByName('libSystem.B.dylib', 'connect');
    const getSockNamePtr = Module.findExportByName('libSystem.B.dylib', 'getsockname');
    const getSockName = getSockNamePtr
        ? new NativeFunction(getSockNamePtr, 'int', ['int', 'pointer', 'pointer'])
        : null;

    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter(args) {
                try {
                    const sockaddr = args[1];
                    const length = args[2].toInt32();
                    if (sockaddr.isNull() || length < 8) return;

                    const family = sockaddr.add(1).readU8();
                    const bytes = bytesAt(sockaddr, Math.min(length, 28));
                    let destinationIp = '';
                    let destinationPort = 0;

                    // Darwin sockaddr_in: family, port (network byte order), IPv4 address.
                    if (family === 2 && length >= 8) {
                        destinationPort = (bytes[2] << 8) | bytes[3];
                        destinationIp = ipv4(bytes);
                    // Darwin sockaddr_in6 uses AF_INET6=30.
                    } else if (family === 30 && length >= 24) {
                        destinationPort = (bytes[2] << 8) | bytes[3];
                        destinationIp = ipv6(bytes);
                    } else {
                        return;
                    }

                    let localIp = '';
                    let localPort = 0;
                    if (getSockName) {
                        const localSockaddr = Memory.alloc(128);
                        const localLength = Memory.alloc(4);
                        localLength.writeU32(128);
                        if (getSockName(args[0].toInt32(), localSockaddr, localLength) === 0) {
                            const localBytes = bytesAt(localSockaddr, Math.min(localLength.readU32(), 28));
                            const localFamily = localSockaddr.add(1).readU8();
                            if (localFamily === 2 && localBytes.length >= 8) {
                                localPort = (localBytes[2] << 8) | localBytes[3];
                                localIp = ipv4(localBytes);
                            } else if (localFamily === 30 && localBytes.length >= 24) {
                                localPort = (localBytes[2] << 8) | localBytes[3];
                                localIp = ipv6(localBytes);
                            }
                        }
                    }

                    send({
                        category: 'TIR_NETWORK_EVENT',
                        syscall: 'connect',
                        process_id: Process.id,
                        bundle_id: bundleIdentifier(),
                        timestamp: Date.now() / 1000.0,
                        socket_fd: args[0].toInt32(),
                        local_ip: localIp,
                        local_port: localPort,
                        destination_ip: destinationIp,
                        destination_port: destinationPort
                    });
                } catch (e) {
                    send({ category: 'TIR_DEBUG', error: 'connect observer: ' + e.message });
                }
            }
        });
    } else {
        send({ category: 'TIR_DEBUG', error: 'connect() export not found' });
    }
}
