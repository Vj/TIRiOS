'use strict';

/*
 * Observe outbound connect() calls in the Frida-attached app process.
 * The local socket tuple is collected in onLeave, after connect() has had
 * an opportunity to allocate the local ephemeral port.
 */
if (ObjC.available) {
    const bundleIdentifier = () => {
        try {
            return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
        } catch (_) {
            return '';
        }
    };

    const readEndpoint = (address, length) => {
        const bytes = Array.from(new Uint8Array(address.readByteArray(Math.min(length, 28))));
        const family = address.add(1).readU8(); // Darwin sockaddr: sa_len then sa_family
        if (family === 2 && length >= 8) {
            return { ip: bytes.slice(4, 8).join('.'), port: (bytes[2] << 8) | bytes[3] };
        }
        if (family === 30 && length >= 24) {
            const words = [];
            for (let i = 8; i < 24; i += 2) words.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
            return { ip: words.join(':'), port: (bytes[2] << 8) | bytes[3] };
        }
        return null;
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
                    const endpoint = readEndpoint(sockaddr, length);
                    if (!endpoint) return;
                    this.socketFd = args[0].toInt32();
                    this.destinationIp = endpoint.ip;
                    this.destinationPort = endpoint.port;
                } catch (e) {
                    send({ category: 'TIR_DEBUG', error: 'connect observer onEnter: ' + e.message });
                }
            },
            onLeave(_retval) {
                if (this.socketFd === undefined) return;
                try {
                    let localIp = '';
                    let localPort = 0;
                    if (getSockName) {
                        const localSockaddr = Memory.alloc(128);
                        const localLength = Memory.alloc(4);
                        localLength.writeU32(128);
                        if (getSockName(this.socketFd, localSockaddr, localLength) === 0) {
                            const localLengthValue = localLength.readU32();
                            const local = readEndpoint(localSockaddr, localLengthValue);
                            if (local) { localIp = local.ip; localPort = local.port; }
                        }
                    }
                    send({
                        category: 'TIR_NETWORK_EVENT',
                        syscall: 'connect',
                        process_id: Process.id,
                        bundle_id: bundleIdentifier(),
                        timestamp: Date.now() / 1000.0,
                        socket_fd: this.socketFd,
                        local_ip: localIp,
                        local_port: localPort,
                        destination_ip: this.destinationIp,
                        destination_port: this.destinationPort
                    });
                } catch (e) {
                    send({ category: 'TIR_DEBUG', error: 'connect observer onLeave: ' + e.message });
                }
            }
        });
    } else {
        send({ category: 'TIR_DEBUG', error: 'connect() export not found' });
    }
}