'use strict';

if (ObjC.available) {
    const emitEvent = (checkType, location, evidence) => {
        send({
            category: 'TIR_RESILIENCE_EVENT',
            check_type: checkType,
            location: location,
            evidence: evidence
        });
    };

    const INSECURE_ACCESSIBILITY = new Set([
        'dk',   // kSecAttrAccessibleAlways
        'dku',  // kSecAttrAccessibleAlwaysThisDeviceOnly
        'ak',   // kSecAttrAccessibleWhenUnlocked (migratable across backups)
        'ck'    // kSecAttrAccessibleAfterFirstUnlock (migratable across backups)
    ]);

    // 1. Keychain Accessibility Flag Inspection (SecItemAdd / SecItemUpdate)
    ['SecItemAdd', 'SecItemUpdate'].forEach((fnName) => {
        const fnPtr = Module.findExportByName('Security', fnName);
        if (!fnPtr) return;

        Interceptor.attach(fnPtr, {
            onEnter(args) {
                try {
                    const dict = new ObjC.Object(args[0]);
                    if (!dict || !dict.objectForKey_) return;

                    const accessible = dict.objectForKey_('pdmn'); // kSecAttrAccessible
                    const service = dict.objectForKey_('svce');    // kSecAttrService
                    const account = dict.objectForKey_('acct');    // kSecAttrAccount

                    const accVal = accessible ? accessible.toString() : 'unset';
                    const svcVal = service ? service.toString() : 'unknown_service';
                    const acctVal = account ? account.toString() : 'unknown_account';

                    if (INSECURE_ACCESSIBILITY.has(accVal) || accVal === 'unset') {
                        emitEvent(
                            'KEYCHAIN_WEAK_ACCESSIBILITY',
                            `Security.framework ${fnName}`,
                            `Keychain item (service='${svcVal}', account='${acctVal}') stored with kSecAttrAccessible='${accVal}'`
                        );
                    }
                } catch (_) {}
            }
        });
    });

    // 2. Background Snapshot Protection Check
    let backgroundEntered = false;
    let windowModifiedOnBackground = false;

    const UIWindow = ObjC.classes.UIWindow;
    if (UIWindow && UIWindow['- setHidden:']) {
        Interceptor.attach(UIWindow['- setHidden:'].implementation, {
            onEnter() {
                if (backgroundEntered) windowModifiedOnBackground = true;
            }
        });
    }

    const UIView = ObjC.classes.UIView;
    if (UIView && UIView['- addSubview:']) {
        Interceptor.attach(UIView['- addSubview:'].implementation, {
            onEnter() {
                if (backgroundEntered) windowModifiedOnBackground = true;
            }
        });
    }

    ['UIApplicationWillResignActiveNotification', 'UISceneWillDeactivateNotification'].forEach((notifName) => {
        const NSNotificationCenter = ObjC.classes.NSNotificationCenter;
        if (NSNotificationCenter && NSNotificationCenter['- postNotificationName:object:userInfo:']) {
            Interceptor.attach(NSNotificationCenter['- postNotificationName:object:userInfo:'].implementation, {
                onEnter(args) {
                    const name = new ObjC.Object(args[2]).toString();
                    if (name === notifName) {
                        backgroundEntered = true;
                        windowModifiedOnBackground = false;
                        setTimeout(() => {
                            if (!windowModifiedOnBackground) {
                                emitEvent(
                                    'SNAPSHOT_NOT_OBSCURED',
                                    name,
                                    `App transitioned to background (${name}) without adding a privacy overlay or hiding sensitive windows`
                                );
                            }
                            backgroundEntered = false;
                        }, 150);
                    }
                }
            });
        }
    });

    // 3. Passive Telemetry for Jailbreak & Anti-Debugging Defenses
    const telemetry = {
        sawJailbreakCheck: false,
        sawAntiDebugCheck: false
    };

    const JB_PATHS = ['/Applications/Cydia.app', '/Library/MobileSubstrate', '/bin/bash', '/usr/sbin/sshd', '/var/jb'];
    ['stat', 'stat64', 'access', 'fopen'].forEach((fnName) => {
        const ptr = Module.findExportByName('libSystem.B.dylib', fnName);
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter(args) {
                try {
                    const path = args[0].readUtf8String();
                    if (path && JB_PATHS.some((jb) => path.includes(jb))) {
                        telemetry.sawJailbreakCheck = true;
                    }
                } catch (_) {}
            }
        });
    });

    const sysctlPtr = Module.findExportByName('libSystem.B.dylib', 'sysctl');
    if (sysctlPtr) {
        Interceptor.attach(sysctlPtr, {
            onEnter(args) {
                try {
                    // CTL_KERN (1), KERN_PROC (14), KERN_PROC_PID (1)
                    const mib0 = args[0].readS32();
                    const mib1 = args[0].add(4).readS32();
                    if (mib0 === 1 && mib1 === 14) {
                        telemetry.sawAntiDebugCheck = true;
                    }
                } catch (_) {}
            }
        });
    }

    const ptracePtr = Module.findExportByName('libSystem.B.dylib', 'ptrace');
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter(args) {
                if (args[0].toInt32() === 31) { // PT_DENY_ATTACH
                    telemetry.sawAntiDebugCheck = true;
                }
            }
        });
    }

    rpc.exports = {
        getTelemetrySummary() {
            return telemetry;
        }
    };
}