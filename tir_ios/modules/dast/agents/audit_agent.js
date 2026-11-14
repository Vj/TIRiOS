'use strict';

if (ObjC.available) {
    const emitFinding = (checkType, location, evidence) => {
        send({
            category: 'TIR_DAST_EVENT',
            check_type: checkType,
            location: location,
            evidence: evidence
        });
    };

    // 1. WKWebView Configuration & JS Bridge Audit
    try {
        const WKUserContentController = ObjC.classes.WKUserContentController;
        if (WKUserContentController) {
            const addHandler = WKUserContentController['- addScriptMessageHandler:name:'];
            Interceptor.attach(addHandler.implementation, {
                onEnter(args) {
                    const handlerObj = new ObjC.Object(args[2]);
                    const bridgeName = new ObjC.Object(args[3]).toString();
                    emitFinding(
                        'WEBVIEW_JS_BRIDGE',
                        'WKUserContentController -addScriptMessageHandler:name:',
                        `Exposed native JS bridge '${bridgeName}' handled by ${handlerObj.$className}`
                    );
                }
            });
        }

        const WKPreferences = ObjC.classes.WKPreferences;
        if (WKPreferences && WKPreferences['- setValue:forKey:']) {
            Interceptor.attach(WKPreferences['- setValue:forKey:'].implementation, {
                onEnter(args) {
                    const val = new ObjC.Object(args[2]).toString();
                    const key = new ObjC.Object(args[3]).toString();
                    if (key === 'allowFileAccessFromFileURLs' && (val === '1' || val.toLowerCase() === 'true')) {
                        emitFinding(
                            'WEBVIEW_FILE_ACCESS',
                            'WKPreferences -setValue:forKey:',
                            'allowFileAccessFromFileURLs enabled on WKWebView preferences'
                        );
                    }
                }
            });
        }
    } catch (e) {
        send({ category: 'TIR_DEBUG', error: `WKWebView hook error: ${e.message}` });
    }

    // 2. LAContext Biometric Policy Usage Audit
    try {
        const LAContext = ObjC.classes.LAContext;
        let sawKeychainAccessControl = false;

        const secAccessControl = Module.findExportByName('Security', 'SecAccessControlCreateWithFlags');
        if (secAccessControl) {
            Interceptor.attach(secAccessControl, {
                onEnter() {
                    sawKeychainAccessControl = true;
                }
            });
        }

        if (LAContext && LAContext['- evaluatePolicy:localizedReason:reply:']) {
            Interceptor.attach(LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
                onEnter(args) {
                    const policy = args[2].toInt32(); // 1 = Biometrics, 2 = DeviceOwnerAuthentication
                    const reason = new ObjC.Object(args[3]).toString();
                    if (!sawKeychainAccessControl) {
                        emitFinding(
                            'BIOMETRIC_BOOLEAN_ONLY',
                            'LAContext -evaluatePolicy:localizedReason:reply:',
                            `Policy=${policy} invoked with reason="${reason}" without prior SecAccessControlCreateWithFlags Keychain binding`
                        );
                    }
                }
            });
        }
    } catch (e) {
        send({ category: 'TIR_DEBUG', error: `LAContext hook error: ${e.message}` });
    }

    // 3. Global UIPasteboard Leakage Check
    try {
        const UIPasteboard = ObjC.classes.UIPasteboard;
        if (UIPasteboard && UIPasteboard['- setString:']) {
            Interceptor.attach(UIPasteboard['- setString:'].implementation, {
                onEnter(args) {
                    const boardName = new ObjC.Object(args[0]).name().toString();
                    const copiedText = new ObjC.Object(args[2]).toString();
                    if (boardName === 'com.apple.UIKit.pboard.general' && copiedText.length >= 6) {
                        emitFinding(
                            'PASTEBOARD_GLOBAL_WRITE',
                            'UIPasteboard -setString:',
                            `Wrote ${copiedText.length} chars to global general pasteboard without expiration/localOnly options`
                        );
                    }
                }
            });
        }
    } catch (e) {
        send({ category: 'TIR_DEBUG', error: `UIPasteboard hook error: ${e.message}` });
    }
}