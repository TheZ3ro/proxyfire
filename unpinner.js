///////////////////////////////////////////////////////////////////////////

// The following function is a modified version of the Frida script at:
// https://github.com/azenla/AppleCache/blob/main/tools/frida-ssl-pin.js
function inject_macOS_unpinning_hooks() {
    var SSL_CTX_set_custom_verify_handle =
        Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
    var SSL_get_psk_identity_handle =
        Module.findExportByName('libboringssl.dylib', 'SSL_get_psk_identity');
    var boringssl_context_set_verify_mode_handle = Module.findExportByName(
        'libboringssl.dylib', 'boringssl_context_set_verify_mode');
    var SSL_VERIFY_NONE = 0;

    if (SSL_CTX_set_custom_verify_handle) {
        var SSL_CTX_set_custom_verify = new NativeFunction(
            SSL_CTX_set_custom_verify_handle, 'void', ['pointer', 'int', 'pointer']);

        var replaced_callback = new NativeCallback(function(ssl, out) {
            console.log('[*] Called custom SSL verifier')
            return SSL_VERIFY_NONE;
        }, 'int', ['pointer', 'pointer']);

        Interceptor.replace(
            SSL_CTX_set_custom_verify_handle,
            new NativeCallback(function(ctx, mode, callback) {
                console.log('[*] Called SSL_CTX_set_custom_verify()');
                SSL_CTX_set_custom_verify(ctx, 0, replaced_callback);
            }, 'void', ['pointer', 'int', 'pointer']));
        console.log('[+] SSL_CTX_set_custom_verify() hook installed.')
    }

    if (SSL_get_psk_identity_handle) {
        Interceptor.replace(
            SSL_get_psk_identity_handle, new NativeCallback(function(ssl) {
                console.log('[*] Called SSL_get_psk_identity_handle()');
                return 'notarealPSKidentity';
            }, 'pointer', ['pointer']));
        console.log('[+] SSL_get_psk_identity() hook installed.')
    }

    if (boringssl_context_set_verify_mode_handle) {
        var boringssl_context_set_verify_mode = new NativeFunction(
            boringssl_context_set_verify_mode_handle, 'int', ['pointer', 'pointer']);

        Interceptor.replace(
            boringssl_context_set_verify_mode_handle,
            new NativeCallback(function(a, b) {
                console.log('[*] Called boringssl_context_set_verify_mode()');
                return SSL_VERIFY_NONE;
            }, 'int', ['pointer', 'pointer']));
        console.log('[+] boringssl_context_set_verify_mode() hook installed.')
    }
}

///////////////////////////////////////////////////////////////////////////

// The following function is a modified version of the Frida script at:
// https://github.com/NVISOsecurity/disable-flutter-tls-verification
function inject_flutter_unpinning_hooks() {
    var config = {
        "ios":{
            "modulename": "Flutter",
            "patterns":{
                "arm64": [
                    "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F9 ?8 1? 40 F9 15 ?? 4? F9 B5 00 00 B4",
                ],
            },
        }
    };

    // Flag to check if TLS validation has already been disabled
    var TLSValidationDisabled = false;

    // Attempt to disable TLS validation immediately and then again after a 2 second delay
    disableTLSValidation();
    setTimeout(disableTLSValidation, 2000, true);

    // Main function to disable TLS validation for Flutter
    function disableTLSValidation(fallback=false) {
        if (TLSValidationDisabled) return;

        var platformConfig = config["ios"];
        var m = Process.findModuleByName(platformConfig["modulename"]);

        // If there is no loaded Flutter module, the setTimeout may trigger a second time, but after that we give up
        if (m === null) {
            if (fallback) console.log("[!] Flutter module not found.");
            return;
        }

        if (Process.arch in platformConfig["patterns"])
        {
            findAndPatch(m, platformConfig["patterns"][Process.arch], Java.available && Process.arch == "arm" ? 1 : 0, fallback);
        }
        else
        {
            console.log("[!] Processor architecture not supported: ", Process.arch);
        }

        if (!TLSValidationDisabled)
        {
            if (fallback){
                if(m.enumerateRanges('r-x').length == 0)
                {
                    console.log('[!] No memory ranges found in Flutter library. This is either a Frida bug, or the application is using some kind of RASP. Try using Frida as a Gadget or using an older Android version (https://github.com/frida/frida/issues/2266)');
                }
                else
                {
                    console.log('[!] ssl_verify_peer_cert not found. Please open an issue at https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues');
                }
            }
            else
            {
                console.log('[!] ssl_verify_peer_cert not found. Trying again...');
            }
        }
    }

    // Find and patch the method in memory to disable TLS validation
    function findAndPatch(m, patterns, thumb, fallback) {
        console.log("[+] Flutter library found");
        var ranges = m.enumerateRanges('r-x');
        ranges.forEach(range => {
            patterns.forEach(pattern => {
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: function(address, size) {
                        console.log('[+] ssl_verify_peer_cert found at offset: 0x' + (address - m.base).toString(16));
                        TLSValidationDisabled = true;
                        hook_ssl_verify_peer_cert(address.add(thumb));
                    }
                });
            });
        });
    }

    // Replace the target function's implementation to effectively disable the TLS check
    function hook_ssl_verify_peer_cert(address) {
        Interceptor.replace(address, new NativeCallback((pathPtr, flags) => {
            return 0;
        }, 'int', ['pointer', 'int']));
    }
}

inject_macOS_unpinning_hooks();
inject_flutter_unpinning_hooks();