/*
              ██                                    ██                ██                
              ████                  ██                                ████        ██    
  ██          ████                              ██                    ████              
            ██████        ██      ██            ██                  ██████      ██      
  ██      ██▒▒▒▒████    ██        ████        ██████              ██▒▒▒▒████    ████    
████      ██▒▒░░▒▒██  ████      ██████        ██▒▒██              ██▒▒░░▒▒██  ██████    
██████  ██▒▒░░░░▒▒██  ████      ██▒▒▒▒██    ██▒▒░░▒▒██████      ██▒▒░░░░▒▒██  ██▒▒▒▒██  
██▒▒▒▒████▒▒░░▒▒██████▒▒▒▒██  ████░░▒▒██    ██▒▒░░▒▒██▒▒▒▒██    ██▒▒░░▒▒████████░░▒▒██  
▒▒░░▒▒████▒▒░░▒▒████▒▒░░▒▒██  ██▒▒░░▒▒██    ██░░░░▒▒▒▒░░░░▒▒██████▒▒░░▒▒██████▒▒░░▒▒████
░░░░▒▒██▒▒░░▒▒██████▒▒░░▒▒████▒▒░░░░▒▒██  ██▒▒░░▒▒██▒▒▒▒░░▒▒████▒▒░░▒▒██████▒▒░░░░▒▒████
░░░░▒▒██▒▒░░░░████▒▒░░░░▒▒████▒▒░░░░▒▒██████▒▒░░▒▒████▒▒░░░░▒▒██▒▒░░░░██████▒▒░░░░▒▒████
▒▒░░▒▒████░░░░▒▒██▒▒▒▒░░░░▒▒████▒▒░░░░▒▒████▒▒░░░░▒▒██▒▒░░▒▒██████░░░░▒▒██████▒▒░░░░▒▒██
▒▒░░▒▒██▒▒▒▒░░▒▒██▒▒▒▒░░▒▒▒▒██▒▒▒▒░░░░░░▒▒██▒▒░░░░▒▒▒▒░░░░▒▒████▒▒▒▒░░▒▒████▒▒▒▒░░░░░░▒▒
░░░░░░▒▒░░░░░░░░▒▒▒▒▒▒░░░░▒▒▒▒▒▒░░░░░░░░▒▒▒▒░░░░░░▒▒▒▒░░░░░░▒▒▒▒░░░░░░░░▒▒▒▒▒▒░░░░░░░░▒▒
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

ProxyFire

Author: Davide TheZero <io@thezero.org>
*/


/*
int
connectx(int socket, const sa_endpoints_t *endpoints, sae_associd_t associd,
    unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len,
    sae_connid_t *connid);

int connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen)

typedef struct sa_endpoints {
	unsigned int     sae_srcif;      /* optional source interface   *
	struct sockaddr *sae_srcaddr;    /* optional source address     *
	socklen_t        sae_srcaddrlen; /* size of source address      *
	struct sockaddr *sae_dstaddr;    /* destination address         *
	socklen_t        sae_dstaddrlen; /* size of destination address *
}sa_endpoints_t;

struct sockaddr {
	__uint8_t       sa_len;         /* total length *
	sa_family_t     sa_family;      /* [XSI] address family *
	char            sa_data[14];    /* [XSI] addr value (actually larger) *
};
*/
const pointerSize = Process.pointerSize;
const byteSize = 1;
const AF_INET = 2;
const AF_INET6 = 30;

class Port {
    /*
     * Port class stores a 2 byte long ArrayBuffer containing the hex representation of a TCP/UDP port
     * - constructor() accept an ArrayBuffer
     * - fromInt() static function return a Port object from a decimal port value
     * - length stores the size in byte of the Port object
     * - toString() return a string representation of the port
     * - toInt() return a decimal representation of the port
     */
    constructor(port_array) {
        if (port_array?.length != Port.length) { console.error('Invalid Port length') }
        this.port = port_array;
    }
    static fromInt(port) {
        let high = Math.floor(port / 256);
        let low = port % 256;
        return new Port([high, low])
    }
    static length = 2;
    toString() {
        return this.toInt().toString()
    }
    toInt() {
        return this.port[0]*256 + this.port[1]
    }
}
class IPv4 {
    /*
     * IPv4 class stores a 4 byte long ArrayBuffer containing the hex representation of an IPv4 address
     * - constructor() accept an ArrayBuffer
     * - length stores the size (in bytes) of the IPv4 object
     * - toString() return a 4-octect string representation of the IPv4
     */
    constructor(ip_array) {
        if (ip_array?.length != IPv4.length) { console.error('Invalid IPv4 length') }
        this.octets = ip_array;
    }
    static length = 4;
    static localhost = [127, 0, 0, 1];
    toString() {
        return this.octets[0]+'.'+this.octets[1]+'.'+this.octets[2]+'.'+this.octets[3]
    }
}
class IPv6 {
    /*
     * IPv6 class stores a 16 byte long ArrayBuffer containing the hex representation of an IPv6 address
     * - constructor() accept an ArrayBuffer
     * - length stores the size (in bytes) of the IPv6 object
     * - toString() return a 8-part string representation of the IPv6
     */
    constructor(ip_array) {
        if (ip_array?.length != IPv6.length) { console.error('Invalid IPv6 length') }
        this.parts = ip_array;
    }
    static length = 16;
    static localhost = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
    toString() {
        const results = [];
        for (let i = 0; i <= 14; i += 2) {
            results.push(((this.parts[i] << 8) | this.parts[i + 1]).toString(16));
        }
        return results.join(':');
    }
}

function proxy(sockaddr_ptr, f) {
    // The proxy function accept a pointer to a sockaddr struct (AF_INET or AF_INET6 type)
    const sock = sockaddr_ptr;
    // We read the sa_len and sa_family fields
    let sa_len = sock.readU8();
    const sa_family = sock.add(byteSize*1).readU8();

    if (sa_family === AF_INET) {
        // the sockaddr is IPv4
        // if we don't have lenght information, we fix its length
        if (sa_len === 0) { sa_len = Port.length + IPv4.length; }
        // and read the sockaddr data
        const sa_data = new Uint8Array(sock.add(byteSize*2).readByteArray(sa_len));
        
        // we parse the port and the ipv4 address
        const port = new Port(sa_data.slice(0, Port.length));
        const ip = new IPv4(sa_data.slice(Port.length, Port.length+IPv4.length));
        if (port.toInt() === 80 || port.toInt() === 443) {
            // the port is either HTTP or HTTPS so needs to be proxied
            console.info('['+f+'] Proxied IPv4 request to ' + ip + ':' + port);

            //sock.add(byteSize*2).writeByteArray(port.port);
            // we write the IPv4 loopback address into the sockaddr struct
            sock.add(byteSize*(2+Port.length)).writeByteArray(IPv4.localhost);
        } else {
            console.warn('['+f+'] got AF_INET packet with port ' + port.toString())
        }
    } else if (sa_family === AF_INET6) {
        // the sockaddr is IPv6
        // fix length. in between Port and IPv6 we have the flow information
        if (sa_len === 0) { sa_len = Port.length + 4 + IPv6.length; }
        const sa_data = new Uint8Array(sock.add(byteSize*2).readByteArray(sa_len));

        // we parse the port and the ipv6 address
        const port = new Port(sa_data.slice(0, Port.length));
        const ip = new IPv6(sa_data.slice(Port.length+4, Port.length+4+IPv6.length));
        if (port.toInt() === 80 || port.toInt() === 443) {
            // the port is either HTTP or HTTPS so needs to be proxied
            console.info('['+f+'] Proxied IPv6 request to ' + ip + ' on port ' + port);

            //sock.add(byteSize*2).writeByteArray(port.port);
            // we write the IPv6 loopback address into the sockaddr struct
            sock.add(byteSize*(2+Port.length+4)).writeByteArray(IPv6.localhost);
        } else {
            console.warn('['+f+'] got AF_INET6 packet with port ' + port.toString())
        }
    }
    else {
        console.warn('['+f+'] got packet with family ' + sa_family)
    }
}

function inject_connect_syscall_hooks() {
    // hook the connectx macOS Darwin/XNU syscall
    const connectx = Module.findExportByName(null, 'connectx');
    Interceptor.attach(connectx, {
        onEnter(args) {
            // connectx accept sa_endpoints that is a struct with a pointer to the sockaddr struct
            const sa_endpoints = ptr(args[1]);
            const sae_dstaddr = sa_endpoints.add(pointerSize*3).readPointer();
            const sae_dstaddrlen = sa_endpoints.add(pointerSize*4).readInt();
            // dereference sockaddr pointer
            proxy(ptr(sae_dstaddr), 'connextx');
        }
    });
    console.info('[+] connectx syscall hook installed!');
    const connect = Module.findExportByName(null, 'connect');
    Interceptor.attach(connect, {
        onEnter(args) {
            // connect accept sockaddr struct directly
            const sockaddr = ptr(args[1]);
            proxy(sockaddr, 'connect');
        }
    });
    console.info('[+] connect syscall hook installed!');
}
inject_connect_syscall_hooks();

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