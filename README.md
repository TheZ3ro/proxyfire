# proxyfire

<img src="/proxyfire.jpg" width="200" />  


**ProxyFire** is a Frida-based Transparent Proxy.  
It can be used to add transparent proxy capabilities to iOS/macOS apps (and more generally POSIX executables) without setting a system-wide proxy and without installing system-wide CA certificates.

*Note*: This is a PoC and not production ready. If you need a full-fledged proxy use Proxifier or the like.

## Usage
```
frida -l proxyfire.js -l unpinner.js -n <process_name>
```
or
```
frida -l proxyfire.js -l unpinner.js -p <process_id>
```

## Credits

ProxyFire is based on: [megahertz0/TransparentProxyForcer](https://github.com/megahertz0/TransparentProxyForcer).  
ProxyFire includes SSL unpinning code from:
- [azenla/AppleCache](https://github.com/azenla/AppleCache): macOS (OpenSSL/BoringSSL) unpinning.
- [NVISOsecurity/disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification): Flutter-specific unpinning.

ProxyFire's icon was generated with an AI. AIs are bad.
