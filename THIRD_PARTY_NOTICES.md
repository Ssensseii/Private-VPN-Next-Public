# Third-party notices

## sing-box 1.14.4

The Windows amd64 binary is downloaded unmodified from the official SagerNet/sing-box GitHub release v1.14.4. The build workflow verifies this archive SHA-256 before extraction:

`99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df`

sing-box is licensed under GNU GPL version 3 or later. Corresponding upstream source: https://github.com/SagerNet/sing-box/tree/v1.14.4. The upstream copyright and additional naming notice are included in `core/LICENSE-sing-box.txt`. PrivateVPN Next is independent and is not affiliated with or endorsed by SagerNet.

## Microsoft Edge WebView2

The build downloads the Microsoft.Web.WebView2 NuGet package at pinned version 1.0.4314.35 and redistributes its x64 WebView2Loader.dll under Microsoft's WebView2 distribution terms. The WebView2 Runtime itself is not bundled; install it if absent: https://developer.microsoft.com/microsoft-edge/webview2/

Distribution documentation: https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution

## go-winres (build-time tool)

The Windows build uses the MIT-licensed `tc-hib/go-winres` resource compiler,
pinned to commit `c4d55a3dfc2e22a4a9fb95ae0280ce106daadce9`, to embed the
application icon and Windows manifest into the executable. The tool is used
only during CI and is not distributed with PrivateVPN Next.

Upstream: https://github.com/tc-hib/go-winres
