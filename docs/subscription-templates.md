# Subscription templates and client selection

The server and `Lite-Plus-web` must be updated together. The subscription feature runs in the main server; no Agent change is required.

## Administration

Open **Node management → Template management**. Filter the list by type. **New template** offers a basic configuration, file import or an empty editor for pasting a complete configuration. The star sets or removes the system default for every client of the same template type, with the affected clients shown before applying. **Apply to…** on a template assigns it to a plan or user subscription; the dialog shows current settings and allows restoring inheritance. Usage labels on the list reopen the corresponding assignment. The preview dialog compares the template with the selected subscription's generated configuration. Templates support MiaoMiaoWu V3 Clash/Mihomo YAML, Loon `.lcf`, Surge `.conf`, and sing-box JSON. Existing node entries are removed before saving; authorized nodes are inserted on each request. Node subscriptions belong in each user's extra links, rather than shared `proxy-providers` or `[Remote Proxy]` sections.

Bind saved templates by client, at the system, plan, or subscription level. Resolution is **subscription → newest active plan with a matching binding → system default → built-in**. A blank binding inherits the next level. Remove bindings before deleting a template. Deleting a user, subscription, or plan removes its bindings. Template content changes take effect on the next request.

Enable **Identify client automatically** on a subscription to select the output using the requesting client's User-Agent. Existing subscriptions retain fixed mode after migration. The existing format remains the fallback for unrecognized clients. Explicit client links are available from the preview selector and can be copied or scanned as a QR code.

## Requests and compatibility

Append `?target=mihomo`, `clash`, `loon`, `surge`, `surge-mac`, `stash`, `sing-box`, or `v2ray` to an existing subscription URL. The token and path stay the same. Precedence is explicit `target`, explicit legacy `format`, automatic client detection (when enabled), then the stored format. The legacy `format=clash` and `format=sing-box` node-list outputs remain unchanged unless an administrator binds a corresponding template.

Clash/Mihomo templates use the shared V3 processor, including `include-all`, `filter`, `exclude-filter`, protocol filters and region groups. DNS, routing and rule-provider definitions remain part of the template. Native Loon/Surge templates replace `[Proxy]` using the appropriate producer, preserving other sections; Loon also generates `[Proxy Chain]` as needed. `__PROXY_NODES__` expands to the compatible authorized node names in native proxy groups. Native templates should use this marker or native regex selection rather than referring to sample nodes removed during import.

Sing-box templates contain complete JSON. Selector/urltest `outbounds` arrays may contain the `__PROXY_NODES__` or MiaoMiaoWu `{all}` marker; it expands to compatible generated outbound tags. An empty group uses the template's direct outbound, adding one if necessary. Template selectors and direct outbounds are preserved; embedded network outbounds are removed. This is the supported JSON template dialect; arbitrary third-party template scripting is not executed.

The adapter covers Lite-Plus node protocols (Shadowsocks, VMess, VLESS, Trojan, Hysteria2, TUIC, AnyTLS) and external Hysteria nodes. Compatibility is determined by the pinned producer library, rather than inventing protocol substitutions. Unsupported nodes are reported in administrator previews. Client version-specific features still require testing with the intended client.

Public delivery and administrator preview use the same generator and user-grant checks. Disabled subscriptions, inactive/expired users and invalid tokens cannot retrieve configurations. Responses use `Cache-Control: no-store` and `Vary: User-Agent`. Preview returns the actual response body, including Base64 for v2ray-family subscriptions; the UI separately decodes node links for QR display.

## Implementation and checks

- Template models and bindings: `nodemgt/models`, `nodemgt/store/subscription_templates.go`.
- Template engine adapter and client selection: `nodemgt/subtpl`.
- Shared preview/delivery pipeline: `nodemgt/subhttp/generate.go`.
- Administrator RPC methods: `admin:nodemgt.template.list`, `.upsert`, `.delete`, `.bind`, `.preview`.
- HTTP subscription URLs expose no template administration API.
- Run `go test ./nodemgt/... ./web/rpc/jsonrpc`; in the web repository run `npm test` and `npm run build`.

The adapter uses `github.com/MMWOrg/mmwX-plugins/proxyparser v0.4.0`. The upstream repository moved to `mmwx-group/mmwX-plugins`; its Go module path is unchanged. The MIT notice is included in `THIRD_PARTY_NOTICES/proxyparser-LICENSE`.
