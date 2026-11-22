# Source layout

The current editable source tree is in `unpacked/`:

- `unpacked/src/` — Go application, embedded UI, tests and Windows integration.
- `unpacked/PrivateVPN-Next.exe.manifest` — Windows application manifest.
- `unpacked/validation/` — sing-box validation configurations.

This is the source of truth used by CI and future builds. Make code changes here.

The original source archive is retained in seven numbered UTF-8 base64 chunks in
`parts/part-01.b64` through `parts/part-07.b64`. It records the imported baseline
and is kept for provenance; it is not regenerated for each subsequent source change.

GitHub Actions reconstructs the archive and verifies its SHA-256:
`9e033c7e2d899d99def63d95d48892d84cef6ad2c23a4fd55ac009aa2a28e15b`.

Do not commit real proxy credentials, passwords, or user settings.
