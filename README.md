# Titan Viewer downloads

[Download Titan Viewer](https://titanviewer.com/download/) · [All releases](https://github.com/Treasur34/TitanViewer/releases) · [Help](https://titanviewer.com/help/)

The download page chooses the newest published package for your operating system. Binary files are delivered by GitHub Releases.

## Windows (32-bit x86 and x64)

Windows 10 version 1809 or newer. Both architectures include the complete host and viewer. The download page selects the matching architecture. One TitanViewer EXE. Choose **Install** or **Continue portable** when it opens. From 0.41.9, the EXE has a timestamped Authenticode signature supplied by Bamboo Trust. The signed `.rdupdate` attachment is used by the application; you do not need to download it separately.

## Linux (X11 previews)

Extract the Linux archive and run `TitanViewer` directly for portable use, or run `Install.sh` as your normal user to add a user installation and application menu entry. Both modes check the signed GitHub update channel automatically at startup and periodically. No sudo is needed.

Portable mode does not require account sign-in or desktop registration. Updates keep the same launcher path, preserve profiles and adjacent user files, and retain a rollback copy. Keep the portable folder in a writable location owned by your user. Packages managed by a Linux distribution must be updated through their package manager.

Choose the archive matching your processor and system libraries:

- **x64:** Ubuntu 22.04 or newer, glibc 2.35 or newer.
- **32-bit x86:** Debian 13, glibc 2.41 or newer.
- **ARM64:** Ubuntu 24.04 or newer, glibc 2.39 or newer; compatible 64-bit Raspberry Pi systems using X11.

Portable 0.39.5 and older copies need one manual download because those old copies lack the portable startup-update code. Managed Linux installations can update through their existing channel. Physical desktop qualification remains separate. Wayland hosting and ARM32 are not included.

## macOS previews

Separate **Intel** and **Apple Silicon** archives require macOS 15 or newer. Extract the ZIP and move Titan Viewer.app to Applications. From 0.41.9, the apps are signed with the Titan Viewer owner's Apple Developer ID and notarized by Apple. Screen Recording and Accessibility permissions are required for hosting and control. Sparkle checks for Ed25519-signed updates. Native CI verifies packaged startup and the shipped updater's installation and relaunch using an isolated test application. Physical desktop permission testing remains separate.

Mobile store builds are not included in this desktop release.

## Automatic updates

Installed and portable Linux and Windows clients check at startup and verify each update with their pinned publisher signature before applying it. Active remote sessions defer installation. Offline clients can update after reconnecting.

The **Publish verified update channels** GitHub Action validates signed release metadata and payloads, then publishes the channels automatically. It refuses incomplete, altered, expired or downgraded releases. The private signing key stays off GitHub.

## Languages

Arabic, English, Turkish, German, Spanish, French, Italian, Portuguese, Russian, Japanese and Chinese. Arabic includes right-to-left layouts.

This repository contains release binaries, signed metadata, notices and the public channel verifier. Application source, private signing keys and server configuration are not included. GitHub's automatic source archives contain only these public distribution files.

These are preview builds. Operating-system code signatures and the update channel's publisher signature are independently verified. Code signing does not guarantee that all browser reputation warnings disappear. License terms apply.
