# Titan Viewer downloads

[Download Titan Viewer](https://titanviewer.com/download/) · [All releases](https://github.com/Treasur34/TitanViewer/releases) · [Help](https://titanviewer.com/help/)

The download page chooses the newest published package for your operating system. Binary files are delivered by GitHub Releases.

## Windows

One EXE. Choose **Install** or **Continue portable** when it opens. The signed `.rdupdate` attachment is used by the application; you do not need to download it separately.

## Linux x64 (X11 preview)

Extract the Linux archive and run `TitanViewer` directly for portable use, or run `Install.sh` as your normal user to add a user installation and application menu entry. Both modes check the signed GitHub update channel automatically at startup and periodically. No sudo is needed.

Portable mode does not require account sign-in or desktop registration. Updates keep the same launcher path, preserve profiles and adjacent user files, and retain a rollback copy. Keep the portable folder in a writable location owned by your user. Packages managed by a Linux distribution must be updated through their package manager.

Portable 0.39.5 and older copies need one download of 0.39.6 because those old copies lack the portable startup-update code. Managed Linux installations can update through their existing channel. The Linux build targets Ubuntu 22.04 x64 / X11; physical desktop and Wayland qualification remains separate. No public macOS or mobile store build is included here.

## Automatic updates

Installed and portable Linux and Windows clients check at startup and verify each update with their pinned publisher signature before applying it. Active remote sessions defer installation. Offline clients can update after reconnecting.

The **Publish verified update channels** GitHub Action validates signed release metadata and payloads, then publishes the channels automatically. It refuses incomplete, altered, expired or downgraded releases. The private signing key stays off GitHub.

## Languages

Arabic, English, Turkish, German, Spanish, French, Italian, Portuguese, Russian, Japanese and Chinese. Arabic includes right-to-left layouts.

This repository contains release binaries, signed metadata, notices and the public channel verifier. Application source, private signing keys and server configuration are not included. GitHub's automatic source archives contain only these public distribution files.

These are preview builds. The Windows EXE does not yet carry an Authenticode certificate; the update channel uses a separate publisher signature. License terms apply.
