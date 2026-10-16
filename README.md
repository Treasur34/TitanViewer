# Titan Viewer downloads

[Download Titan Viewer](https://titanviewer.com/download/) · [All releases](https://github.com/Treasur34/TitanViewer/releases) · [Help](https://titanviewer.com/help/)

The download page chooses the newest published package for your operating system. Binary files are delivered by GitHub Releases.

## Windows

One EXE. Choose **Install** or **Continue portable** when it opens. The signed `.rdupdate` attachment is used by the application; you do not need to download it separately.

## Linux x64 (X11 preview)

Extract the Linux archive and run `Install.sh` as your normal user, without sudo. This installs into your user account using the signed GitHub channel and adds the application menu entry. Launch the installed app from that entry to receive automatic updates.

Running the extracted `TitanViewer` directly remains portable and does not automatically install it. Packages managed by a Linux distribution must be updated through their package manager.

The 0.39.5 Linux build was tested on Ubuntu 22.04 x64, including an actual installed 0.38.0 to 0.39.5 upgrade. Physical desktop and Wayland qualification remains separate. No public macOS or mobile store build is included here.

## Automatic updates

Installed Linux and Windows clients check at startup and verify each update with their pinned publisher signature before applying it. Active remote sessions defer installation. Offline clients can update after reconnecting.

The **Publish verified update channels** GitHub Action validates signed release metadata and payloads, then publishes the channels automatically. It refuses incomplete, altered, expired or downgraded releases. The private signing key stays off GitHub.

## Languages

Arabic, English, Turkish, German, Spanish, French, Italian, Portuguese, Russian, Japanese and Chinese. Arabic includes right-to-left layouts.

This repository contains release binaries, signed metadata, notices and the public channel verifier. Application source, private signing keys and server configuration are not included. GitHub's automatic source archives contain only these public distribution files.

These are preview builds. The Windows EXE does not yet carry an Authenticode certificate; the update channel uses a separate publisher signature. License terms apply.
