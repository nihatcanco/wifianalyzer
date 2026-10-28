# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

First release.

- Desktop app with a connection card, signal history, a spectrum chart per band, a sortable network table and channel
  recommendations. Saves scans as JSON, remembers its layout and follows the system's light or dark mode.
- Runs on macOS through CoreWLAN, on Windows through the Native Wifi API and on Linux through nl80211, with the same
  information on each where the system provides it.
- Explains and requests the permissions macOS and Windows require before they show nearby networks. On macOS this
  builds a small app bundle, Wi-Fi Analyzer.app.
- Works without any network access. Tests enforce it by reading the code and by watching the app run.
