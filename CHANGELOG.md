# Changelog

All notable changes to this project are documented here.
Versions follow [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`.

## [Unreleased]

## [1.0.0] - 2026-11-10

First public release of **Flashlight**, a mobile app tracking debugger by measure-apps.com.

- Live hits list on http://127.0.0.1:8082, opens with mitmweb: one row per event, Pause, Clear, Copy JSON and a link to the same request in mitmweb
- Connection status: the flashlight icon lights up when an iPhone sends traffic through the proxy; the page shows how to connect, which iPhone is connected and whether HTTPS works
- Tool detection by domain for GA4 (Firebase and web), Firebase, Crashlytics, Adjust, AppsFlyer, Meta, Branch, Singular, Kochava, Airbridge, TikTok, Snapchat, Google Ads, Mixpanel, Amplitude, Segment, Braze, CleverTap, OneSignal, AppMetrica, RevenueCat, Sentry, Datadog and Clarity
- GA4 / Firebase protobuf decoded into events, parameters, ecommerce items, user properties and device & app info, including Firebase validation errors
- App filter with the app's name and icon from the App Store / Google Play, and a source filter (app SDK, in-app webview, Safari, Chrome, in-app browsers of social apps)
- Server-side GTM detection from the app's Firebase config, Firebase SKAN and other binary payloads decoded
- Regex search across event names, URLs, status codes and parameters
- Single Python file, no dependencies; installer for macOS
