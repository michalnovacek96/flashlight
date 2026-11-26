# Changelog

All notable changes to this project are documented here.
Versions follow [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`.

## [Unreleased]

- The Adjust is not linked to GA4 check (Firebase app_instance_id missing in Adjust) is no longer shown
- Batched requests split into one hit each, recognised by their shape for any tool: Graph API batches (Meta SDK: mobile_sdk_gk, app_settings), JSON lines and envelopes (Sentry: session, client_report, event with the exception type). Meta's settings request is named app_settings
- Apple Ads hits decoded: event attribution, the AdServices token as one value and Apple's answer (attribution true / false, campaign, ad group, keyword) in the hit detail, plus a course CTA that says what Apple answered
- Firebase SKAN hits show the same message as SKAN through an MMP: a weak conversion value schema leaves iOS campaigns with almost no data
- Plainer course CTAs for webview GA4 hits, ATT not authorized and first_open: each starts with what the hit shows
- Removed the Open in mitmweb link from the hit detail
- Clearer course CTA for Meta, TikTok and Snapchat hits: two messages take turns from hit to hit, one on installs counted by two ad networks, one on the weeks of waiting for an app release with every new ad network SDK

## [1.0.4] - 2026-11-26

- Meta detection covers all Graph API hosts of the Meta SDK: ep1.facebook.com and ep2.facebook.com (newer iOS SDKs send app settings and /activities there), graph-video.facebook.com, and graph.fb.gg / graph-video.fb.gg for apps with Facebook Gaming login
- TikTok: the TikTok Business SDK sends to analytics.us.tiktok.com (or another *.tiktok.com its server config picks), these hits used to fall under Other
- Google Ads: the on-device measurement SDK (part of Firebase Analytics 11.14.0+) sends to app-ads-services.com
- Snapchat: the SDK's own metrics (gcp.api.snapchat.com/sdk/metrics)
- New tools: Apple Ads (AdServices attribution), UXCam, LaunchDarkly, DataDome and the consent tools (CMP) OneTrust, Didomi, Usercentrics, Cookiebot, Sourcepoint, consentmanager, Google UMP, TrustArc, Ketch, Axeptio and iubenda

## [1.0.3] - 2026-11-20

- Proxy setup moved to the bottom right corner, next to the version
- The steps to connect an iPhone show whenever there are no hits, even with a tool filter on (a remembered filter of a removed tool used to hide them)

## [1.0.2] - 2026-11-20

- Proxy setup button in the header: the proxy IP address, port and certificate steps stay reachable after the iPhone connects

## [1.0.1] - 2026-11-13

- Removed the source of a hit (app SDK, webview, browsers) from the filters and the hit detail

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
