# Security and Privacy Risks

This project intentionally probes messaging platforms to infer device presence via delivery timing. It is a **security hazard** because it shows how silent network interactions can leak sensitive metadata about users. Running it against others without explicit consent can violate laws and policies.

## What makes it hazardous
- **Unwanted surveillance:** Reveals when a device is active/idle/offline without the owner’s knowledge.
- **Side-channel exploitation:** Uses timing side channels (RTT and delivery receipts) rather than intended APIs.
- **Metadata exposure:** Collects and stores timestamps, presence state, and contact identifiers.
- **Persistence risk:** Data are written to SQLite and volumes; compromise or mishandling leaks historical activity traces.
- **Abuse potential:** Could be combined with other data to profile behavior patterns.

## Built-in mitigations (limited)
- Labeled as research-only; no production hardening.
- High-frequency probing removed; still actively sends network traffic.
- No obfuscation; traffic may be visible in logs/IDS.

## Why you should probably not run this
- You are responsible for complying with platform terms of service and local law.
- Unauthorized monitoring may be illegal (wiretap, computer misuse, privacy statutes).
- Even with consent, storing presence data may create obligations under data protection laws.

If you cannot obtain informed, explicit consent from all monitored parties, **do not run this software.**
