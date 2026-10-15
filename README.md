# kerberoasting-blue-team
# Kerberoasting — Blue Team Detection & Response

A defensive (Blue Team) write-up of the **Kerberoasting** attack: how it works, how to
**detect** it in a SIEM, and how to **mitigate** it. Built as a lab learning exercise on
simulated data — no real organisational data is included.

- **MITRE ATT&CK:** [T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- **Tactic:** Credential Access
- **Focus:** detection engineering + response, not exploitation

---

## 1. What is Kerberoasting?

In an Active Directory environment, service accounts are identified by a **Service
Principal Name (SPN)**. Any authenticated domain user can request a Kerberos service
ticket (**TGS**) for an account that has an SPN. That ticket is encrypted with the
**service account's password hash**.

An attacker abuses this by:

1. Enumerating accounts that have an SPN (often normal *user* accounts running services).
2. Requesting TGS tickets for those SPNs — **no elevated privileges are required**.
3. Exporting the tickets and **cracking them offline** to recover the service account's
   cleartext password.

The attack is attractive because the request itself looks like normal Kerberos activity,
and cracking happens **offline**, away from the network. The weak link is often **RC4**
encryption (`0x17`), which is easier to crack than AES.

---

## 2. Detection

### Primary log source
**Windows Security Event ID `4769` — "A Kerberos service ticket was requested."**

Key fields to inspect:

| Field | Why it matters |
|---|---|
| `Ticket Encryption Type` | `0x17` = RC4-HMAC. In a modern AES environment, RC4 requests are suspicious. AES = `0x12` / `0x11`. |
| `Service Name` | The targeted SPN. Machine accounts end with `$`; **user** accounts with SPNs are the usual target. |
| `Account Name` | The requesting user. One account requesting many distinct SPNs is a red flag. |
| `Client Address` | Source host of the requests. |
| `Ticket Options` | Helps baseline normal vs. abnormal request patterns. |

### Detection logic (what to alert on)
A single account requesting **many distinct SPN tickets** with **RC4 encryption** in a
**short time window** is the core behavioural signal. Tune the threshold to your
environment (e.g. **≥ 5 distinct SPNs in 10 minutes**).

- Splunk query: [`detection/kerberoasting_splunk.spl`](detection/kerberoasting_splunk.spl)
- Sigma rule: [`detection/sigma_kerberoasting.yml`](detection/sigma_kerberoasting.yml)

### Triage steps for an analyst
1. Confirm the **encryption type** (`0x17` RC4) and count **distinct `Service Name`** values per `Account Name`.
2. Check whether the requesting account normally touches these services (baseline / asset context).
3. Review the **`Client Address`** — is it a workstation that should be enumerating SPNs?
4. Correlate with recent **4768** (TGT requests) and endpoint/EDR telemetry (e.g. tools like Rubeus / Impacket patterns).
5. If confirmed: treat affected **service accounts as compromised**, rotate their passwords, and hunt for follow-on use.

---

## 3. Mitigations

- **Use Group Managed Service Accounts (gMSA)** — long, automatically rotated passwords that are not practical to crack.
- **Enforce strong service-account passwords** (25+ characters) where gMSA is not possible.
- **Disable RC4 / require AES** for Kerberos where supported; alert on any remaining RC4 (`0x17`) usage.
- **Apply least privilege** to service accounts — a cracked password should yield minimal access.
- **Deploy a honeypot SPN account** (a decoy service account with an SPN and no real use); any TGS request for it is high-fidelity evidence of enumeration.
- **Monitor Event ID 4769** continuously for the RC4 + many-distinct-SPN pattern.

---

## 4. Detection ↔ ATT&CK mapping

| Stage | Signal | Reference |
|---|---|---|
| SPN enumeration | Burst of 4769 for distinct SPNs from one account | T1558.003 |
| Weak-crypto request | `Ticket Encryption Type = 0x17` (RC4) | T1558.003 |
| Decoy triggered | Any 4769 for a honeypot SPN | T1558.003 |

---

## References
- MITRE ATT&CK — T1558.003: https://attack.mitre.org/techniques/T1558/003/
- Microsoft — Audit Kerberos Service Ticket Operations (Event 4769)
- SANS / community detection guidance on Kerberoasting

---
*Author: Osman Onur Uyar — lab-based, defensive learning write-up on simulated data.*
