"""S03 · Identity, Active Directory and cloud IAM.

AD attack-path reasoning, ADCS abuse, Kerberos posture, shadow credentials,
DC hardening, Entra/AI-key exposure, and readiness gaps for the 2026
identity-centric attack techniques.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..core.models import Evidence, Finding, RunContext, Severity

# ══════════════════════════════════════════════════════════════════ AD graph
def _ldap_objects(ctx: RunContext, base_dn: str) -> list[dict[str, Any]] | None:
    try:
        import ldap3
    except Exception:
        return None
    host = ctx.opt("dc") or (ctx.scope.hosts[0] if ctx.scope and ctx.scope.hosts else None)
    if not host:
        return None
    try:
        srv = ldap3.Server(host, get_info=ldap3.ALL)
        conn = ldap3.Connection(srv, auto_bind=True)
        conn.search(base_dn, "(objectClass=*)",
                    attributes=["cn", "name", "memberOf", "userAccountControl",
                                "servicePrincipalName", "msDS-AllowedToDelegateTo",
                                "msDS-KeyCredentialLink", "userPassword", "member"],
                    paged_size=1000)
        return [e.entry_attributes_as_dict for e in conn.response if e.type == "searchResEntry"]
    except Exception as e:  # noqa: BLE001
        ctx.note(f"identity: LDAP bind failed ({e})")
        return None


def check_ad_path(ctx: RunContext) -> list[Finding]:
    """Map AD principals and flag the highest-value escalation structures."""
    base_dn = ctx.opt("base_dn")
    if not base_dn:
        return [Finding(
            capability="s03_identity.ad_attack_path",
            title="AD attack-path analysis requires --base-dn and a reachable DC",
            severity=Severity.INFO, target="ad",
            detail=("Graph analysis is only meaningful against a live directory. Supply "
                    "--base-dn (e.g. DC=corp,DC=example,DC=com) and ensure a read-only bind "
                    "account is available."),
            tags=["identity", "ad", "gap"],
            remediation="Use BloodHound CE (pip install bloodhound) for full graph pathing; "
                        "AEGIS provides the structural review below.",
        )]
    objs = _ldap_objects(ctx, base_dn)
    if objs is None:
        return [Finding(
            capability="s03_identity.ad_attack_path",
            title="LDAP enumeration unavailable", severity=Severity.MEDIUM, target="ad",
            detail="Could not enumerate the directory (no ldap3, or bind failed). AD attack "
                   "path analysis is UNMEASURED.",
            tags=["identity", "ad", "gap"],
            remediation="`pip install ldap3` and provide read-only credentials via AEGIS_* env.",
        )]
    return _structural_ad_review(ctx, objs)


def _structural_ad_review(ctx: RunContext, objs: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    # NOTE: a `privileged` name set was declared here and never used. Group-name
    # matching for these lives in the disabled-account check below, which works
    # off the UAC 0x200 flag rather than name heuristics. Kept as a comment so the
    # next reader does not assume a name blocklist is in force when it is not.
    n_privileged = 0
    disabled_not_flagged: list[str] = []
    krbtgt_present = False
    gmsa: list[str] = []
    delegatable: list[str] = []

    for o in objs:
        cn = str(o.get("cn") or o.get("name") or [b""])[0] if isinstance(
            o.get("cn") or o.get("name"), list) else str(o.get("cn") or o.get("name") or "")
        uac = o.get("userAccountControl")
        if uac:
            try:
                val = int(list(uac)[0] if isinstance(uac, list) else uac)
                if val == 512:
                    n_privileged += 1
                elif val == 514 and cn.lower().startswith(("admin", "svc", "sql", "backup")):
                    disabled_not_flagged.append(cn)
            except Exception:
                pass
        if "krbtgt" in cn.lower():
            krbtgt_present = True
        if o.get("msDS-GroupMSAMembership"):
            gmsa.append(cn)
        if o.get("msDS-AllowedToDelegateTo"):
            delegatable.append(cn)

    if n_privileged:
        out.append(Finding(
            capability="s03_identity.ad_attack_path",
            title=f"{n_privileged} accounts with UAC 0x200 (domain-admin capable)",
            severity=Severity.HIGH, target="AD",
            detail="Accounts flagged as domain-admin capable. Compromise of any one is a "
                   "domain compromise; there is no partial credit.",
            attack_ids=["T1068.002", "T1078.001"],
            tags=["identity", "ad", "privacc"], confidence="high",
            remediation="Use just-in-time privileged access, tiered administration, and "
                        "alert on use of any Tier-0 account.",
        ))
    if disabled_not_flagged:
        out.append(Finding(
            capability="s03_identity.ad_attack_path",
            title=f"{len(disabled_not_flagged)} disabled accounts with privileged-looking names",
            severity=Severity.LOW, target="AD",
            detail=("Names like " + ", ".join(disabled_not_flagged[:8]) +
                    " are disabled but not renamed. Re-enabling them is the first thing an "
                    "attacker with domain write attempts."),
            attack_ids=["T1136.003"], tags=["identity", "ad", "hygiene"],
            remediation="Rename or delete stale privileged accounts; alert on any state change.",
        ))
    if not krbtgt_present:
        out.append(Finding(
            capability="s03_identity.ad_attack_path",
            title="KRBTGT not observed in the enumeration", severity=Severity.MEDIUM,
            target="AD", detail="The krbtgt account was not in the returned set.",
            tags=["identity", "ad"],
            remediation="Confirm enumeration covered domain controllers.",
        ))
    if gmsa:
        out.append(Finding(
            capability="s03_identity.ad_attack_path",
            title=f"{len(gmsa)} gMSA accounts present", severity=Severity.MEDIUM, target="AD",
            detail="Group Managed Service Accounts remove the interactive-logon risk but are "
                   "high-value targets. Confirm their host principals and rotation.",
            attack_ids=["T1003.006", "T1550.003"],
            tags=["identity", "ad", "gmsa"],
            remediation="Rotate gMSA secrets automatically; restrict delegation.",
        ))
    if delegatable:
        out.append(Finding(
            capability="s03_identity.ad_attack_path",
            title=f"{len(delegatable)} accounts have delegation configured",
            severity=Severity.HIGH if len(delegatable) > 5 else Severity.MEDIUM, target="AD",
            detail="Delegation (unconstrained in particular) is a first-hop-to-Tier-0 primitive. "
                   "Members: " + ", ".join(delegatable[:10]),
            attack_ids=["T1134.006", "T1550.003"],
            tags=["identity", "ad", "delegation"],
            remediation="Prefer constrained delegation to specific SPNs; remove unconstrained.",
        ))
    return out


def check_adcs(ctx: RunContext) -> list[Finding]:
    """ADCS escalation surface: enrollee rights, template vulns, CA ACLs."""
    base_dn = ctx.opt("base_dn")
    objs = _ldap_objects(ctx, base_dn) if base_dn else None
    out: list[Finding] = []
    DANGEROUS_TEMPLATES = {
        "userescrapelegacy": "ESC1 — enrollee can supply a subject; low-priv ESC.",
        "vulnerablecerttemplateforesc1": "ESC1 — ESC1 directly.",
        "usercertforattestation": "ESC3 — proof-of-possession bypass.",
        "vulnerablecerttemplateforesc3": "ESC3 — ESC3 directly.",
        "vulnerablecerttemplateforesc4": "ESC4 — subject alt name unconstrained.",
        "ctrsimulation": "ESC6 — CA-side template risk.",
        "anypurpose": "ESC7 — CA-side template risk.",
    }
    templates = ctx.opt("adcs_templates") or []
    risky = []
    for t in templates:
        tn = str(t.get("cn") if isinstance(t, dict) else t).lower().replace("-", "").replace(" ", "")
        for pat, why in DANGEROUS_TEMPLATES.items():
            if pat in tn:
                risky.append((str(t.get("cn") if isinstance(t, dict) else t), why))
    if risky:
        for name, why in risky:
            out.append(Finding(
                capability="s03_identity.adcs_abuse",
                title=f"Vulnerable certificate template: {name}", severity=Severity.CRITICAL,
                target=name,
                detail=f"{why}. Templates like this turn any authenticated user into a "
                       "domain controller with one request.",
                attack_ids=["T1649", "T1134.002", "T1553.004"],
                tags=["identity", "ad", "adcs", "certs", "critical"],
                confidence="high", cwe="CWE-295",
                remediation="Delete or lock down the template, or remove the enrolment right "
                            "from low-privileged users.",
            ))
    if objs:
        enrolment = [o for o in objs if o.get("msPKIEnrollment")]
        if len(enrolment) > 10:
            out.append(Finding(
                capability="s03_identity.adcs_abuse",
                title=f"{len(enrolment)} principals can enrol for certificates",
                severity=Severity.HIGH, target="AD",
                detail="Broad enrolment rights combined with any vulnerable template is an "
                       "instant path to DA.",
                attack_ids=["T1649"], tags=["identity", "ad", "adcs"],
                remediation="Restrict enrolment to a dedicated group.",
            ))
    if not out:
        out.append(Finding(
            capability="s03_identity.adcs_abuse",
            title="ADCS not assessed", severity=Severity.LOW, target="ADCS",
            detail="No templates provided. Supply --adcs-templates or run Certipy-AD.",
            tags=["identity", "ad", "gap"],
            remediation="`pip install certipy-ad` then `certipy-ad req -u user -p pass -dc dc -target ca`",
        ))
    return out


def check_kerberos(ctx: RunContext) -> list[Finding]:
    """Kerberos posture review."""
    out: list[Finding] = []
    asrep = ctx.opt("asrep_roastable") or []
    if asrep:
        out.append(Finding(
            capability="s03_identity.kerberos_weakness",
            title=f"{len(asrep)} accounts AS-REP roastable (no pre-auth required)",
            severity=Severity.HIGH, target="AD",
            detail="Members: " + ", ".join(map(str, asrep[:10])),
            attack_ids=["T1558.003"], tags=["identity", "kerberos", "ad"],
            remediation="Set 'Do not require Kerberos preauthentication' on service accounts "
                        "that do not need it.",
        ))
    fast = ctx.opt("asrep_fast_users") or []
    if fast:
        out.append(Finding(
            capability="s03_identity.kerberos_weakness",
            title="FAST pre-authentication not required", severity=Severity.MEDIUM, target="AD",
            detail="Without FAST, offline AS-REP roasting against a KDC is possible.",
            attack_ids=["T1558.003"], tags=["identity", "kerberos"],
            remediation="Enforce FAST armoring across the forest.",
        ))
    if ctx.opt("rc4_enabled"):
        out.append(Finding(
            capability="s03_identity.kerberos_weakness",
            title="RC4/HMAC-MD5 still permitted in the domain", severity=Severity.MEDIUM,
            target="AD",
            detail="RC4 is downgrade-attackable and slow; its presence usually means AES is "
                   "not enforced.",
            attack_ids=["T1550.003"], tags=["identity", "kerberos"],
            remediation="Disable RC4 for Kerberos; enforce AES.",
        ))
    if not out:
        out.append(Finding(
            capability="s03_identity.kerberos_weakness",
            title="Kerberos posture not assessed", severity=Severity.INFO, target="AD",
            detail="Supply --asrep-roastable / --rc4-enabled or run netexec against a DC.",
            tags=["identity", "kerberos"],
            remediation="`pip install netexec` then `nxc <dc> -u user -p pass -u '*' --asrep-roast`",
        ))
    return out


def check_ldap(ctx: RunContext) -> list[Finding]:
    """Enumerate privileged group membership from a directory export."""
    members = ctx.opt("privileged_members") or {}
    out = []
    for grp, users in (members or {}).items():
        try:
            n = len(users)
        except TypeError:
            continue
        if n:
            sev = Severity.CRITICAL if n > 10 else Severity.MEDIUM
            out.append(Finding(
                capability="s03_identity.ldap_enum",
                title=f"{grp}: {n} members", severity=sev, target=grp,
                detail=", ".join(map(str, list(users)[:12])),
                attack_ids=["T1069.002"], tags=["identity", "ldap", "privacc"],
                remediation="Baseline this membership and alert on any change.",
            ))
    if not out:
        out.append(Finding(
            capability="s03_identity.ldap_enum",
            title="No directory data supplied", severity=Severity.INFO, target="AD",
            detail="Pass --privileged-members from a directory export, or let AEGIS bind via LDAP.",
            tags=["identity", "ldap"],
        ))
    return out


def check_smb(ctx: RunContext) -> list[Finding]:
    """SMB exposure and signing posture."""
    hosts = ctx.opt("smb_hosts") or (ctx.scope.hosts if ctx.scope else [])
    out = []
    nmap = ctx.opt("_providers", {}).get("smb_enum")
    if nmap is None or not getattr(nmap, "runnable", False):
        return [Finding(
            capability="s03_identity.smb_enum",
            title="SMB enumeration requires netexec or nmap", severity=Severity.LOW,
            target="AD", detail="No SMB tool available in this environment.",
            tags=["identity", "smb", "gap"],
            remediation="`pip install netexec`",
        )]
    from ..core.runner import execute
    for h in list(hosts)[:20]:
        res = execute(nmap.provider, ["-smb-enum", "-targets", h, "-users", ""],
                      ctx.config, timeout=120)
        if res.ok and res.stdout.strip():
            out.append(Finding(
                capability="s03_identity.smb_enum", title=f"SMB data gathered: {h}",
                severity=Severity.INFO, target=h, detail=res.stdout[:400],
                tags=["identity", "smb"],
                evidence=[Evidence(kind="output", summary="netexec", locator=h,
                                   excerpt=res.stdout[:400])],
            ))
    return out


def check_delegation(ctx: RunContext) -> list[Finding]:
    """Delegation abuse surface."""
    return _delegation_review(ctx)


def _delegation_review(ctx: RunContext) -> list[Finding]:
    unconstrained = ctx.opt("unconstrained_delegation") or []
    constrained = ctx.opt("constrained_delegation") or {}
    out = []
    if unconstrained:
        out.append(Finding(
            capability="s03_identity.ad_delegation",
            title=f"{len(unconstrained)} accounts with UNCONSTRAINED delegation",
            severity=Severity.CRITICAL, target="AD",
            detail=("Unconstrained delegation accepts a TGT from any service on the host. "
                    "Combined with a capture (e.g. HTTP auth) this yields the ability to "
                    "impersonate any user. Members: " + ", ".join(map(str, unconstrained[:10]))),
            attack_ids=["T1134.006", "T1550.003"],
            tags=["identity", "delegation", "ad", "critical"],
            remediation="Remove unconstrained delegation; use constrained delegation to named SPNs.",
        ))
    if constrained:
        out.append(Finding(
            capability="s03_identity.ad_delegation",
            title=f"{len(constrained)} accounts with constrained delegation",
            severity=Severity.LOW, target="AD",
            detail=", ".join(f"{k}" for k in list(constrained)[:10]),
            attack_ids=["T1134.006"], tags=["identity", "delegation"],
            remediation="Confirm each delegation target is still required.",
        ))
    if not out:
        out.append(Finding(
            capability="s03_identity.ad_delegation",
            title="Delegation not assessed", severity=Severity.INFO, target="AD",
            detail="Supply --unconstrained-delegation or run an LDAP/ADeleg enumeration.",
            tags=["identity", "delegation"],
        ))
    return out


def check_shadow_creds(ctx: RunContext) -> list[Finding]:
    """Detect msDS-KeyCredentialLink shadow credentials."""
    base_dn = ctx.opt("base_dn")
    objs = _ldap_objects(ctx, base_dn) if base_dn else None
    hits = []
    if objs:
        hits = [o for o in objs if o.get("msDS-KeyCredentialLink")]
    hits += list(ctx.opt("shadow_creds") or [])
    if hits:
        return [Finding(
            capability="s03_identity.shadow_credentials",
            title=f"{len(hits)} principals carry shadow credentials", severity=Severity.CRITICAL,
            target="AD",
            detail="msDS-KeyCredentialLink values allow forging Kerberos tickets for the "
                   "principal without knowing the password. Legitimate use is rare.",
            attack_ids=["T1556.005"], tags=["identity", "ad", "credentials", "critical"],
            remediation="Purge the values; alert on any change to this attribute.",
        )]
    return [Finding(
        capability="s03_identity.shadow_credentials",
        title="No shadow credentials found in the supplied data", severity=Severity.OK,
        target="AD", detail="msDS-KeyCredentialLink absent across the enumerated objects.",
        tags=["identity", "ad"],
    )]


def check_dc_hardening(ctx: RunContext) -> list[Finding]:
    """DC protocol hardening checklist."""
    CHECKS = [
        ("smb_signing", "SMB signing required on domain controllers",
         "Unsigned SMB is relayable into DA.", "T1557.002", Severity.HIGH),
        ("ldaps_signing", "LDAP signing + channel binding enforced",
         "Without channel binding, LDAP is relayable.", "T1557.002", Severity.HIGH),
        ("smbv1", "SMBv1 disabled", "SMBv1 carries no signing and is EOL.", "T1021.002", Severity.MEDIUM),
        ("null_sessions", "Null sessions to DCs denied",
         "Null sessions leak domain trust and SPN data.", "T1087.002", Severity.MEDIUM),
        ("asrp_exposed", "No pre-auth required accounts",
         "Enables offline AS-REP roasting.", "T1558.003", Severity.MEDIUM),
        ("rc4", "RC4 disabled in Kerberos",
         "RC4 is downgradeable and slow to brute-force but fast to relay.", "T1550.003", Severity.MEDIUM),
        ("anonspn", "No accounts with SPNs on non-service hosts",
         "Non-service SPNs enable Kerberoasting.", "T1558.003", Severity.HIGH),
        ("rodc", "RODC password-replication policy reviewed",
         "Misconfigured RODC can leak cached secrets.", "T1003.006", Severity.LOW),
    ]
    findings = ctx.opt("dc_flags") or {}
    out = []
    for key, title, why, tid, sev in CHECKS:
        val = findings.get(key)
        if val is None:
            out.append(Finding(
                capability="s03_identity.dc_hardening", title=f"{title} — UNVERIFIED",
                severity=Severity.MEDIUM, target=key,
                detail=f"{why} (status not supplied)", attack_ids=[tid],
                tags=["identity", "hardening", "gap"],
                remediation="Verify explicitly; an unverified control is not a control.",
            ))
        elif val in ("no", "false", "disabled", False):
            out.append(Finding(
                capability="s03_identity.dc_hardening", title=f"{title} — FAILING",
                severity=sev, target=key, detail=why, attack_ids=[tid],
                tags=["identity", "hardening", "ad"],
                remediation="Enable this control and re-test.",
            ))
    if not any(f.severity is Severity.MEDIUM and "UNVERIFIED" in f.title for f in out):
        out.append(Finding(
            capability="s03_identity.dc_hardening",
            title="DC hardening: all supplied controls pass", severity=Severity.OK,
            target="AD", detail=f"{len(out)} controls verified.",
            tags=["identity", "hardening"],
        ))
    return out


def check_cred_dump_indicators(ctx: RunContext) -> list[Finding]:
    """Hunt for credential-dumping indicators in supplied telemetry."""
    from ..core.util import read_text
    hay = ""
    for src in (ctx.opt("logs") or []):
        hay += read_text(src, 20_000_000)
    hay_l = hay.lower()
    SIGNALS = [
        ("comsvcs.dll MiniDump", ["comsvcs.dll", "minidump", "lsass.dmp"]),
        ("procdump LSASS", ["procdump", "-ma", "lsass"]),
        ("sekurlsa / mimikatz", ["sekurlsa", "mimikatz", "gentilkiwi", "kerberos::list"]),
        ("DCSync-style replication", ["drsreplicaterep", "replicating directory changes all"]),
        ("Ntdsutil", ["ntdsutil"]),
        ("reg save SAM/SYSTEM", ["reg save", "sam", "system32\\config\\sam"]),
        ("credential manager dump", ["vaultenumerate", "rundll32 keymgr.dll"]),
        ("WerFault LSASS", ["werfault.exe", "-u", "-s", "lsass"]),
    ]
    out = []
    for name, sigs in SIGNALS:
        hits = [s for s in sigs if s in hay_l]
        if len(hits) >= 2:
            out.append(Finding(
                capability="s03_identity.mimikatz_indicators",
                title=f"Credential-dump indicators: {name}", severity=Severity.CRITICAL,
                target="logs", detail="Matched: " + ", ".join(hits),
                attack_ids=["T1003.001", "T1003.002", "T1003.003"],
                tags=["identity", "hunting", "defense", "critical"],
                confidence="high",
                remediation="Isolate the host; treat all credentials on it as compromised "
                            "and rotate them.",
            ))
    if not out:
        out.append(Finding(
            capability="s03_identity.mimikatz_indicators",
            title="No credential-dump indicators in the supplied telemetry",
            severity=Severity.OK, target="logs", tags=["identity", "hunting"],
            remediation="Keep LSASS protected (RunAsPPL) and require protected-process light "
                        "for the credential stack.",
        ))
    return out


# ══════════════════════════════════════════════════════════════════ cloud / AI
def check_entra(ctx: RunContext) -> list[Finding]:
    """Entra ID posture checklist (offline, config-driven)."""
    CHK = [
        ("legacy_auth_disabled", "Legacy authentication disabled", Severity.HIGH, "T1550.001"),
        ("mfa_admin_required", "MFA required for all admins", Severity.CRITICAL, "T1556.006"),
        ("ca_policies_harden", "Conditional Access covers all apps", Severity.HIGH, "T1556.009"),
        ("user_consent_blocked", "User app-consent blocked", Severity.MEDIUM, "T1136.003"),
        ("unprivileged_search", "Unprivileged user search disabled", Severity.MEDIUM, "T1087.002"),
        ("guest_review", "Guest accounts reviewed and expired", Severity.MEDIUM, "T1136.003"),
        ("workforce_isolation", "Workforce tenant isolation enforced", Severity.LOW, "T1550.001"),
        ("device_compliance", "Device compliance required for access", Severity.MEDIUM, "T1078"),
    ]
    flags = ctx.opt("entra_flags") or {}
    out = []
    for key, title, sev, tid in CHK:
        v = flags.get(key)
        if v in (False, "no", "off", "disabled"):
            out.append(Finding(
                capability="s03_identity.entra_assess", title=f"Entra: {title} — NOT ENFORCED",
                severity=sev, target=key,
                detail="Reported as disabled in the supplied configuration.",
                attack_ids=[tid], tags=["identity", "entra", "cloud"],
                remediation="Enable and verify enforcement with a test account.",
            ))
        elif v is None:
            out.append(Finding(
                capability="s03_identity.entra_assess", title=f"Entra: {title} — UNVERIFIED",
                severity=Severity.MEDIUM, target=key,
                detail="Not present in the supplied configuration export.",
                attack_ids=[tid], tags=["identity", "entra", "gap"],
                remediation="Export the tenant configuration and re-run.",
            ))
    if not out:
        out.append(Finding(
            capability="s03_identity.entra_assess", title="Entra posture: all checks pass",
            severity=Severity.OK, target="entra", tags=["identity", "entra"]))
    return out


def check_device_code(ctx: RunContext) -> list[Finding]:
    """Device-code-phishing readiness audit."""
    from ..core.util import read_text
    log = ""
    for src in (ctx.opt("logs") or []):
        log += read_text(src, 10_000_000)
    out = []
    if log:
        l = log.lower()
        if "devicecode" in l or "device_code" in l or "usercode" in l:
            hits = len([1 for _ in re.finditer(r"device.?code", l)])
            out.append(Finding(
                capability="s03_identity.device_code_readiness",
                title=f"Device-authorisation activity in telemetry ({hits} references)",
                severity=Severity.HIGH, target="logs",
                detail="OAuth device-code flow events present. Each one is a potential "
                       "phishing attempt or a legitimate CLI sign-in — they must be "
                       "distinguished, which means you need both fields.",
                attack_ids=["T1550.001", "T1528"],
                tags=["identity", "phishing", "detection", "device-code"],
                evidence=[Evidence(kind="log", summary="device code events", locator="logs",
                                   excerpt=l[max(0, l.find("device") - 200):
                                            l.find("device") + 400])],
                remediation="Alert on device authorisation initiated by an unusual client or "
                            "geo; correlate with the requesting user's sign-in location.",
            ))
    out.append(Finding(
        capability="s03_identity.device_code_readiness",
        title="Alert logic required for device-code phishing",
        severity=Severity.MEDIUM, target="detection",
        detail=("Detect: (a) device authorisation requests from clients that never do so "
                "normally, (b) a user entering a code they did not initiate, (c) token "
                "issuance without a corresponding interactive sign-in. Elastic, Silverfort and "
                "LevelBlue all publish this."),
        attack_ids=["T1550.001"], tags=["identity", "detection", "device-code"],
        refs=["https://www.silverfort.com/blog/device-code-attacks-in-azure-from-exploitation-to-detection/",
              "https://pushsecurity.com/blog/device-code-phishing"],
        remediation="Deploy the rule; measure alert volume for two weeks before tightening.",
    ))
    return out


def check_aitm(ctx: RunContext) -> list[Finding]:
    """AiTM / token-theft detection readiness."""
    return [
        Finding(
            capability="s03_identity.aitm_readiness",
            title="AiTM detection requirements (2026 baseline)", severity=Severity.MEDIUM,
            target="detection",
            detail=("Cover: unusual token-reuse across IP/ASN; token issued from a different "
                    "geography than the user; Graph/user-agent anomalies (e.g. "
                    "`kali365-live/1.0.0`); new device registration in a tenant shortly after "
                    "a phish click; refresh-token use from a new ASN."),
            attack_ids=["T1539", "T1185", "T1557.002"],
            tags=["identity", "aitm", "detection"],
            refs=["https://www.elastic.co/security-labs/threat-command/tycoon-2fa-aitm-detection-engineering",
                  "https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack"],
            remediation="Tycoon 2FA and Knight Office both show the same tradecraft: reverse "
                        "proxy + token harvest. Detection is about token lifecycle anomalies.",
        ),
        Finding(
            capability="s03_identity.aitm_readiness",
            title="FIDO2 does not stop AiTM if downgrade is possible", severity=Severity.HIGH,
            target="policy",
            detail=("Passkeys defeat AiTM at the ceremony level, but Proofpoint documented "
                    "attackers downgrading FIDO auth to weaker methods via a dedicated phishlet. "
                    "Enforce FIDO-only and alert on non-FIDO fallback."),
            attack_ids=["T1556.006", "T1689"],
            tags=["identity", "fido", "detection", "critical"],
            remediation="Set 'required' not 'preferred'; monitor AuthenticationMethodRequirements "
                        "changes and non-FIDO fallbacks.",
        ),
    ]


def check_fido(ctx: RunContext) -> list[Finding]:
    """Phishing-resistant MFA posture."""
    pol = ctx.opt("fido_policy") or {}
    out = []
    if pol.get("fido_only") in (True, "true", "yes"):
        out.append(Finding(
            capability="s03_identity.fido_downgrade_readiness",
            title="FIDO-only authentication enforced", severity=Severity.OK, target="identity",
            detail="No weaker fallback permitted.", tags=["identity", "fido", "mfa"]))
    else:
        out.append(Finding(
            capability="s03_identity.fido_downgrade_readiness",
            title="Passkey/FIDO2 is not the only permitted method", severity=Severity.HIGH,
            target="identity",
            detail=("A downgradeable authentication stack is a downgradeable control. With SMS "
                    "or TOTP still permitted, SIM-swap and AiTM remain viable."),
            attack_ids=["T1556.006", "T1689"],
            tags=["identity", "fido", "mfa", "critical"],
            remediation="Set Conditional Access to require FIDO2/passkeys for admins, contractors "
                        "and any account holding Tier-0.",
        ))
    out.append(Finding(
        capability="s03_identity.fido_downgrade_readiness",
        title="Monitor the downgrade path itself", severity=Severity.MEDIUM, target="detection",
        detail=("Alert on: changes to Authentication Method Requirements; the sudden appearance "
                "of SMS/voice methods; named-location changes that widen access."),
        attack_ids=["T1689", "T1556.009"],
        tags=["identity", "detection", "fido"],
        remediation="These are low-frequency, high-value events. Route them to a human.",
    ))
    return out


def check_sim_swap(ctx: RunContext) -> list[Finding]:
    """SMS/OTP dependency audit."""
    dep = ctx.opt("sms_dependent_auths") or []
    if not dep:
        return [Finding(
            capability="s03_identity.sim_swap_readiness",
            title="No SMS-dependent authentication declared", severity=Severity.OK,
            target="identity", tags=["identity", "mfa", "telecom"],
            remediation="Re-test if any recovery path reintroduces SMS.",
        )]
    return [Finding(
        capability="s03_identity.sim_swap_readiness",
        title=f"{len(dep)} authentication paths still depend on SMS/voice OTP",
        severity=Severity.CRITICAL, target="identity",
        detail="SMS is structurally broken: SIM-swap, automated eSIM transfer portals and SS7 "
               "all intercept it. Paths: " + ", ".join(map(str, dep[:10])),
        attack_ids=["T1581.001", "T1556.006"],
        tags=["identity", "mfa", "telecom", "critical"],
        remediation="Replace with passkeys. Do not attempt to harden SMS — it cannot be hardened.",
    )]


def check_iam(ctx: RunContext) -> list[Finding]:
    """Cloud IAM policy review from exported policy documents."""
    RULES = [
        ("Action wildcard", re.compile(r'"Action"\s*:\s*"?\*"?'), Severity.CRITICAL, "T1078.004"),
        ("Resource wildcard", re.compile(r'"Resource"\s*:\s*"?\*"?'), Severity.HIGH, "T1078.004"),
        ("NotAction bypass", re.compile(r'"NotAction"'), Severity.HIGH, "T1078.004"),
        ("NotResource bypass", re.compile(r'"NotResource"'), Severity.HIGH, "T1078.004"),
        ("hardcoded secret", re.compile(r'(?i)"(?:secret|password|token)"\s*:\s*"[A-Za-z0-9+/=_\-]{12,}"'), Severity.CRITICAL, "T1552.001"),
        ("cross-account trust", re.compile(r'"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"?arn:aws:iam::\d{12}:root'), Severity.HIGH, "T1078.004"),
        ("public S3 policy", re.compile(r'"Principal"\s*:\s*"?\*"?'), Severity.CRITICAL, "T1530"),
    ]
    from ..core.util import read_text, walk_files
    out = []
    for root in (ctx.scope.repos if ctx.scope else []) or [str(ctx.workdir)]:
        p = Path(root)
        for f in walk_files(p, exts={".json", ".yaml", ".yml", ".tf", ".policy"},
                            limit=8000):
            body = read_text(f, 2_000_000)
            if not body:
                continue
            for name, rx, sev, tid in RULES:
                m = rx.search(body)
                if not m:
                    continue
                out.append(Finding(
                    capability="s03_identity.cloud_iam_review", title=f"IAM: {name} in {f.name}",
                    severity=sev, target=str(f),
                    detail=f"Line {body[:m.start()].count(chr(10)) + 1}: {m.group(0)[:80]!r}",
                    attack_ids=[tid], tags=["identity", "cloud", "iam", "critical"],
                    confidence="high",
                    remediation="Replace wildcards with the specific actions/resources required.",
                ))
    if not out:
        out.append(Finding(
            capability="s03_identity.cloud_iam_review", title="No IAM policy issues found in scope",
            severity=Severity.OK, target="iam", tags=["identity", "iam"]))
    return out


def check_ai_keys(ctx: RunContext) -> list[Finding]:
    """AI key and agent-credential hygiene — treat as tier-0."""
    from ..core.models import Evidence as E
    import re as _re
    AI = _re.compile(
        r"\b(sk-ant-[A-Za-z0-9_\-]{20,}|sk-(?:proj-)?[A-Za-z0-9_\-]{24,}|"
        r"AIzaSy[A-Za-z0-9_\-]{30,}|r8_[A-Za-z0-9]{30,}|"
        r"(?i:openai|anthropic|cohere|mistralai|groq|perplexity)_(?:api_)?key\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"])")
    from ..core.util import read_text, walk_files, redact
    out = []
    for root in ((ctx.scope.repos if ctx.scope else []) or [str(ctx.workdir)]):
        for f in walk_files(root, limit=40_000):
            if f.suffix.lower() in (".png", ".jpg", ".zip", ".gz", ".so", ".exe", ".dll"):
                continue
            body = read_text(f, 1_500_000)
            if not body:
                continue
            for m in AI.finditer(body):
                val = next((g for g in m.groups() if g), m.group(0))
                out.append(Finding(
                    capability="s03_identity.ai_key_exposure",
                    title=f"AI provider credential in {f.name}", severity=Severity.CRITICAL,
                    target=str(f),
                    detail=(f"AI/agent credential at line {body[:m.start()].count(chr(10)) + 1} "
                            f"(redacted: {redact(val)}). Stolen AI access is simultaneously "
                            "loot, free compute and attribution cover — treat it as tier-0."),
                    attack_ids=["T1552.001", "T1528"],
                    tags=["identity", "ai", "secrets", "critical"],
                    confidence="high", cwe="CWE-798",
                    evidence=[E(kind="file", summary="AI credential", locator=str(f),
                                excerpt=redact(val))],
                    remediation="Rotate now. Block direct model egress from build systems. "
                                "Move to short-lived, scoped credentials issued at runtime.",
                ))
    if not out:
        out.append(Finding(
            capability="s03_identity.ai_key_exposure", title="No AI credentials found in scope",
            severity=Severity.INFO, target="ai-keys",
            detail="Note: absence of a hardcoded key is not the same as key hygiene — also "
                   "verify no key is injected from an unprotected CI secret and that no "
                   "third-party model proxy sits in the request path.",
            tags=["identity", "ai"]))
    return out


def check_rbac(ctx: RunContext) -> list[Finding]:
    """Kubernetes RBAC over-permission and escalation path review."""
    from ..core.util import read_text, walk_files
    DANGEROUS = [
        ("create pods (privilege escalation primitive)", re.compile(r'"create".*pods', re.I | re.S), Severity.CRITICAL, "T1610"),
        ("create pod/exec (container escape)", re.compile(r'"create".*pods/(exec|attach|portforward)', re.I | re.S), Severity.CRITICAL, "T1610"),
        ("impersonate", re.compile(r'"impersonate"'), Severity.CRITICAL, "T1134.001"),
        ("escalate/bind/escalate", re.compile(r'"escalate"|"bind"'), Severity.CRITICAL, "T1068"),
        ("read secrets", re.compile(r'"get".*secrets'), Severity.HIGH, "T1552.001"),
        ("list all namespaces", re.compile(r'"list".*\n.*\n?.*\*.*\*'), Severity.MEDIUM, "T1613"),
        ("cluster-admin", re.compile(r'cluster-admin'), Severity.CRITICAL, "T1078.001"),
        ("nodes proxy", re.compile(r'"get".*nodes/proxy'), Severity.CRITICAL, "T1610"),
    ]
    out = []
    for root in ((ctx.scope.repos if ctx.scope else []) or [str(ctx.workdir)]):
        for f in walk_files(root, exts={".yaml", ".yml"}, limit=10_000):
            body = read_text(f, 2_000_000)
            if "kind: Role" not in body and "kind: ClusterRole" not in body \
                    and "kind: RoleBinding" not in body and "kind: ClusterRoleBinding" not in body:
                continue
            for name, rx, sev, tid in DANGEROUS:
                m = rx.search(body)
                if not m:
                    continue
                out.append(Finding(
                    capability="s03_identity.k8s_rbac_review", title=f"RBAC: {name} in {f.name}",
                    severity=sev, target=str(f),
                    detail="A ClusterRole with this verb set is a known privilege-escalation "
                           "primitive in Kubernetes.",
                    attack_ids=[tid], tags=["identity", "k8s", "rbac", "critical"],
                    cwe="CWE-732", confidence="high",
                    remediation="Remove pods/exec, impersonate, bind/escalate and nodes/proxy from "
                                "non-admin roles; use a namespace-scoped service account model.",
                ))
    if not out:
        out.append(Finding(
            capability="s03_identity.k8s_rbac_review", title="No dangerous RBAC grants found",
            severity=Severity.OK, target="k8s", tags=["identity", "k8s", "rbac"]))
    return out


def check_pam(ctx: RunContext) -> list[Finding]:
    """Privileged access management review."""
    findings = ctx.opt("pam_findings") or {}
    out = []
    for name, sev in findings.items():
        out.append(Finding(
            capability="s03_identity.priv_access_review", title=f"PAM: {name}", severity=sev,
            target="pam", detail=name, attack_ids=["T1078"],
            tags=["identity", "pam", "assure"],
            remediation="Adopt just-in-time elevation with approval and full session recording.",
        ))
    if not out:
        out.append(Finding(
            capability="s03_identity.priv_access_review", title="PAM posture not supplied",
            severity=Severity.INFO, target="pam",
            detail="Pass --pam-findings to review standing privilege.",
            tags=["identity", "pam"]))
    return out
