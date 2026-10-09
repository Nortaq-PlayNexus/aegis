"""The capability catalog.

This is the single source of truth for "what can this suite do, and how".
Every capability names its providers. If no provider is runnable, `aegis coverage`
reports it as a gap. That is the contract.
"""
from __future__ import annotations

from .models import Capability, Domain, Phase, Provider, ProviderKind

# install command helpers
def WINGET(pkg: str) -> str:
    return f"winget install -e --id {pkg}"


def GO(pkg: str) -> str:
    return f"go install {pkg}"


def PIP(pkg: str) -> str:
    return f"pip install {pkg}"


def C(cid, title, domain, phase, summary="", **kw) -> Capability:
    return Capability(id=cid, title=title, domain=domain, phase=phase,
                      summary=summary, **kw)


def N(ref: str, summary: str = "") -> Provider:
    return Provider(kind=ProviderKind.NATIVE, ref=ref, summary=summary or "built into AEGIS")


def D(image: str, summary: str, install: str = "", **kw) -> Provider:
    return Provider(kind=ProviderKind.DOCKER, ref=image, summary=summary,
                    install=install or f"docker pull {image}", **kw)


def L(binary: str, summary: str, install: str = "", aliases: list[str] | None = None,
      **kw) -> Provider:
    return Provider(kind=ProviderKind.LOCAL, ref=binary, summary=summary,
                    install=install, requires=aliases or [], **kw)


def R(api: str, summary: str, env: list[str] | None = None, **kw) -> Provider:
    return Provider(kind=ProviderKind.REMOTE, ref=api, summary=summary,
                    env={k: "1" for k in (env or [])}, **kw)


def M(ref: str, summary: str, install: str = "", **kw) -> Provider:
    return Provider(kind=ProviderKind.MANUAL, ref=ref, summary=summary,
                    install=install, **kw)


CATALOG: list[Capability] = []
add = CATALOG.append


# ══════════════════════════════════════════════════════════ S01 · RECON
D1 = Domain.RECON

add(C("subdomain_enum", "Subdomain enumeration", D1, Phase.RECON,
      "Passive + active subdomain discovery across many sources.",
      providers=[
          D("projectdiscovery/subfinder:latest", "PD subfinder"),
          L("subfinder", "PD subfinder (native binary)", GO("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")),
          D("owasp/amass:latest", "OWASP Amass"),
          L("amass", "OWASP Amass", GO("github.com/owasp-amass/amass/v4/...@master"), aliases=["amass4"]),
          D("projectdiscovery/chaos:latest", "ProjectDiscovery Chaos"),
          N("aegis.suites.s01_recon:check_subdomain_enum", "AEGIS native multi-source enum"),
      ],
      attack_ids=["T1590.002", "T1590.001"],
      inputs=["domain"], outputs=["subdomain"], tags=["recon", "dns", "dorks"],
      references=["https://projectdiscovery.io", "https://github.com/owasp-amass/amass"]))

add(C("ct_log_mining", "Certificate Transparency mining", D1, Phase.RECON,
      "Mine CT logs for issued names — highest-yield single source.",
      providers=[N("aegis.suites.s01_recon:check_ct_logs",
                   "crt.sh + certspotter native"),
                 R("crt.sh", "crt.sh CT search", env=["NET"]),
                 R("certspotter", "SSLMate CertSpotter", env=["CERTSPOTTER_API_KEY"])],
      attack_ids=["T1590.003"],
      inputs=["domain"], outputs=["subdomain", "cert"], tags=["recon", "certs", "crt"],
      references=["https://crt.sh", "https://sslmate.com/certspotter/"]))

add(C("dns_records", "DNS record & zone analysis", D1, Phase.ENUMERATE,
      "A/AAAA/MX/NS/TXT/CNAME/SOA, zone-transfer attempts, SPF/DMARC posture.",
      providers=[D("projectdiscovery/dnsx:latest", "PD dnsx"),
                 L("dnsx", "PD dnsx", GO("github.com/projectdiscovery/dnsx/cmd/dnsx@latest")),
                 N("aegis.suites.s01_recon:check_dns", "AEGIS native DNS via dnspython")],
      attack_ids=["T1016", "T1590"],
      inputs=["domain"], outputs=["dns"], tags=["recon", "dns", "emailsec"],
      references=["https://github.com/projectdiscovery/dnsx"]))

add(C("dns_zone_transfer", "DNS zone transfer", D1, Phase.ENUMERATE,
      "Attempt AXFR against authoritative nameservers.",
      providers=[N("aegis.suites.s01_recon:check_axfr", "native AXFR attempt")],
      attack_ids=["T1584.004"], inputs=["domain"], outputs=["dns"],
      tags=["recon", "dns"], references=[]))

add(C("http_probe", "HTTP service probing", D1, Phase.ENUMERATE,
      "Liveness, status, title, tech, webserver, content-length, favicon hash.",
      providers=[D("projectdiscovery/httpx:latest", "PD httpx"),
                 L("httpx", "PD httpx", GO("github.com/projectdiscovery/httpx/cmd/httpx@latest")),
                 N("aegis.suites.s01_recon:check_http_probe", "AEGIS native prober")],
      attack_ids=["T1592.001"], inputs=["host", "url"], outputs=["http", "tech"],
      tags=["recon", "http"], references=["https://projectdiscovery.io"]))

add(C("port_scan", "Port scanning", D1, Phase.ENUMERATE,
      "TCP/UDP discovery, service version banners.",
      default_active=True,
      providers=[N("aegis.suites.s01_recon:check_port_scan", "AEGIS native TCP connect scanner"),
                 D("insecurelysofficial/1.5.7-uclibc:latest", "nmap (alpine base)", privileged=True),
                 L("nmap", "nmap", WINGET(pkg="Insecure.Nmap"), aliases=["nmap.exe"]),
                 D("projectdiscovery/naabu:latest", "PD naabu", privileged=True),
                 L("naabu", "PD naabu", GO("github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"))],
      attack_ids=["T1046"], inputs=["host", "cidr"], outputs=["port", "banner"],
      tags=["recon", "network"], references=["https://nmap.org"]))

add(C("service_fingerprint", "Service & version fingerprinting", D1, Phase.ENUMERATE,
      "Web tech, TLS, SSH, SMTP, DB fingerprints from banners and responses.",
      providers=[D("projectdiscovery/httpx:latest", "PD httpx -tech-detect"),
                 N("aegis.suites.s01_recon:check_service_fingerprint", "AEGIS native fingerprint")],
      attack_ids=["T1592"], inputs=["host", "url"], outputs=["tech", "banner"],
      tags=["recon", "fingerprint"], references=[]))

add(C("bgp_asn_map", "BGP / ASN / routing map", D1, Phase.RECON,
      "ASN ownership, prefix announcements, ROA/RPKI validity, upstream visibility.",
      providers=[D("projectdiscovery/asnmap:latest", "PD asnmap"),
                 L("asnmap", "PD asnmap", GO("github.com/projectdiscovery/asnmap/cmd/asnmap@latest")),
                 R("ripestat", "RIPEstat API", env=["NET"]),
                 N("aegis.suites.s01_recon:check_bgp", "AEGIS native BGP/RPKI via RIPEstat")],
      attack_ids=["T1590"], inputs=["asn", "cidr"], outputs=["bgp", "asn"],
      tags=["recon", "bgp", "network"],
      references=["https://stat.ripe.net", "https://bgp.tools"]))

add(C("bgp_hijack_detect", "BGP route-hijack detection", D1, Phase.DETECT,
      "Detect prefix hijacks by comparing live routing against RPKI ROAs.",
      default_active=True,
      providers=[R("ris", "RIPEstat RIS", env=["NET"]),
                 D("projectdiscovery/asnmap:latest", "PD asnmap"),
                 M("bgpmon", "BGP monitoring subscription", install="bgp.tools / RIPE RIS account")],
      attack_ids=["T1598", "T1600.001"], inputs=["asn", "prefix"], outputs=["bgp", "alert"],
      tags=["recon", "bgp", "detection", "military"], references=["https://ris.ripe.net"]))

add(C("historical_infra", "Historical infrastructure (Wayback / Common Crawl)", D1, Phase.RECON,
      "Recover retired hosts, old paths, defaced content, prior tech.",
      providers=[N("aegis.suites.s01_recon:check_history", "AEGIS native Wayback+CC client"),
                 R("wayback", "Wayback CDX API", env=["NET"]),
                 R("commoncrawl", "Common Crawl index", env=["NET"])],
      attack_ids=["T1590"], inputs=["domain"], outputs=["url", "host"],
      tags=["recon", "history", "archive"],
      references=["https://web.archive.org", "https://commoncrawl.org"]))

add(C("search_engine_recon", "Search-engine dorking", D1, Phase.RECON,
      "Google/Bing/GitHub dork sweeps for leaked material and forgotten endpoints.",
      providers=[N("aegis.suites.s01_recon:check_dorking", "AEGIS native dork engine")],
      attack_ids=["T1593.001", "T1593.002"],
      inputs=["domain"], outputs=["url", "secret"], tags=["recon", "dorks"],
      references=[]))

add(C("code_secret_search", "Public code & secret search", D1, Phase.RECON,
      "Search public repos, pastes, gists for credentials and config.",
      providers=[N("aegis.suites.s01_recon:check_paste_leak", "AEGIS native paste+code search"),
                 R("grepapp", "grep.app code search", env=["NET"]),
                 R("github_api", "GitHub code search", env=["GITHUB_TOKEN"]),
                 M("shodan_api", "Shodan / Censys API", install="shodan account (free tier available)")],
      attack_ids=["T1593", "T1552.001"],
      inputs=["domain", "org"], outputs=["secret", "repo"], tags=["recon", "secrets", "code"],
      references=["https://grep.app"]))

add(C("exposed_files", "Exposed file & metadata discovery", D1, Phase.ENUMERATE,
      ".env, .git, backups, config files, source maps, directory listing.",
      default_active=True,
      providers=[D("projectdiscovery/nuclei:latest", "nuclei exposure templates"),
                 L("nuclei", "nuclei", GO("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")),
                 N("aegis.suites.s01_recon:check_exposed_files", "AEGIS native exposure probe")],
      attack_ids=["T1526", "T1530"], inputs=["url"], outputs=["url", "exposure"],
      tags=["recon", "exposure", "http"],
      references=["https://github.com/projectdiscovery/nuclei-templates"]))

add(C("dir_fuzz", "Directory / file fuzzing", D1, Phase.ENUMERATE,
      "Content discovery with wordlists and recursion.",
      default_active=True,
      providers=[L("ffuf", "ffuf", GO("github.com/ffuf/ffuf/v2@latest")),
                 L("dirsearch", "dirsearch", PIP("dirsearch"), aliases=["dirsearch.py"]),
                 D("projectdiscovery/katana:latest", "PD katana crawler"),
                 N("aegis.suites.s01_recon:check_dir_fuzz", "AEGIS native fuzzer (SecLists)")],
      attack_ids=["T1595.003"], inputs=["url"], outputs=["url"],
      tags=["recon", "fuzzing", "web"], references=["https://github.com/ffuf/ffuf"]))

add(C("endpoint_crawl", "Endpoint & parameter crawling", D1, Phase.ENUMERATE,
      "Crawl JS/HTML for hidden params, routes, secrets.",
      default_active=True,
      providers=[D("projectdiscovery/katana:latest", "PD katana"),
                 L("katana", "PD katana", GO("github.com/projectdiscovery/katana/cmd/katana@latest")),
                 N("aegis.suites.s01_recon:check_crawl", "AEGIS native crawler")],
      attack_ids=["T1595.002"], inputs=["url"], outputs=["url", "param", "secret"],
      tags=["recon", "crawl", "web"], references=["https://github.com/projectdiscovery/katana"]))

add(C("api_discovery", "API surface discovery", D1, Phase.ENUMERATE,
      "Find OpenAPI/Swagger/GraphQL endpoints and enumerate operations.",
      default_active=True,
      providers=[D("projectdiscovery/katana:latest", "katana -graphql flag"),
                 N("aegis.suites.s01_recon:check_api_discovery", "AEGIS native OpenAPI/GraphQL discovery")],
      attack_ids=["T1592.002", "T1190"], inputs=["url"], outputs=["api", "endpoint"],
      tags=["recon", "api", "graphql"], references=[]))

add(C("vuln_scan", "Known-vulnerability scanning", D1, Phase.ANALYZE,
      "Template-driven checks of known issues across hosts and URLs.",
      default_active=True,
      providers=[D("projectdiscovery/nuclei:latest", "nuclei"),
                 L("nuclei", "nuclei", GO("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")),
                 N("aegis.suites.s01_recon:check_nuclei_native", "AEGIS native template subset")],
      attack_ids=["T1190"], inputs=["url", "host", "cidr"], outputs=["vuln"],
      tags=["recon", "vuln", "scan"], references=["https://docs.projectdiscovery.io/templates"]))

add(C("oob_validation", "Out-of-band interaction validation", D1, Phase.EXPLOIT,
      "Confirm blind SSRF/XXE/RCE/desync via an interaction server.",
      default_active=True,
      providers=[D("projectdiscovery/interactsh:latest", "PD interactsh server"),
                 L("interactsh-server", "interactsh-server", GO("github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest")),
                 L("interactsh-client", "interactsh client", GO("github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")),
                 N("aegis.suites.s01_recon:check_oob", "AEGIS native OOB client stub")],
      attack_ids=["T1189", "T1190"], inputs=["url"], outputs=["oob"],
      tags=["recon", "oob", "validation"], references=["https://github.com/projectdiscovery/interactsh"]))

add(C("whois_registrant", "Domain registration intel", D1, Phase.RECON,
      "Registrar, NS, registrant, creation date, nameservers, abuse contact.",
      providers=[N("aegis.suites.s01_recon:check_whois", "AEGIS native RDAP client")],
      attack_ids=["T1590"], inputs=["domain"], outputs=["whois"],
      tags=["recon", "whois"], references=["https://rdap.org"]))

add(C("email_surface", "Email & mail surface", D1, Phase.ENUMERATE,
      "MX inventory, SPF/DMARC/DKIM posture, disposable/temporary mail detection, mail harvest.",
      providers=[N("aegis.suites.s01_recon:check_email_surface", "AEGIS native MX/SPF/DMARC audit")],
      attack_ids=["T1589.002"], inputs=["domain"], outputs=["mx", "email", "posture"],
      tags=["recon", "email", "spf"], references=[]))

add(C("osint_social", "Social account discovery", D1, Phase.RECON,
      "Resolve a handle to real accounts across networks (authorised subjects only).",
      providers=[L("sherlock", "sherlock", PIP("sherlock-project"), aliases=["sherlock-project"]),
                 L("maigret", "maigret", PIP("maigret"), aliases=["maigret3"]),
                 N("aegis.suites.s01_recon:check_osint_social", "AEGIS native handle check")],
      attack_ids=["T1589.003"], inputs=["username"], outputs=["account"],
      tags=["osint", "social"],
      references=["https://github.com/sherlock-project/sherlock", "https://github.com/soxoj/maigret"]))

add(C("phone_domain_osint", "Phone & personal-surface OSINT", D1, Phase.RECON,
      "Phone footprint, breach correlations, domain registrant pivots.",
      providers=[L("phoneinfoga", "phoneinfoga", GO("github.com/sundowndev/phoneinfoga/cmd/phoneinfoga@latest"), aliases=["phoneinfoga-cli"]),
                 N("aegis.suites.s01_recon:check_phone_osint", "AEGIS native")],
      attack_ids=["T1589"], inputs=["phone"], outputs=["phone", "breach"],
      tags=["osint", "phone"], references=["https://github.com/sundowndev/phoneinfoga"]))

add(C("typosquat_registry", "Package-registry typosquat sweep", D1, Phase.RECON,
      "Check whether look-alike names are registrable in public registries.",
      providers=[N("aegis.suites.s01_recon:check_typosquat", "AEGIS native registry + permutations")],
      attack_ids=["T1583.001"], inputs=["package", "org"], outputs=["package"],
      tags=["recon", "supplychain", "brand"], references=[]))

add(C("geolocate_target", "Geolocation & IP intel", D1, Phase.RECON,
      "Geolocate hosts; flag datacenter vs residential; map to physical locations.",
      providers=[R("ipinfo", "ipinfo.io", env=["IPINFO_TOKEN"]),
                 R("ipapi", "ip-api.com (free)", env=["NET"]),
                 N("aegis.suites.s01_recon:check_geo", "AEGIS native geo + ASN")],
      attack_ids=["T1590.003"], inputs=["ip"], outputs=["geo", "asn"],
      tags=["recon", "geo", "intel"], references=[]))

add(C("cloud_asset_discovery", "Cloud asset discovery (storage/API surface)", D1, Phase.RECON,
      "Find publicly exposed buckets, functions, queues, dev endpoints for an org.",
      providers=[L("cloud_enum", "cloud_enum", PIP("cloud_enum")),
                 M("prowler", "prowler (also in S04)", install="docker pull prowler/prowler"),
                 N("aegis.suites.s01_recon:check_cloud_enum", "AEGIS native bucket/API discovery")],
      attack_ids=["T1583.001", "T1526"], inputs=["org", "keyword"], outputs=["cloud_asset"],
      tags=["recon", "cloud", "storage"], references=["https://github.com/initstring/cloud_enum"]))

add(C("tls_inventory", "TLS / certificate inventory", D1, Phase.ENUMERATE,
      "Certificate chain, expiry, protocol/cipher posture, SAN enumeration.",
      providers=[D("projectdiscovery/tlsx:latest", "PD tlsx"),
                 L("tlsx", "PD tlsx", GO("github.com/projectdiscovery/tlsx/cmd/tlsx@latest")),
                 N("aegis.suites.s01_recon:check_tls", "AEGIS native TLS audit")],
      attack_ids=["T1592"], inputs=["host", "url"], outputs=["tls", "cert"],
      tags=["recon", "tls", "crypto"], references=[]))

# ══════════════════════════════════════════════════════════ S02 · SURFACE
D2 = Domain.SURFACE

add(C("asset_inventory", "Attack-surface inventory", D2, Phase.ANALYZE,
      "Unify assets from every recon source into a deduplicated inventory with ownership.",
      providers=[N("aegis.suites.s02_surface:check_inventory", "AEGIS native inventory builder")],
      attack_ids=["T1589"], inputs=["domain", "file"], outputs=["asset"],
      tags=["surface", "inventory"], references=[]))

add(C("dangling_dns", "Dangling DNS record detection", D2, Phase.ANALYZE,
      "CNAME/MX/NS/PTR to deallocated providers = subdomain takeover.",
      providers=[N("aegis.suites.s02_surface:check_dangling", "AEGIS native dangling-record audit")],
      attack_ids=["T1584.001", "T1583.001"],
      inputs=["domain", "subdomain"], outputs=["takeover"],
      tags=["surface", "dns", "takeover"],
      references=["https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"]))

add(C("subdomain_takeover", "Subdomain takeover exploitation check", D2, Phase.EXPLOIT,
      "Confirm a dangling record is actually claimable (authorised validation only).",
      default_active=True,
      providers=[D("projectdiscovery/nuclei:latest", "takeover templates"),
                 L("nuclei", "nuclei", GO("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")),
                 N("aegis.suites.s02_surface:check_takeover_validate", "AEGIS native claim-probe")],
      attack_ids=["T1583.001"], inputs=["subdomain"], outputs=["takeover"],
      tags=["surface", "takeover"], references=[]))

add(C("shadow_domains", "Shadow / expired-domain monitoring", D2, Phase.DETECT,
      "Watch for expiring, newly-registered, and typosquat domains targeting the org.",
      providers=[R("rdap", "RDAP expiry checks", env=["NET"]),
                 L("amass", "amass -enum -src", GO("github.com/owasp-amass/amass/v4/...@master")),
                 N("aegis.suites.s02_surface:check_shadow_domains", "AEGIS native RDAP+permutation watch")],
      attack_ids=["T1583.001"], inputs=["domain"], outputs=["domain", "alert"],
      tags=["surface", "phishing", "monitor"], references=[]))

add(C("pale_asset_fingerprint", "Pale / forgotten asset fingerprinting", D2, Phase.ANALYZE,
      "Favicon-hash and stack matching to find forgotten staging/legacy assets.",
      default_active=True,
      providers=[D("projectdiscovery/httpx:latest", "httpx -favicon"),
                 L("httpx", "PD httpx", GO("github.com/projectdiscovery/httpx/cmd/httpx@latest")),
                 N("aegis.suites.s02_surface:check_pale_assets", "AEGIS native favicon matcher")],
      attack_ids=["T1590.002"], inputs=["url", "cidr"], outputs=["asset"],
      tags=["surface", "fingerprint", "shadow"], references=[]))

add(C("cloud_storage_exposure", "Public cloud storage exposure", D2, Phase.ANALYZE,
      "Anonymous-read/write on buckets and blob endpoints.",
      default_active=True,
      providers=[M("prowler", "prowler storage checks", install="docker pull prowler/prowler"),
                 L("cloud_enum", "cloud_enum", PIP("cloud_enum")),
                 N("aegis.suites.s02_surface:check_storage", "AEGIS native anonymous-read probe")],
      attack_ids=["T1530", "T1526"], inputs=["bucket", "org"], outputs=["exposure"],
      tags=["surface", "cloud", "storage"], references=[]))

add(C("exposure_graph", "Attack-path / exposure graph", D2, Phase.ANALYZE,
      "Build a graph of assets → relationships → reachable risk, and rank paths.",
      providers=[N("aegis.suites.s02_surface:build_exposure_graph", "AEGIS native graph (networkx)")],
      attack_ids=["T1210"], inputs=["inventory"], outputs=["graph", "path"],
      tags=["surface", "graph", "attackpath"],
      references=["https://github.com/DataDog/KubeHound"]))

add(C("exposure_scoring", "Exposure risk scoring", D2, Phase.ANALYZE,
      "Rank inventory by exploitability, data sensitivity, and business criticality.",
      providers=[N("aegis.suites.s02_surface:score_exposure", "AEGIS native scoring")],
      attack_ids=[], inputs=["inventory"], outputs=["score", "rank"],
      tags=["surface", "risk", "prioritisation"], references=[]))

add(C("third_party_shadow", "Third-party / SaaS shadow discovery", D2, Phase.ANALYZE,
      "Enumerate OAuth apps, exposed tenants, vendor portals, forgotten admin consoles.",
      default_active=True,
      providers=[D("projectdiscovery/nuclei:latest", "exposure + misconfig templates"),
                 N("aegis.suites.s02_surface:check_third_party", "AEGIS native")],
      attack_ids=["T1526"], inputs=["domain", "org"], outputs=["asset", "saas"],
      tags=["surface", "saas", "thirdparty"], references=[]))

add(C("admin_panel_discovery", "Admin console discovery", D2, Phase.ENUMERATE,
      "Find exposed admin/management endpoints and default consoles.",
      default_active=True,
      providers=[D("projectdiscovery/nuclei:latest", "exposures"),
                 N("aegis.suites.s02_surface:check_admin", "AEGIS native")],
      attack_ids=["T1190"], inputs=["url"], outputs=["url", "admin"],
      tags=["surface", "admin", "http"], references=[]))

add(C("default_credential_check", "Default credential testing (authorised)", D2, Phase.EXPLOIT,
      "Test vendor-default creds on in-scope services only.",
      default_active=True,
      providers=[N("aegis.suites.s02_surface:check_default_creds",
                   "AEGIS native bounded test (top-N vendors, scope-gated)"),
                 L("netexec", "netexec (CrackMapExec lineage)", PIP("netexec"), aliases=["nxc", "crackmapexec"]),
                 L("hydra", "hydra", WINGET(pkg="Kirale.Hydra"), aliases=["thc-hydra"])],
      attack_ids=["T1110.001", "T1078.001"],
      inputs=["host", "scope"], outputs=["credential"],
      tags=["surface", "auth", "exploit"], references=["https://github.com/Pennyw0rth/NetExec"]))

add(C("drift_monitor", "Asset & configuration drift monitor", D2, Phase.DETECT,
      "Re-run inventory on a schedule and diff against baseline to find new exposure.",
      providers=[N("aegis.suites.s02_surface:check_drift", "AEGIS native baseline diff")],
      attack_ids=["T1136"], inputs=["baseline", "inventory"], outputs=["drift", "alert"],
      tags=["surface", "monitor", "drift"], references=[]))

# ══════════════════════════════════════════════════════════ S03 · IDENTITY
D3 = Domain.IDENTITY

add(C("ad_attack_path", "Active Directory attack-path graph", D3, Phase.ANALYZE,
      "Collect AD graph data and enumerate paths from low-priv to Domain Admin.",
      providers=[L("BloodHound", "BloodHound CE", PIP("bloodhound")),
                 L("SharpHound", "SharpHound.exe", install="download from bloodhound.specterops.io"),
                 L("sharphound", "sharphound", install="via BloodHound CE py package"),
                 N("aegis.suites.s03_identity:check_ad_path", "AEGIS native graph builder (LDAP)")],
      attack_ids=["T1068.002", "T1098.007", "T1558.003"],
      inputs=["domain", "dc"], outputs=["graph", "path"],
      tags=["identity", "ad", "attackpath"],
      references=["https://bloodhound.specterops.io"]))

add(C("adcs_abuse", "AD Certificate Services abuse", D3, Phase.ANALYZE,
      "Enumerate templates, CA ACLs, enrollee permissions, and escalation paths.",
      providers=[L("certipy-ad", "Certipy-AD", PIP("certipy-ad"), aliases=["certipy"]),
                 N("aegis.suites.s03_identity:check_adcs", "AEGIS native LDAP template audit")],
      attack_ids=["T1649", "T1553.004", "T1134.002"],
      inputs=["domain", "dc"], outputs=["path", "finding"],
      tags=["identity", "ad", "adcs", "certs"],
      references=["https://github.com/ly4k/Certipy"]))

add(C("kerberos_weakness", "Kerberos posture", D3, Phase.ANALYZE,
      "AS-REP roasting exposure, FAST flags, weak encryption types, delegation abuse.",
      providers=[L("netexec", "netexec", PIP("netexec"), aliases=["nxc"]),
                 L("impacket", "impacket", PIP("impacket"), aliases=["GetUserSPNs.py"]),
                 N("aegis.suites.s03_identity:check_kerberos", "AEGIS native Kerberos audit")],
      attack_ids=["T1558.003", "T1558.001", "T1550.003"],
      inputs=["domain", "dc"], outputs=["finding"],
      tags=["identity", "kerberos", "ad"], references=[]))

add(C("ldap_enum", "LDAP enumeration", D3, Phase.ENUMERATE,
      "Directory tree walk, privileged group membership, ACL review.",
      providers=[L("ldapsearch", "ldapsearch (openldap)", install="apt/choco openldap"),
                 L("netexec", "netexec", PIP("netexec"), aliases=["nxc"]),
                 N("aegis.suites.s03_identity:check_ldap", "AEGIS native ldap3")],
      attack_ids=["T1087.002", "T1069.002"],
      inputs=["domain", "dc"], outputs=["object", "user", "group"],
      tags=["identity", "ldap", "ad"], references=[]))

add(C("smb_enum", "SMB / RPC enumeration", D3, Phase.ENUMERATE,
      "Share enumeration, session listing, signing state, named-pipe exposure.",
      providers=[L("netexec", "netexec", PIP("netexec"), aliases=["nxc"]),
                 L("smbclient", "smbclient (samba)", install="samba tools"),
                 N("aegis.suites.s03_identity:check_smb", "AEGIS native SMB")],
      attack_ids=["T1135", "T1021.002"],
      inputs=["host", "domain"], outputs=["share", "session"],
      tags=["identity", "smb"], references=[]))

add(C("ad_delegation", "AD delegation abuse surface", D3, Phase.ANALYZE,
      "Constrained/unconstrained delegation, gMSA exposure, RBCM weakness.",
      providers=[L("netexec", "netexec", PIP("netexec"), aliases=["nxc"]),
                 M("adeleg", "ADeleg", install="github.com/joe-ilt/ADeleg"),
                 N("aegis.suites.s03_identity:check_delegation", "AEGIS native")],
      attack_ids=["T1134.006", "T1550.003"],
      inputs=["domain", "dc"], outputs=["finding", "path"],
      tags=["identity", "delegation", "ad"], references=[]))

add(C("shadow_credentials", "Shadow credential detection", D3, Phase.DETECT,
      "Find msDS-KeyCredentialLink / shadow-cred artefacts and their paths.",
      providers=[L("BloodHound", "BloodHound CE", PIP("bloodhound")),
                 L("netexec", "netexec", PIP("netexec"), aliases=["nxc"]),
                 N("aegis.suites.s03_identity:check_shadow_creds", "AEGIS native LDAP")],
      attack_ids=["T1556.005", "T1134.006"],
      inputs=["domain", "dc"], outputs=["finding", "path"],
      tags=["identity", "credentials", "ad"], references=[]))

add(C("dc_hardening", "Domain controller hardening audit", D3, Phase.ANALYZE,
      "SMB signing, LDAP signing/channel binding, SMBv1, weak protocols, DCShadow surface.",
      providers=[L("impacket", "impacket", PIP("impacket"), aliases=["nltest"]),
                 L("netexec", "netexec", PIP("netexec"), aliases=["nxc"]),
                 N("aegis.suites.s03_identity:check_dc_hardening", "AEGIS native")],
      attack_ids=["T1207", "T1550.002"],
      inputs=["host", "domain"], outputs=["finding"],
      tags=["identity", "hardening", "ad"], references=[]))

add(C("mimikatz_indicators", "Credential-dumping indicator hunt", D3, Phase.DETECT,
      "Hunt for LSASS access, comsvcs.dll MiniDump, sekurlsa, DCSync patterns.",
      providers=[L("sigma_cli", "sigma-cli", install="sigma-cli"),
                 L("hayabusa", "hayabusa", install="github.com/Yamato-Security/hayabusa/releases"),
                 N("aegis.suites.s03_identity:check_cred_dump_indicators", "AEGIS native evtx/EDR logic")],
      attack_ids=["T1003.001", "T1003.003", "T1003.006"],
      inputs=["evtx", "log"], outputs=["finding", "event"],
      tags=["identity", "hunting", "defense"], references=[]))

add(C("entra_assess", "Entra ID / cloud identity assessment", D3, Phase.ANALYZE,
      "Role assignments, legacy auth, app registrations, consent risk, MFA coverage.",
      providers=[M("entraaudit", "Entra audit (Graph)", env=["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]),
                 M("pacu", "Pacu", install="pip install pacu"),
                 N("aegis.suites.s03_identity:check_entra", "AEGIS native Graph checklist auditor")],
      attack_ids=["T1528", "T1136.003", "T1606.002"],
      inputs=["tenant"], outputs=["finding", "role"],
      tags=["identity", "entra", "cloud"], references=[]))

add(C("device_code_readiness", "Device-code phishing readiness", D3, Phase.DETECT,
      "Assess whether non-interactive device-authorisation flows are monitored.",
      providers=[L("chainsaw", "chainsaw", install="github.com/WithSecureOpenSource/chainsaw/releases"),
                 L("hayabusa", "hayabusa", install="github.com/Yamato-Security/hayabusa/releases"),
                 N("aegis.suites.s03_identity:check_device_code", "AEGIS native detection audit")],
      attack_ids=["T1550.001", "T1528"],
      inputs=["log", "config"], outputs=["gap", "rule"],
      tags=["identity", "phishing", "detection", "detectiongap"],
      references=["https://github.com/WithSecureOpenSource/chainsaw"]))

add(C("aitm_readiness", "AiTM / token-theft readiness", D3, Phase.DETECT,
      "Assess coverage for session-cookie theft, unusual token issuance, and replay.",
      providers=[N("aegis.suites.s03_identity:check_aitm", "AEGIS native"),
                 L("sigma_cli", "sigma-cli", install="sigma-cli")],
      attack_ids=["T1539", "T1185", "T1557.002"],
      inputs=["log", "config"], outputs=["gap", "rule"],
      tags=["identity", "aitm", "detection", "detectiongap"], references=[]))

add(C("fido_downgrade_readiness", "Phishing-resistant MFA downgrade readiness", D3, Phase.DETECT,
      "Verify FIDO2 is enforced with no fallback, and that downgrade is monitored.",
      providers=[N("aegis.suites.s03_identity:check_fido", "AEGIS native policy auditor")],
      attack_ids=["T1556.006", "T1689"],
      inputs=["policy", "config"], outputs=["gap", "finding"],
      tags=["identity", "fido", "mfa", "detectiongap"],
      references=["https://www.proofpoint.com/us/blog/threat-insight/dont-phish-let-me-down-fido-authentication-downgrade"]))

add(C("sim_swap_readiness", "SIM-swap / OTP resilience readiness", D3, Phase.ASSURE,
      "Audit whether any critical MFA still depends on SMS/voice.",
      providers=[N("aegis.suites.s03_identity:check_sim_swap", "AEGIS native")],
      attack_ids=["T1581.001"], inputs=["policy", "config"], outputs=["gap", "finding"],
      tags=["identity", "mfa", "telecom"], references=[]))

add(C("cloud_iam_review", "Cloud IAM over-permission review", D3, Phase.ANALYZE,
      "Excessive roles, cross-account trust, wildcard policies, unused keys.",
      default_active=True,
      providers=[M("prowler", "prowler IAM checks", install="docker pull prowler/prowler"),
                 M("cloudsploit", "cloudsploit", install="npm i -g cloudsploit"),
                 N("aegis.suites.s03_identity:check_iam", "AEGIS native policy parser")],
      attack_ids=["T1078.004", "T1098.001", "T1552.001"],
      inputs=["account", "policy"], outputs=["finding", "role"],
      tags=["identity", "cloud", "iam"], references=[]))

add(C("ai_key_exposure", "AI key & agent-credential exposure", D3, Phase.DETECT,
      "Hunt for exposed LLM/agent API keys, tokens, and unrotated sessions — treat as tier-0.",
      providers=[D("trufflesecurity/trufflehog:latest", "trufflehog verified-secret scan"),
                 L("gitleaks", "gitleaks", WINGET(pkg="zricethezav.gitleaks")),
                 L("trufflehog", "trufflehog", GO("github.com/trufflesecurity/trufflehog@latest")),
                 N("aegis.suites.s03_identity:check_ai_keys", "AEGIS native provider-pattern scan")],
      attack_ids=["T1552.001", "T1528"],
      inputs=["repo", "path", "file"], outputs=["secret", "finding"],
      tags=["identity", "ai", "secrets", "critical"],
      references=["https://github.com/trufflesecurity/trufflehog"]))

add(C("k8s_rbac_review", "Kubernetes RBAC over-permission", D3, Phase.ANALYZE,
      "Wildcard verbs/resources, privilege-escalation paths via create-pod, secrets access.",
      default_active=True,
      providers=[M("kubeaudit", "kubeaudit", install="go install github.com/Shopify/kubeaudit@latest"),
                 D("aquasec/kubescape:latest", "kubescape"),
                 M("rbac-scan", "rbac-scan (personal-operator)", install="docker pull safercloud/rbac-scan"),
                 N("aegis.suites.s03_identity:check_rbac", "AEGIS native RBAC parser")],
      attack_ids=["T1610", "T1552.001", "T1068"],
      inputs=["manifest", "cluster"], outputs=["path", "finding"],
      tags=["identity", "k8s", "rbac", "attackpath"], references=[]))

add(C("priv_access_review", "Privileged access review", D3, Phase.ASSURE,
      "Standing admin accounts, shared creds, no just-in-time, dormant privilege.",
      providers=[N("aegis.suites.s03_identity:check_pam", "AEGIS native")],
      attack_ids=["T1078"], inputs=["directory", "report"], outputs=["finding"],
      tags=["identity", "pam", "assure"], references=[]))

# ══════════════════════════════════════════════════════════ S04 · SUPPLY CHAIN
D4 = Domain.SUPPLYCHAIN

add(C("secret_scan", "Secret scanning", D4, Phase.DETECT,
      "Pattern + entropy + verification secret detection across code, history, images, IaC.",
      providers=[D("trufflesecurity/trufflehog:latest", "trufflehog (verified)"),
                 L("gitleaks", "gitleaks", WINGET(pkg="zricethezav.gitleaks")),
                 L("trufflehog", "trufflehog", GO("github.com/trufflesecurity/trufflehog@latest")),
                 D("zricethezav/gitleaks:latest", "gitleaks (container)"),
                 N("aegis.suites.s04_supplychain:scan_secrets", "AEGIS native multi-pattern scan")],
      attack_ids=["T1552.001", "T1552.004"],
      inputs=["repo", "path", "file", "image"], outputs=["secret", "finding"],
      tags=["supplychain", "secrets", "critical"],
      references=["https://github.com/gitleaks/gitleaks"]))

add(C("sbom_generate", "SBOM generation", D4, Phase.PREPARE,
      "CycloneDX/SPDX SBOM from filesystem, container image, or repo.",
      providers=[D("anchore/syft:latest", "syft"),
                 L("syft", "syft", WINGET(pkg="Anchore.Syft")),
                 N("aegis.suites.s04_supplychain:sbom_generate", "AEGIS native SPDX-lite generator")],
      attack_ids=[], inputs=["path", "image"], outputs=["sbom"],
      tags=["supplychain", "sbom", "compliance"],
      references=["https://github.com/anchore/syft"]))

add(C("sbom_verify", "SBOM policy verification", D4, Phase.DETECT,
      "Check an SBOM against policy: banned licences, unknown components, EOL packages.",
      providers=[N("aegis.suites.s04_supplychain:sbom_verify", "AEGIS native SBOM policy engine"),
                 D("anchore/grype:latest", "grype (vuln view)"),
                 L("grype", "grype", WINGET(pkg="Anchore.Grype"))],
      attack_ids=[], inputs=["sbom", "policy"], outputs=["finding"],
      tags=["supplychain", "sbom", "policy"], references=[]))

add(C("dependency_vuln", "Dependency vulnerability scanning", D4, Phase.ANALYZE,
      "CVE/known-vuln matching against lockfiles and SBOMs with reachability awareness.",
      providers=[D("aquasec/trivy:latest", "trivy"),
                 L("trivy", "trivy", WINGET(pkg="AquaSecurity.Trivy")),
                 D("anchore/grype:latest", "grype"),
                 L("grype", "grype", WINGET(pkg="Anchore.Grype")),
                 D("google/osv-scanner:latest", "osv-scanner"),
                 L("osv-scanner", "osv-scanner", GO("github.com/google/osv-scanner/cmd/osv-scanner@latest")),
                 L("pip-audit", "pip-audit", PIP("pip-audit")),
                 N("aegis.suites.s04_supplychain:scan_deps", "AEGIS native lockfile parser + OSV")],
      attack_ids=["T1195.001"], inputs=["path", "lockfile", "sbom"], outputs=["vuln"],
      tags=["supplychain", "vuln", "deps"], references=[]))

add(C("container_scan", "Container image scanning", D4, Phase.ANALYZE,
      "OS packages, app deps, secrets, and config inside images.",
      default_active=True,
      providers=[D("aquasec/trivy:latest", "trivy image"),
                 L("trivy", "trivy", WINGET(pkg="AquaSecurity.Trivy")),
                 D("anchore/grype:latest", "grype"),
                 N("aegis.suites.s04_supplychain:scan_image", "AEGIS native manifest+layer inspect")],
      attack_ids=["T1195.002"], inputs=["image"], outputs=["vuln", "secret"],
      tags=["supplychain", "container", "vuln"], references=[]))

add(C("iac_scan", "Infrastructure-as-code scanning", D4, Phase.ANALYZE,
      "Terraform/CloudFormation/K8s manifests for misconfig and over-permission.",
      providers=[D("bridgecrew/checkov:latest", "checkov"),
                 L("checkov", "checkov", PIP("checkov")),
                 D("aquasec/trivy:latest", "trivy config"),
                 D("aquasecurity/tfsec:latest", "tfsec"),
                 L("tfsec", "tfsec", WINGET(pkg="aquasecurity.tfsec")),
                 D("aquasec/kubescape:latest", "kubescape"),
                 N("aegis.suites.s04_supplychain:scan_iac", "AEGIS native IaC rule engine")],
      attack_ids=["T1526"], inputs=["path", "tf", "yaml"], outputs=["misconfig"],
      tags=["supplychain", "iac", "cloud", "config"], references=[]))

add(C("cicd_audit", "CI/CD pipeline audit", D4, Phase.ANALYZE,
      "Workflow permissions, self-hosted runner risk, secret exposure, OIDC trust.",
      providers=[N("aegis.suites.s04_supplychain:audit_cicd", "AEGIS native workflow analyser"),
                 M("zizmor", "zizmor (GH Actions static analysis)", install="pip install zizmor"),
                 M("scanner", "CI-specific scanner", install="vendor tooling"),
                 D("aquasec/trivy:latest", "trivy config (workflows)")],
      attack_ids=["T1195.001", "T1552.001", "T1078.004"],
      inputs=["path", "github"], outputs=["finding", "workflow"],
      tags=["supplychain", "cicd", "critical"], references=[]))

add(C("provenance_verify", "Build provenance verification", D4, Phase.DETECT,
      "Verify SLSA/in-toto attestations and signatures on artifacts.",
      providers=[D("sigstore/cosign:latest", "cosign verify"),
                 L("cosign", "cosign", GO("github.com/sigstore/cosign/v2/cmd/cosign@latest")),
                 M("slsa-verifier", "slsa-verifier", install="go install github.com/slsa-framework/slsa-verifier/v2/...@latest"),
                 N("aegis.suites.s04_supplychain:verify_provenance", "AEGIS native attestation parser")],
      attack_ids=["T1195.001"], inputs=["artifact", "attestation"], outputs=["verdict", "finding"],
      tags=["supplychain", "slsa", "sigstore", "provenance", "critical"],
      references=["https://slsa.dev", "https://github.com/sigstore/cosign"]))

add(C("signature_hygiene", "Signing-key & keyless hygiene", D4, Phase.ASSURE,
      "Are release keys short-lived, keyless, hardware-backed, and rotated?",
      providers=[N("aegis.suites.s04_supplychain:audit_signing", "AEGIS native")],
      attack_ids=["T1553.002"], inputs=["config", "workflow"], outputs=["gap", "finding"],
      tags=["supplychain", "signing", "keys", "assure"], references=[]))

add(C("malicious_package_scan", "Malicious package behaviour scan", D4, Phase.ANALYZE,
      "Install scripts, obfuscated payloads, unicode smuggling, postinstall hooks.",
      providers=[N("aegis.suites.s04_supplychain:scan_package", "AEGIS native behaviour heuristics"),
                 D("trufflesecurity/trufflehog:latest", "trufflehog on package tree"),
                 N("aegis.suites.s04_supplychain:unicode_scan", "AEGIS invisible-unicode detector")],
      attack_ids=["T1195.001", "T1027.018"],
      inputs=["package", "archive"], outputs=["finding", "finding"],
      tags=["supplychain", "malware", "unicode", "critical"],
      references=["https://attack.mitre.org/techniques/T1027/018/"]))

add(C("registry_presence", "Registry & distribution-channel audit", D4, Phase.ANALYZE,
      "Is the package published everywhere it should be — and nowhere it should not?",
      providers=[N("aegis.suites.s04_supplychain:audit_registries", "AEGIS native registry queries")],
      attack_ids=["T1195.001"], inputs=["package"], outputs=["finding"],
      tags=["supplychain", "registry"], references=[]))

add(C("selfhosted_runner_exposure", "Self-hosted runner exposure", D4, Phase.DETECT,
      "Internet-reachable runners are the pivot in most CI/CD compromises.",
      default_active=True,
      providers=[N("aegis.suites.s04_supplychain:check_runners", "AEGIS native"),
                 D("aquasec/trivy:latest", "trivy config"),
                 M("gh_api", "GitHub API", env=["GITHUB_TOKEN"])],
      attack_ids=["T1195.001"], inputs=["github", "host"], outputs=["finding", "exposure"],
      tags=["supplychain", "cicd", "exposure"], references=[]))

add(C("artifact_registry_exposure", "Artifact registry exposure", D4, Phase.DETECT,
      "Anonymous read/pull on package registries and artifact stores.",
      default_active=True,
      providers=[N("aegis.suites.s04_supplychain:check_registries_exposed", "AEGIS native anon probe")],
      attack_ids=["T1530"], inputs=["registry"], outputs=["exposure"],
      tags=["supplychain", "exposure", "registry"], references=[]))

add(C("sast_scan", "Static analysis (SAST)", D4, Phase.ANALYZE,
      "Pattern-based source review for injection, secrets, dangerous sinks.",
      providers=[D("semgrep/semgrep:latest", "semgrep"),
                 L("semgrep", "semgrep", PIP("semgrep")),
                 L("bandit", "bandit (python)", PIP("bandit")),
                 N("aegis.suites.s04_supplychain:sast", "AEGIS native pattern rules")],
      attack_ids=["T1190", "T1059"], inputs=["path"], outputs=["finding", "code"],
      tags=["supplychain", "sast", "code"], references=[]))

add(C("license_policy", "OSS licence policy", D4, Phase.ASSURE,
      "Flag copyleft, unknown, and conflicting licences against org policy.",
      providers=[N("aegis.suites.s04_supplychain:license_audit", "AEGIS native")],
      attack_ids=[], inputs=["sbom", "path"], outputs=["finding"],
      tags=["supplychain", "compliance", "licence"], references=[]))

# ══════════════════════════════════════════════════════════ S05 · DETECTION
D5 = Domain.DETECTION

add(C("attack_coverage_map", "ATT&CK coverage mapping", D5, Phase.ASSURE,
      "Map the org's detections/emulations against the ATT&CK technique matrix.",
      providers=[N("aegis.suites.s05_detection:coverage_map", "AEGIS native (v19-aware)")],
      attack_ids=[], inputs=["rules", "matrix"], outputs=["coverage", "gap"],
      tags=["detection", "assure", "attack"], references=["https://attack.mitre.org"]))

add(C("defense_impairment_gap", "Defense Impairment (TA0112) gap analysis", D5, Phase.ASSURE,
      "New v19 tactic — nobody has rules yet. Enumerate the 18 techniques and test coverage.",
      providers=[N("aegis.suites.s05_detection:defense_impairment_gap", "AEGIS native")],
      attack_ids=["T1685", "T1686", "T1687", "T1689", "T1690", "T1688", "T1553"],
      inputs=["rules", "logs"], outputs=["gap", "rule"],
      tags=["detection", "attack", "critical", "new2026"],
      references=["https://attack.mitre.org/tactics/TA0112/"]))

add(C("stealth_gap", "Stealth (TA0005) coverage gap", D5, Phase.ASSURE,
      "Broad behavioural baselining coverage for concealment techniques.",
      providers=[N("aegis.suites.s05_detection:stealth_gap", "AEGIS native")],
      attack_ids=["T1564", "T1036", "T1070", "T1562"], inputs=["rules"], outputs=["gap"],
      tags=["detection", "attack", "new2026"],
      references=["https://attack.mitre.org/tactics/TA0005/"]))

add(C("sigma_authoring", "Sigma rule authoring", D5, Phase.PREPARE,
      "Scaffold, lint, and unit-test a Sigma rule against the local corpus.",
      providers=[L("sigma_cli", "sigma-cli", install="pip install sigma-cli"),
                 L("sigma", "sigma (pySigma)", install="pip install pysigma"),
                 N("aegis.suites.s05_detection:sigma_scaffold", "AEGIS native scaffold+validate")],
      attack_ids=[], inputs=["technique", "logsource"], outputs=["rule"],
      tags=["detection", "sigma", "dac"], references=["https://github.com/SigmaHQ/sigma"]))

add(C("sigma_validate", "Sigma rule validation", D5, Phase.DETECT,
      "Parse, type-check, and test rules; catch field/logsource mistakes before deploy.",
      providers=[L("sigma_cli", "sigma-cli", install="pip install sigma-cli"),
                 N("aegis.suites.s05_detection:sigma_validate", "AEGIS native")],
      attack_ids=[], inputs=["rule", "path"], outputs=["verdict", "error"],
      tags=["detection", "sigma", "dac"], references=[]))

add(C("dac_pipeline", "Detection-as-Code pipeline", D5, Phase.ASSURE,
      "CI that lints, tests, and diffs detections on every change; emits coverage delta.",
      providers=[N("aegis.suites.s05_detection:dac_pipeline", "AEGIS native CI recipe generator")],
      attack_ids=[], inputs=["repo"], outputs=["pipeline", "report"],
      tags=["detection", "dac", "cicd"], references=[]))

add(C("log_source_coverage", "Log-source coverage audit", D5, Phase.ASSURE,
      "Which required log sources are actually collected, parsed, and searchable?",
      providers=[N("aegis.suites.s05_detection:log_source_audit", "AEGIS native")],
      attack_ids=[], inputs=["config", "log"], outputs=["gap", "source"],
      tags=["detection", "logging", "assure"], references=[]))

add(C("sysmon_config_audit", "Sysmon configuration audit", D5, Phase.ASSURE,
      "Compare deployed Sysmon config to reference; find blind spots in event coverage.",
      providers=[N("aegis.suites.s05_detection:sysmon_audit", "AEGIS native")],
      attack_ids=["T1055", "T1003", "T1059.001"], inputs=["config"], outputs=["gap", "finding"],
      tags=["detection", "sysmon", "windows", "endpoint"], references=[]))

add(C("ebpf_rule_audit", "eBPF runtime rule coverage", D5, Phase.ASSURE,
      "Validate Falco/Tetragon policy coverage and flag known evasion classes (io_uring, eBPF rootkits).",
      providers=[N("aegis.suites.s05_detection:ebpf_rule_audit", "AEGIS native")],
      attack_ids=["T1564.001", "T1014"], inputs=["rules"], outputs=["gap", "finding"],
      tags=["detection", "ebpf", "runtime"],
      references=["https://falco.org", "https://tetragon.io"]))

add(C("ids_rule_review", "IDS/IPS rule review", D5, Phase.ASSURE,
      "Review Suricata/etc. rulesets for coverage of the org's known protocols.",
      providers=[N("aegis.suites.s05_detection:ids_rule_review", "AEGIS native"),
                 D("projectdiscovery/nuclei:latest", "nuclei as traffic oracle")],
      attack_ids=[], inputs=["rules"], outputs=["gap", "finding"],
      tags=["detection", "ids", "network"], references=[]))

add(C("siem_ingest_check", "SIEM ingest & parse validation", D5, Phase.DETECT,
      "Confirm key log sources parse correctly end-to-end in the SIEM pipeline.",
      providers=[N("aegis.suites.s05_detection:siem_ingest_check", "AEGIS native")],
      attack_ids=[], inputs=["log", "config"], outputs=["verdict", "gap"],
      tags=["detection", "siem", "logging"], references=[]))

add(C("control_integrity_monitor", "Control-integrity monitoring", D5, Phase.DETECT,
      "Monitor the defender's own stack: log gaps, agent health, policy drift, rule disablement.",
      providers=[N("aegis.suites.s05_detection:control_integrity", "AEGIS native")],
      attack_ids=["T1685", "T1685.003", "T1562.008"],
      inputs=["config", "log", "agent"], outputs=["alert", "finding"],
      tags=["detection", "defenseimpairment", "critical"],
      references=[]))

add(C("alert_tuning_baseline", "Alert baseline & tuning", D5, Phase.ASSURE,
      "Baseline detection volume, surface true-positive ratio, propose suppression safely.",
      providers=[N("aegis.suites.s05_detection:alert_baseline", "AEGIS native")],
      attack_ids=[], inputs=["alerts", "log"], outputs=["baseline", "proposal"],
      tags=["detection", "siem", "tuning"], references=[]))

add(C("killchain_telemetry", "Kill-chain telemetry coverage", D5, Phase.ASSURE,
      "For each tactic, is there a source that can observe it? Produces a source map.",
      providers=[N("aegis.suites.s05_detection:killchain_telemetry", "AEGIS native")],
      attack_ids=[], inputs=["config"], outputs=["map", "gap"],
      tags=["detection", "assure", "telemetry"], references=[]))

add(C("emulation_validate", "Emulation-validated detection", D5, Phase.DETECT,
      "Prove detections fire by running atomic tests and correlating to alerts.",
      providers=[M("invoke_atomicredteam", "Invoke-AtomicRedTeam", install="git clone redcanaryco/atomic-red-team"),
                 M("stratus", "Stratus Red Team", install="docker run keinos/stratus-red-team"),
                 N("aegis.suites.s05_detection:emulation_validate", "AEGIS native correlation")],
      attack_ids=[], inputs=["technique"], outputs=["result", "gap"],
      tags=["detection", "purple", "emulation"], references=["https://www.atomicredteam.io"]))

# ══════════════════════════════════════════════════════════ S06 · RESPONSE
D6 = Domain.RESPONSE

add(C("ioc_enrich", "IOC enrichment", D6, Phase.RESPOND,
      "Expand indicators across reputation, geo, ASN, passive DNS, malware family.",
      providers=[N("aegis.suites.s06_response:enrich_iocs", "AEGIS native multi-source"),
                 R("virustotal", "VirusTotal", env=["VIRUSTOTAL_API_KEY"]),
                 R("abusech", "abuse.ch ThreatFox/MalwareBazaar", env=["NET"]),
                 R("greynoise", "GreyNoise", env=["GREYNOISE_API_KEY"]),
                 R("otx", "AlienVault OTX", env=["OTX_API_KEY"])],
      attack_ids=[], inputs=["ioc"], outputs=["verdict", "context"],
      tags=["response", "enrich", "intel"],
      references=["https://threatfox.abuse.ch"]))

add(C("ioc_validate", "IOC validation & false-positive triage", D6, Phase.RESPOND,
      "Confirm an indicator is genuinely malicious before you act on it.",
      providers=[N("aegis.suites.s06_response:validate_ioc", "AEGIS native")],
      attack_ids=[], inputs=["ioc"], outputs=["verdict"], tags=["response", "triage"], references=[]))

add(C("threat_feed_sync", "Threat-intel feed sync", D6, Phase.PREPARE,
      "Pull and normalise feeds into a local store with provenance.",
      providers=[R("abusech", "abuse.ch feeds", env=["NET"]),
                 R("cisa_kev", "CISA KEV", env=["NET"]),
                 R("nvd", "NVD / OSV", env=["NET"]),
                 N("aegis.suites.s06_response:sync_feeds", "AEGIS native feed syncer")],
      attack_ids=[], inputs=[], outputs=["indicator"],
      tags=["response", "intel", "feed"],
      references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]))

add(C("intel_platform_sync", "MISP / OpenCTI integration", D6, Phase.RESPOND,
      "Push and pull indicators between AEGIS and your intel platform.",
      providers=[M("misp_api", "MISP REST", env=["MISP_URL", "MISP_KEY"]),
                 M("opencti_api", "OpenCTI GraphQL", env=["OPENCTI_URL", "OPENCTI_TOKEN"]),
                 N("aegis.suites.s06_response:intel_sync", "AEGIS native adapter")],
      attack_ids=[], inputs=["indicator"], outputs=["sync"],
      tags=["response", "cti", "integration"], references=[]))

add(C("triage_automation", "Indicator triage", D6, Phase.RESPOND,
      "One-shot triage of hashes, URLs, domains, IPs across many sources.",
      providers=[L("malwoverview", "malwoverview", PIP("malwoverview")),
                 N("aegis.suites.s06_response:triage", "AEGIS native triage")],
      attack_ids=[], inputs=["ioc", "file"], outputs=["verdict", "context"],
      tags=["response", "triage"], references=["https://github.com/alexandreborges/malwoverview"]))

add(C("malware_triage", "Malware capability triage", D6, Phase.RESPOND,
      "Extract capabilities, packer, and behaviour flags from suspicious binaries.",
      providers=[D("mandiant/capa:latest", "capa"),
                 L("capa", "capa", install="pip install flare-capa"),
                 L("diec", "Detect It Easy CLI", install="Detect It Easy"),
                 N("aegis.suites.s06_response:malware_triage", "AEGIS native static triage")],
      attack_ids=[], inputs=["file", "hash"], outputs=["capability", "verdict"],
      tags=["response", "malware", "triage"], references=["https://github.com/mandiant/capa"]))

add(C("yara_prep", "YARA rule authoring & corpus", D6, Phase.DETECT,
      "Write rules, build test corpora, manage signatures, watch for silent failures.",
      providers=[L("yara", "yara", PIP("yara-python"), aliases=["yara64"]),
                 L("yara-x", "yara-x", install="cargo install yara-x-cli"),
                 N("aegis.suites.s06_response:yara_author", "AEGIS native rule builder")],
      attack_ids=[], inputs=["rule", "sample"], outputs=["rule", "match"],
      tags=["response", "yara", "detection"], references=[]))

add(C("pcap_analysis", "PCAP / network forensics", D6, Phase.RESPOND,
      "Protocol dissection, C2 beacon detection, JA3/JA4, DNS-tunnel and exfil analysis.",
      providers=[L("tshark", "tshark", WINGET(pkg="WiresharkFoundation.TShark"), aliases=["wireshark"]),
                 D("ghcr.io/arkime/arkime:latest", "Arkime (full session capture)"),
                 N("aegis.suites.s06_response:pcap_analyse", "AEGIS native (dpkt/scapy-free analysis)")],
      attack_ids=["T1041", "T1071", "T1572"], inputs=["pcap"], outputs=["finding", "flow"],
      tags=["response", "network", "forensics"],
      references=["https://github.com/arkime/arkime"]))

add(C("log_analysis", "Log analysis & hunting", D6, Phase.RESPOND,
      "Fast hunts across Windows/AD/cloud logs with Sigma-backed rules.",
      providers=[L("chainsaw", "chainsaw", install="github.com/WithSecureOpenSource/chainsaw/releases"),
                 L("hayabusa", "hayabusa", install="github.com/Yamato-Security/hayabusa/releases"),
                 L("plaso", "log2timeline (plaso)", PIP("plaso"), aliases=["log2timeline.py"]),
                 N("aegis.suites.s06_response:log_hunt", "AEGIS native hunters")],
      attack_ids=[], inputs=["log", "evtx", "rule"], outputs=["finding", "event"],
      tags=["response", "hunting", "forensics"], references=[]))

add(C("forensics_triage", "Endpoint forensics triage", D6, Phase.RESPOND,
      "Memory/disk triage, process trees, persistence discovery, anti-forensics detection.",
      providers=[L("vol", "volatility3", PIP("volatility3"), aliases=["vol.py"]),
                 L("chainsaw", "chainsaw", install="github.com/WithSecureOpenSource/chainsaw/releases"),
                 N("aegis.suites.s06_response:host_triage", "AEGIS native persistence hunt")],
      attack_ids=["T1014", "T1564", "T1070"], inputs=["image", "path"], outputs=["finding", "artifact"],
      tags=["response", "forensics", "dfir"], references=[]))

add(C("evidence_collect", "Evidence collection", D6, Phase.RESPOND,
      "Hash-chain and capture everything a finding produced, tamper-evidently.",
      providers=[N("aegis.suites.s06_response:collect_evidence", "AEGIS native")],
      attack_ids=[], inputs=["finding"], outputs=["evidence", "chain"],
      tags=["response", "evidence", "chainofcustody"], references=[]))

add(C("containment_verify", "Containment verification", D6, Phase.RESPOND,
      "Verify isolation actually holds: egress, identity, token revocation, segmentation.",
      providers=[N("aegis.suites.s06_response:verify_containment", "AEGIS native checklist")],
      attack_ids=["T1562"], inputs=["host", "account"], outputs=["verdict", "gap"],
      tags=["response", "containment"], references=[]))

add(C("eradicate_verify", "Eradication & recovery validation", D6, Phase.RECOVER,
      "Confirm persistence removed, creds rotated, builds/pipelines clean, backups verified.",
      providers=[N("aegis.suites.s06_response:verify_recovery", "AEGIS native")],
      attack_ids=["T1070", "T1195.001"], inputs=["host", "repo", "backup"], outputs=["verdict", "gap"],
      tags=["response", "recover", "assure"], references=[]))

add(C("breach_timeline", "Breach timeline construction", D6, Phase.RESPOND,
      "Correlate all evidence into a first-compromise → impact timeline.",
      providers=[N("aegis.suites.s06_response:build_timeline", "AEGIS native")],
      attack_ids=[], inputs=["finding", "log"], outputs=["timeline"],
      tags=["response", "timeline", "dfir"], references=[]))

add(C("mttd_measure", "Detection performance measurement", D6, Phase.ASSURE,
      "Measure MTTD/MTTR and detection-lag against known ground truth.",
      providers=[N("aegis.suites.s06_response:measure_mttd", "AEGIS native")],
      attack_ids=[], inputs=["timeline", "alert"], outputs=["metric"],
      tags=["response", "metrics", "assure"], references=[]))

add(C("underground_exposure", "Underground exposure monitoring", D6, Phase.RESPOND,
      "Track credential/host offers on forums and channels via vendor feeds.",
      providers=[M("kela", "KELA / DarkOwl / Flashpoint", install="licensed feed subscription"),
                 M("intelx", "Intelligence X API", env=["INTELX_API_KEY"]),
                 N("aegis.suites.s06_response:exposure_ledger", "AEGIS native ledger")],
      attack_ids=[], inputs=["org", "domain"], outputs=["exposure", "alert"],
      tags=["response", "underground", "leaks"], references=[]))

# ══════════════════════════════════════════════════════════ S07 · AI SEC
D7 = Domain.AISEC

add(C("llm_app_inventory", "LLM/agent application inventory", D7, Phase.PREPARE,
      "Find every place a model is called, an agent exists, or a key is configured.",
      providers=[N("aegis.suites.s07_aisec:llm_inventory", "AEGIS native repo/env scanner")],
      attack_ids=["T1588.007"], inputs=["path", "host"], outputs=["inventory", "finding"],
      tags=["ai", "inventory", "shadowai"], references=[]))

add(C("prompt_injection_test", "Prompt-injection testing", D7, Phase.EXPLOIT,
      "Direct + indirect injection suites against the app under test (authorised).",
      default_active=True,
      providers=[L("promptfoo", "promptfoo", install="npm i -g promptfoo"),
                 L("garak", "garak", PIP("garak")),
                 L("pyrit", "pyrit", PIP("pyrit")),
                 N("aegis.suites.s07_aisec:prompt_injection", "AEGIS native injection corpus")],
      attack_ids=["T1204.002", "T1683.001"],
      inputs=["url", "endpoint"], outputs=["finding", "attack"],
      tags=["ai", "prompt-injection", "critical"],
      references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"]))

add(C("agent_permission_audit", "Agent permission & tool-use audit", D7, Phase.ANALYZE,
      "Least-privilege for agents: which tools, which scopes, which approvals?",
      providers=[N("aegis.suites.s07_aisec:agent_permission_audit", "AEGIS native"),
                 M("agentops", "agent-observability platform", install="vendor/OSS agent tooling")],
      attack_ids=["T1098", "T1552.001"], inputs=["config", "repo"], outputs=["finding", "gap"],
      tags=["ai", "agent", "leastprivilege", "critical"], references=[]))

add(C("indirect_injection_surface", "Indirect-injection surface review", D7, Phase.ANALYZE,
      "If the agent can read web/email/repo data, treat it all as hostile input.",
      providers=[N("aegis.suites.s07_aisec:indirect_injection_surface", "AEGIS native"),
                 M("grafanaghost", "GrafanaGhost case study", install="reference only")],
      attack_ids=["T1204.002"], inputs=["config", "url"], outputs=["finding", "gap"],
      tags=["ai", "prompt-injection", "critical", "new2026"],
      references=["https://labs.cloudsecurityalliance.org/research/csa-research-note-indirect-prompt-injection-in-the-wild-2026/"]))

add(C("ai_supplychain_key_hygiene", "AI supply-chain credential hygiene", D7, Phase.DETECT,
      "Are model keys tier-0? Is egress blocked from build systems? Any reseller/proxy in path?",
      providers=[N("aegis.suites.s07_aisec:ai_key_hygiene", "AEGIS native"),
                 L("gitleaks", "gitleaks", WINGET(pkg="zricethezav.gitleaks"))],
      attack_ids=["T1552.001", "T1528"], inputs=["repo", "config", "env"], outputs=["gap", "secret"],
      tags=["ai", "keys", "supplychain", "critical", "new2026"],
      references=["https://www.anthropic.com/threat-intelligence-report-september-2026"]))

add(C("llm_config_review", "LLM configuration & system-prompt review", D7, Phase.ANALYZE,
      "Exposed system prompts, over-broad tool declarations, debug endpoints, model fallback.",
      providers=[N("aegis.suites.s07_aisec:llm_config_review", "AEGIS native")],
      attack_ids=["T1682"], inputs=["config", "repo"], outputs=["finding"],
      tags=["ai", "config", "prompt"], references=[]))

add(C("rag_poisoning_surface", "RAG / data-poisoning surface", D7, Phase.ANALYZE,
      "Ingestion paths, untrusted corpora, retrieval filters, tenant isolation in vector stores.",
      providers=[N("aegis.suites.s07_aisec:rag_surface", "AEGIS native")],
      attack_ids=["T1565.001"], inputs=["config", "repo"], outputs=["finding", "gap"],
      tags=["ai", "rag", "data"], references=[]))

add(C("model_supplychain", "Model & weight provenance", D7, Phase.ASSURE,
      "Model card, licence, training-data provenance, integrity of the weights you run.",
      providers=[N("aegis.suites.s07_aisec:model_provenance", "AEGIS native")],
      attack_ids=["T1195"], inputs=["model", "config"], outputs=["verdict", "gap"],
      tags=["ai", "provenance", "assure"], references=[]))

add(C("adversarial_ml_eval", "Adversarial-ML evaluation", D7, Phase.ANALYZE,
      "Evasion, poisoning, extraction, and inference attacks against your own models.",
      default_active=True,
      providers=[L("adversarial-robustness-toolbox", "adversarial-robustness-toolbox", PIP("adversarial-robustness-toolbox"), aliases=["art"]),
                 M("adversarial", "ART", install="pip install adversarial-robustness-toolbox"),
                 N("aegis.suites.s07_aisec:aml_eval", "AEGIS native")],
      attack_ids=["T1608.001"], inputs=["model"], outputs=["finding", "metric"],
      tags=["ai", "adversarial-ml", "mlops"], references=[]))

add(C("shadow_ai_detection", "Shadow AI detection", D7, Phase.DETECT,
      "Find unauthorised model usage, browser extensions, and unreviewed tools in the enterprise.",
      providers=[N("aegis.suites.s07_aisec:shadow_ai", "AEGIS native"),
                 D("projectdiscovery/httpx:latest", "proxy/extension discovery")],
      attack_ids=["T1567.002"], inputs=["proxy", "endpoint", "device"], outputs=["finding", "exposure"],
      tags=["ai", "shadowai", "detection"], references=[]))

add(C("ai_gateway_audit", "AI gateway & proxy audit", D7, Phase.ANALYZE,
      "What models does the gateway actually reach, and what leaves the network?",
      providers=[N("aegis.suites.s07_aisec:gateway_audit", "AEGIS native")],
      attack_ids=["T1041"], inputs=["config", "proxy"], outputs=["finding", "route"],
      tags=["ai", "egress", "proxy"], references=[]))

add(C("agent_exfil_test", "Agent-mediated exfiltration test", D7, Phase.EXPLOIT,
      "Can the agent be induced to send data out through a tool or a prompt? (authorised)",
      default_active=True,
      providers=[N("aegis.suites.s07_aisec:agent_exfil_test", "AEGIS native harness")],
      attack_ids=["T1041", "T1567"], inputs=["url", "config"], outputs=["finding"],
      tags=["ai", "exfil", "agent", "critical"], references=[]))

# ══════════════════════════════════════════════════════════ S08 · LAB
D8 = Domain.LAB

add(C("range_orchestrate", "Lab / range orchestration", D8, Phase.PREPARE,
      "Bring up isolated, disposable practice environments on demand.",
      providers=[M("docker", "Docker", install="docker desktop"),
                 M("vagrant", "Vagrant", install="https://www.vagrantup.com"),
                 L("docker", "docker", install="docker desktop")],
      attack_ids=[], inputs=["lab"], outputs=["lab", "endpoints"],
      tags=["lab", "emulation", "training"], references=[]))

add(C("vuln_lab_control", "Vulnerable-by-design lab control", D8, Phase.PREPARE,
      "Kubernetes Goat, TerraformGoat, Metarget, JuiceShop, DVWA-style targets.",
      providers=[M("docker", "containerised labs", install="docker pull + run"),
                 N("aegis.suites.s08_lab:lab_control", "AEGIS native lab manager")],
      attack_ids=[], inputs=["lab"], outputs=["status", "url"],
      tags=["lab", "training"], references=[]))

add(C("atomic_emulation", "Atomic attack emulation", D8, Phase.EXPLOIT,
      "Run individual ATT&CK-mapped atomic tests to validate detections.",
      default_active=True,
      providers=[M("atomic", "Invoke-AtomicRedTeam (Windows)",
                          install="git clone https://github.com/redcanaryco/atomic-red-team"),
                 M("atomic_linux", "atomic-red-team (Linux/macOS)", install="clone + shell-gym"),
                 N("aegis.suites.s08_lab:atomic_run", "AEGIS native safe atomic subset")],
      attack_ids=[], inputs=["technique"], outputs=["result", "event"],
      tags=["lab", "emulation", "purple"],
      references=["https://www.atomicredteam.io"]))

add(C("purple_team_runner", "Purple-team campaign runner", D8, Phase.EXPLOIT,
      "Chain emulations into a campaign and map each step to the detection that should fire.",
      default_active=True,
      providers=[M("caldera", "MITRE/Apache Caldera", install="docker run -p 8888:8888 mitre/caldera"),
                 N("aegis.suites.s08_lab:purple_campaign", "AEGIS native")],
      attack_ids=[], inputs=["profile"], outputs=["report", "gap"],
      tags=["lab", "purple", "campaign"], references=[]))

add(C("c2_sanitise", "C2 infrastructure sanitisation", D8, Phase.PREPARE,
      "Scrub operator artifacts from test infra so detections are not contaminated.",
      providers=[N("aegis.suites.s08_lab:c2_sanitise", "AEGIS native")],
      attack_ids=[], inputs=["dir"], outputs=["cleaned"],
      tags=["lab", "opsec", "c2"], references=[]))

add(C("detection_test_harness", "Detection test harness", D8, Phase.DETECT,
      "Feed controlled events to collectors and assert the expected alert fires.",
      providers=[N("aegis.suites.s08_lab:detection_harness", "AEGIS native")],
      attack_ids=[], inputs=["rule", "event"], outputs=["pass", "fail"],
      tags=["lab", "detection", "ci"], references=[]))

add(C("benchmark_run", "Assessment benchmark & metrics", D8, Phase.ASSURE,
      "Time, coverage, and reproducibility metrics for your own test programmes.",
      providers=[N("aegis.suites.s08_lab:benchmark", "AEGIS native")],
      attack_ids=[], inputs=["run"], outputs=["metrics"],
      tags=["lab", "metrics", "assure"], references=[]))

add(C("lab_lifecycle", "Lab teardown & hygiene", D8, Phase.RECOVER,
      "Destroy environments, purge artifacts, verify nothing is left reachable.",
      providers=[N("aegis.suites.s08_lab:lab_teardown", "AEGIS native")],
      attack_ids=[], inputs=["lab"], outputs=["status"],
      tags=["lab", "teardown", "hygiene"], references=[]))

# ══════════════════════════════════════════════════════════ S09 · ASSURE
D9 = Domain.ASSURE

add(C("control_mapping", "Control framework mapping", D9, Phase.ASSURE,
      "Map findings to CIS/NIST CSF/ISO and measure control effectiveness.",
      providers=[N("aegis.suites.s09_assure:map_controls", "AEGIS native mapping engine")],
      attack_ids=[], inputs=["finding", "framework"], outputs=["map", "gap"],
      tags=["assure", "compliance", "controls"], references=["https://www.nist.gov/cyberframework"]))

add(C("pqc_inventory", "Post-quantum crypto inventory", D9, Phase.ASSURE,
      "Where is your classical crypto? You cannot migrate what you cannot find.",
      providers=[N("aegis.suites.s09_assure:pqc_inventory", "AEGIS native crypto discovery")],
      attack_ids=["T1600.001"], inputs=["repo", "config", "host"], outputs=["inventory", "gap"],
      tags=["assure", "pqc", "crypto", "new2026"],
      references=["https://www.cisa.gov/topics/risk-management/quantum"]))

add(C("harvest_now_decrypt", "HNDL exposure review", D9, Phase.ASSURE,
      "Long-lived sensitive data that would be decryptable on Q-Day.",
      providers=[N("aegis.suites.s09_assure:hndl_review", "AEGIS native")],
      attack_ids=["T1600.001"], inputs=["inventory"], outputs=["gap", "priority"],
      tags=["assure", "pqc", "data"], references=[]))

add(C("supplychain_policy", "Supply-chain policy enforcement", D9, Phase.ASSURE,
      "Codify and enforce the org's supply-chain rules in CI.",
      providers=[N("aegis.suites.s09_assure:policy_engine", "AEGIS native policy-as-code")],
      attack_ids=["T1195.001"], inputs=["policy", "finding"], outputs=["verdict", "policy"],
      tags=["assure", "supplychain", "policy", "critical"], references=[]))

add(C("config_drift", "Configuration drift detection", D9, Phase.DETECT,
      "Detect drift from hardened baselines across hosts, containers, and IaC.",
      providers=[N("aegis.suites.s09_assure:drift_check", "AEGIS native")],
      attack_ids=["T1562"], inputs=["baseline", "target"], outputs=["drift", "finding"],
      tags=["assure", "drift", "hardening"], references=[]))

add(C("ics_control_check", "SANS 5 ICS critical controls", D9, Phase.ASSURE,
      "Assess the five controls that matter most for OT environments.",
      providers=[N("aegis.suites.s09_assure:ics_controls", "AEGIS native")],
      attack_ids=[], inputs=["evidence", "ot"], outputs=["map", "gap"],
      tags=["assure", "ics", "ot", "military"],
      references=["https://www.sans.org/white-papers/five-ics-critical-security-controls"]))

add(C("audit_trail", "Audit trail & accountability", D9, Phase.ASSURE,
      "Every action AEGIS takes is recorded; export it for audit.",
      providers=[N("aegis.suites.s09_assure:audit_export", "AEGIS native")],
      attack_ids=[], inputs=[], outputs=["trail"],
      tags=["assure", "audit", "compliance"], references=[]))

add(C("evidence_package", "Audit evidence package", D9, Phase.ASSURE,
      "Assemble a defensible, hash-chained evidence bundle for an engagement.",
      providers=[N("aegis.suites.s09_assure:evidence_package", "AEGIS native")],
      attack_ids=[], inputs=["run"], outputs=["package"],
      tags=["assure", "evidence", "audit"], references=[]))

add(C("continuous_monitor", "Continuous monitoring loop", D9, Phase.DETECT,
      "Re-run selected suites on a schedule; diff and alert on change.",
      providers=[N("aegis.suites.s09_assure:monitor_loop", "AEGIS native")],
      attack_ids=[], inputs=["schedule", "suite"], outputs=["drift", "alert"],
      tags=["assure", "monitor", "continuous"], references=[]))

add(C("metrics_rollup", "Risk metrics & trend rollup", D9, Phase.ASSURE,
      "Severity distribution, MTTR, coverage %, and trend over time.",
      providers=[N("aegis.suites.s09_assure:rollup", "AEGIS native")],
      attack_ids=[], inputs=["run"], outputs=["metrics", "trend"],
      tags=["assure", "metrics", "board"], references=[]))

add(C("executive_report", "Executive & technical reporting", D9, Phase.ASSURE,
      "Board-level narrative plus engineer-level detail from the same findings.",
      providers=[N("aegis.suites.s09_assure:report", "AEGIS native renderer")],
      attack_ids=[], inputs=["run"], outputs=["report"],
      tags=["assure", "reporting", "board"], references=[]))
