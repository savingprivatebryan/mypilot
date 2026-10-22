#!/usr/bin/env python3
"""CI gate: assert an assembled device tree is a correct MyPilot image.

Run with cwd = an assembled tree (after ``assemble.py build``), or pass --target <dir>. Exits
non-zero with a clear message on any violation, so the daily publish pipeline FAILS LOUDLY rather
than shipping an image that re-enabled sunnylink phone-home, never launches the agent, or lost SSH.

Usage:
  verify_assembled.py [--target DIR] [--expect-private] [--expect-public]
    --expect-private: also require the private layer's effects — used for a personal build,
                      NOT for public channels.
    --expect-public:  also assert the tree carries NO non-public content — no driving-bus reader
                      beyond the audited GPS line, and no forbidden tokens (secrets/keys/cloud/
                      private-layer effects). Use on the public/self-host build so a fork can never
                      publish a tree that quietly picked up private or unsafe content.
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import tokenize

PROC = "system/manager/process_config.py"
UI_STATE = "selfdrive/ui/sunnypilot/ui_state.py"

# --- SAFETY: the on-device agent must NEVER hold a persistent reader on openpilot's realtime msgq
# driving bus. A persistent (even conflate / near-zero-CPU) subscriber on a high-rate,
# validity-load-bearing service perturbs the safety consumers' receive timing -> a communication
# fault / "take control" state onroad (a proven on-device failure mode). The agent's own tests guard
# this in dev/CI; THIS gate enforces it on the SHIP path so a publish aborts if any agent module
# reintroduces a driving-bus reader. Scanned over the WHOLE assembled agent tree, not just one file.
_BUS_BANNED = ("SubMaster", "drain_sock", "vEgo", "gearShifter", "carState")  # never in agent code
_BUS_GATED = ("sub_sock", "recv_one", "conflate")  # subscription APIs, allowed ONLY on an audited line
_BUS_AUDIT_SENTINEL = "mypilot-gps-reader"  # the single sanctioned low-rate GPS reader marker


def _agent_bus_violations(agent_dir: str) -> list[str]:
    """Token-scan every .py under the assembled agent dir. Return a list of violations: a _BUS_BANNED
    name used in CODE, or a _BUS_GATED subscription API on a line lacking the audited sentinel.
    Comments and string literals (docstrings) are excluded, so the words may appear in explanatory
    prose but not in actual code."""
    out: list[str] = []
    for root, dirs, files in os.walk(agent_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, agent_dir)
            try:
                src = open(path).read()
                lines = src.splitlines()
                for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                    if tok.type in (tokenize.COMMENT, tokenize.STRING):
                        continue
                    s, ln = tok.string, tok.start[0]
                    if s in _BUS_BANNED:
                        out.append(f"agent {rel}:{ln} uses banned driving-bus name {s!r}: "
                                   f"{lines[ln - 1].strip()!r}")
                    elif s in _BUS_GATED and _BUS_AUDIT_SENTINEL not in lines[ln - 1]:
                        out.append(f"agent {rel}:{ln} un-audited bus API {s!r}: "
                                   f"{lines[ln - 1].strip()!r}")
            except (OSError, tokenize.TokenError, SyntaxError) as exc:
                out.append(f"agent {rel}: could not scan ({exc})")
    return out


# --- ZERO-LEAK (public build): a public / self-hosted build must be provably free of non-public
# content. This is the inverse of --expect-private: rather than requiring the private layer's
# effects, it FORBIDS them, plus any secret/credential/cloud markers. It is a defense-in-depth scan
# so a fork's automated build can never publish a tree that quietly picked up private or cloud bits.
# Forbidden as a substring anywhere in the assembled tree's text files. Kept deliberately broad; add
# terms here rather than loosening. (Reviewed/owned by the security lane.)
#
# The public denylist covers generic secret/credential + cloud/edition markers only. A deployment
# that layers its own build-specific effects supplies EXTRA denylist terms from a gitignored companion
# (see _load_extra_forbidden) so this public file names none of them — the denylist itself must not
# enumerate a deployment's private specifics.
_FORBIDDEN_TOKENS = (
    # secret / key material
    "-----BEGIN", "PRIVATE KEY", "sk_live_", "sk_test_", "whsec_", "AWS_SECRET", "BEGIN OPENSSH",
    "ssh-ed25519 ", "ssh-rsa ",
    # cloud / edition / tenant vocabulary that must never reach a public build
    "stripe", "billing", "tenant", "cf-connecting", "MYPILOT_CLOUD", "mypilot-cloud", "enterprise",
)

# Extra deployment-specific forbidden tokens live in a GITIGNORED companion that is ABSENT from the
# public tree. Load it if present (fail-OPEN on absence: a public / self-hosted checkout simply scans
# the generic list above — it does not crash). A deployment with its own private layer ships the
# companion, getting full coverage of its own effects without this public file naming any of them.
_EXTRA_FORBIDDEN_MODULE = os.path.join("sunnypilot", "mypilot", "private", "forbidden_tokens.py")


def _load_extra_forbidden(root: str) -> tuple[str, ...]:
    """Return extra forbidden tokens from the gitignored companion if present, else (). Fail-open on
    absence (public tree has no companion → generic list only); never raises on a missing file."""
    path = os.path.join(root, _EXTRA_FORBIDDEN_MODULE)
    if not os.path.exists(path):
        return ()
    ns: dict = {}
    try:
        exec(compile(open(path).read(), path, "exec"), ns)  # noqa: S102 - trusted build-machine file
    except Exception as exc:  # noqa: BLE001
        # A present-but-broken companion is a build-machine error, not a public concern → surface it.
        return (f"__companion_error__:{exc}",)
    toks = ns.get("FORBIDDEN_TOKENS", ())
    return tuple(str(t) for t in toks)


# Only scan text-ish files; skip binaries/assets so a stray byte match can't false-positive.
_SCAN_EXTS = (".py", ".sh", ".json", ".txt", ".md", ".toml", ".yaml", ".yml", ".cfg", ".ini",
              ".env", ".conf", ".h", ".cc", ".cpp", ".c", ".ts", ".svelte", ".html")
_SKIP_DIRS = {".git", "__pycache__", "node_modules", "translations"}


def _public_leak_violations(root: str) -> list[str]:
    """Scan the assembled tree for forbidden tokens (case-insensitive). Returns violations. A public
    build must produce ZERO. This proves absence of private/secret/cloud content structurally.

    Denylist = the inline generic list + any deployment-specific tokens from the gitignored companion
    (fail-open if absent). Both are enforced fail-closed: a matching token anywhere is a violation."""
    out: list[str] = []
    extra = _load_extra_forbidden(root)
    # A present-but-broken companion surfaces as a violation (build-machine error, don't scan blind).
    broken = [e for e in extra if e.startswith("__companion_error__:")]
    if broken:
        return [f"private/forbidden_tokens.py failed to load: {e.split(':', 1)[1]}" for e in broken]
    needles = [t.lower() for t in (_FORBIDDEN_TOKENS + extra)]
    # The companion denylist file necessarily CONTAINS the forbidden token strings (it defines them),
    # so exclude it from the content scan — else it self-matches its own list. Only that one file is
    # exempted; any other content under the private dir is still scanned.
    companion_rel = os.path.normpath(_EXTRA_FORBIDDEN_MODULE)
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in sorted(files):
            if not name.endswith(_SCAN_EXTS):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if os.path.normpath(rel) == companion_rel:
                continue
            try:
                text = open(path, encoding="utf-8", errors="ignore").read().lower()
            except OSError as exc:
                out.append(f"{rel}: could not scan ({exc})")
                continue
            for needle in needles:
                if needle in text:
                    out.append(f"{rel}: forbidden token {needle!r} present in a public build")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=".")
    ap.add_argument("--expect-private", action="store_true")
    ap.add_argument("--expect-public", action="store_true")
    args = ap.parse_args()
    os.chdir(args.target)
    if args.expect_private and args.expect_public:
        print("[verify] --expect-private and --expect-public are mutually exclusive", file=sys.stderr)
        return 2

    fails: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            fails.append(msg)

    proc = open(PROC).read() if os.path.exists(PROC) else ""

    # The sunnylink teardown + MyPilot Link UI only apply to the sunnypilot base (sunnylink is a
    # sunnypilot feature). Detect it by the sunnypilot UI tree; the root base (openpilot/frogpilot)
    # has no sunnylink, so those checks are skipped there.
    is_sunnypilot = os.path.isdir("selfdrive/ui/sunnypilot")

    # 1. (sunnypilot only) No live sunnylink phone-home daemon registration survives.
    if is_sunnypilot:
        for needle in ('"manage_sunnylinkd"', '"sunnylink_registration_manager"', '"statsd_sp"',
                       "sunnylink.backups.manager", "sunnylink.uploader"):
            check(needle not in proc, f"sunnylink daemon still registered: {needle}")
        # ...and the orphaned shims/import are gone (no dangling references).
        check("sunnylink_ready_shim" not in proc, "orphaned sunnylink_ready_shim still present")
        check("from openpilot.sunnypilot.sunnylink.utils import" not in proc,
              "unused sunnylink.utils import still present")

    # 2. The agent is registered AND will actually land in managed_processes (above the build line).
    check('"mypilotd"' in proc, "mypilotd not registered")
    if "mypilotd" in proc and "managed_processes = {p.name: p for p in procs}" in proc:
        before = proc.split("managed_processes = {p.name: p for p in procs}")[0]
        check('"mypilotd"' in before, "mypilotd registered AFTER managed_processes (will never launch)")
    check("restart_if_crash=True" in proc, "mypilotd missing restart_if_crash=True")

    if is_sunnypilot:
        # 3. In-UI sunnylink worker force-disabled.
        if os.path.exists(UI_STATE):
            check("self.sunnylink_enabled = False" in open(UI_STATE).read(),
                  "ui_state does not force sunnylink_enabled = False")
        # 4. MyPilot Link UI present; old sunnylink panel gone.
        check(os.path.exists("selfdrive/ui/sunnypilot/mici/layouts/mypilot_link.py"),
              "mypilot_link.py missing (UI not vendored)")
        check(not os.path.exists("selfdrive/ui/sunnypilot/mici/layouts/sunnylink.py"),
              "dead sunnylink.py panel still present")
        # 4b. Version stamped with the sunnypilot- base tag (fails loud if upstream moved version.h).
        candidates = ("openpilot/sunnypilot/common/version.h", "sunnypilot/common/version.h")
        vh = next((p for p in candidates if os.path.exists(p)), None)
        if vh is not None:
            check('SUNNYPILOT_VERSION "sunnypilot-' in open(vh).read(),
                  "version not stamped with sunnypilot- base tag")
        else:
            check(False, "version header not found in expected locations")

    # 5. Agent overlay present + import-safe launcher.
    launcher = next((p for p in ("sunnypilot/mypilot/mypilotd.py", "mypilot/mypilotd.py")
                     if os.path.exists(p)), None)
    check(launcher is not None, "agent launcher (mypilotd.py) missing")

    # 6. No user-visible 'sunnypilot' brand left in the key mici screens we rebrand.
    home = "selfdrive/ui/mici/layouts/home.py"
    if os.path.exists(home):
        check('UnifiedLabel("sunnypilot"' not in open(home).read(),
              "home wordmark still says sunnypilot")

    # 6b. The pairing alert key must be registered (the agent's on-screen pairing references it).
    alerts = "selfdrive/selfdrived/alerts_offroad.json"
    check(os.path.exists(alerts) and "Offroad_MyPilotPairing" in open(alerts).read(),
          "Offroad_MyPilotPairing alert not registered in alerts_offroad.json")

    # 6c. No stale sunnypilot.ai terms URL anywhere (source OR translation catalogs) — a wrong
    #     external link on non-English devices.
    if is_sunnypilot:
        tdir = "selfdrive/ui/translations"
        if os.path.isdir(tdir):
            for name in os.listdir(tdir):
                if name.endswith((".po", ".pot")):
                    check("sunnypilot.ai/terms" not in open(os.path.join(tdir, name)).read(),
                          f"stale sunnypilot.ai/terms URL in translation catalog {name}")

    # 7. Private layer (only when expected): delegate to the private layer's own verifier if present.
    #    The checks for a private build's effects live with that build (a gitignored verify.py), so the
    #    public recipe asserts only that the layer ran, not what it contains.
    if args.expect_private:
        priv_verify = os.path.join("sunnypilot", "mypilot", "private", "verify.py")
        check(os.path.exists(priv_verify), "private: layer verifier missing (build with --private?)")
        if os.path.exists(priv_verify):
            rc = subprocess.run([sys.executable, priv_verify]).returncode
            check(rc == 0, "private: layer verification failed")

    # 8. SAFETY (ALWAYS — every build, public or private): the assembled agent must hold NO persistent
    #    driving-bus reader beyond the single audited GPS line. This is a generic safety invariant, not
    #    an edition feature, so it gates EVERY image a self-hoster or we could ship onto a car.
    agent_dir = next((d for d in ("sunnypilot/mypilot/mypilot_agent", "mypilot/mypilot_agent")
                      if os.path.isdir(d)), None)
    check(agent_dir is not None, "agent package (mypilot_agent) missing from the assembled tree")
    if agent_dir is not None:
        for v in _agent_bus_violations(agent_dir):
            check(False, f"no-driving-bus: {v}")

    # 9. ZERO-LEAK (only when --expect-public): the tree must carry NO private/secret/cloud content.
    #    The inverse of --expect-private. A public / self-hosted build asserts absence structurally.
    if args.expect_public:
        for v in _public_leak_violations("."):
            check(False, f"public-leak: {v}")

    if fails:
        print("[verify] FAILED:", file=sys.stderr)
        for f in fails:
            print("  -", f, file=sys.stderr)
        return 1
    mode = " (with private layer)" if args.expect_private else (
        " (public, zero-leak verified)" if args.expect_public else "")
    print("[verify] OK — assembled tree is a correct MyPilot image" + mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
