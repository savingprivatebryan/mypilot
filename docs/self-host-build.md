# Self-hosting your own MyPilot device build

This repo ships the **tooling** to build your own MyPilot device image and keep it tracking sunnypilot
upstream — **your fork, your runner, your device, your builds.** MyPilot does not host, serve, sign,
or support these builds; this is the recipe, not a hosted service.

> ⚠️ **Safety.** These builds run on a car that steers. Every build is checked by the no-driving-bus
> safety gate (`verify_assembled.py`), and a build that fails verification is not published — but a
> passing build is still *your* responsibility to test before you drive it. The **nightly** channel
> tracks bleeding-edge upstream and is **untested** — treat it accordingly. Never install onto a
> device while it is onroad; apply offroad only.

## What you get

- A reusable GitHub Actions workflow (`.github/workflows/build-device-image.yml`) that, on a schedule
  or on demand, tracks sunnypilot upstream, replays the public MyPilot layer, assembles a device
  image, verifies it (safety + zero-leak), and publishes to a channel branch in your fork.
- Two channels: **stable** (tracks the sunnypilot release lineage) and **nightly** (tracks the
  sunnypilot `__nightly` branch — bleeding-edge, untested).
- The on-device config to point your comma at *your* fork's channel.

## One-time setup

1. **Fork this repo** on GitHub (this gives you `github.com/<you>/mypilot`).
2. Enable Actions in your fork (Settings → Actions → allow workflows).
3. (Optional) Point the workflow at a self-hosted runner if you'd rather not use GitHub-hosted CI.
4. The workflow references **only public inputs** — the public sunnypilot upstream and this public
   repo. Do **not** add any credential, private remote, or `--private` flag: a public build must
   reference public inputs only. The `--expect-public` verify step will fail the build if any
   private/secret/cloud content is ever present, which also protects your fork from accidentally
   committing something it shouldn't.

## Building

- **Automatic:** the workflow runs on a daily schedule and builds when sunnypilot upstream advances
  (a new stable tag, or a new nightly commit). A clean build publishes automatically.
- **Manual:** Actions → *build-device-image* → *Run workflow* → pick `stable` or `nightly`.
- **If a build fails to rebase** (upstream refactored a file the MyPilot layer touches), the Actions
  run goes red with the conflicting file / failed step. Fix the replay (update the affected patch),
  then re-run. Nothing is published on a failed build.

## Pointing your comma at your fork (on-device channel tracking)

Your device's updater tracks a branch on a remote. To track *your* fork's channel, set the updater
target branch on-device (offroad):

```bash
# On the device (offroad), point the updater at your fork's channel branch.
# Replace <you> and the channel branch name to match what your workflow publishes.
git -C /data/openpilot remote set-url origin https://github.com/<you>/mypilot-device.git
python3 - <<'PY'
from openpilot.common.params import Params
Params().put("UpdaterTargetBranch", "mypilot-mici")   # or your nightly channel branch
PY
# Then let the updater fetch on the next offroad reboot (sudo reboot). NEVER `systemctl restart comma`.
```

The updater's normal fetch → finalize → apply flow then tracks your channel. Apply happens on an
offroad reboot. (A future release adds an on-device stable/nightly picker and an explicit
"install now" consent step so nothing applies without you choosing when — until then, the standard
updater flow applies the staged build on the next offroad reboot.)

## What this tooling does NOT include

- No hosted build service, update server, or artifact signing from MyPilot — you run and serve your
  own.
- No private/owner layer (SSH-access hooks, car-specific ports, owner toggles): those are not in the
  public tree and are not part of a public build by construction.
- No support obligation: this is community DIY tooling.
