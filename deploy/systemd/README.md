# systemd units (optional)

Three units, matching the three real OS processes Argus runs natively:

| Unit | Process | Notes |
|---|---|---|
| `bbhunter.service` | gateway (`uvicorn app.main:app`) | Also runs the continuous-monitoring **scheduler** and the Redis event consumer — both are `asyncio` tasks inside this same process, not separate binaries. There is intentionally no separate `bbhunter-scheduler.service`: creating one would either duplicate the scheduler (running it twice) or start a process that doesn't exist. Set `ARGUS_SCHEDULER=off` in `.env` to disable it without touching this unit. |
| `bbhunter-worker.service` | orchestrator (job worker pool) | `BindsTo=bbhunter.service` — stops if the gateway stops, since it has nothing to report events to. |
| `bbhunter-web.service` | Next.js frontend | |

`run.sh` remains fully usable whether or not these are installed — it manages
the same three processes directly with its own PID tracking when systemd
isn't in the picture (see `scripts/lib/services.sh`). Don't run both at once
against the same install: pick native `run.sh`, systemd, or Docker Compose,
not two of them pointed at the same `.env`/database.

## Install

```bash
sudo useradd --system --home /opt/argus --shell /usr/sbin/nologin argus
sudo mkdir -p /opt/argus && sudo cp -r . /opt/argus && cd /opt/argus
sudo ./install.sh --production --non-interactive
sudo chown -R argus:argus /opt/argus

sudo cp deploy/systemd/bbhunter*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bbhunter.service bbhunter-worker.service bbhunter-web.service
sudo systemctl status bbhunter.service
```

## Logs

```bash
journalctl -u bbhunter.service -f
journalctl -u bbhunter-worker.service -f
```

## Updating

```bash
sudo systemctl stop bbhunter-worker bbhunter-web bbhunter
cd /opt/argus && sudo -u argus ./install.sh --upgrade --non-interactive
sudo systemctl start bbhunter bbhunter-worker bbhunter-web
```

Edit the `WorkingDirectory=`/`ExecStart=` paths in the unit files first if
you didn't install to `/opt/argus`, or the `User=`/`Group=` if you didn't
create an `argus` system user.
