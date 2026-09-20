# Scheduling OverSeer

`daemon/` contains **templates and documentation only** — no scheduling
logic lives in Python. `overseer run` is a single, idempotent pass
(fetch, normalize, dedup, store, report); something outside the process
has to call it repeatedly. Pick systemd or cron below; they're
equivalent, just choose whichever your environment already uses.

## This is polling, not push-based

**There is no webhook or streaming source here. `overseer run` only sees
an advisory once it runs. The polling interval you configure IS the
detection latency** — with the default 30-minute interval, an advisory
published one minute after a run finishes will not be picked up for
close to 30 minutes. Lowering the interval lowers that latency, at the
cost of more frequent requests against CISA/Cisco. There is no way to
get faster-than-interval detection out of this design; that tradeoff is
inherent to polling, not a bug.

## Option A: systemd (timer + service)

Two template units are provided:

- `overseer.service` — runs `overseer run` once (`Type=oneshot`)
- `overseer.timer` — triggers that service every 30 minutes

### Install

1. Copy both templates and fill in the placeholders (`__OVERSEER_USER__`,
   `__OVERSEER_GROUP__`, `__OVERSEER_INSTALL_DIR__`) for your machine:

   ```sh
   sudo cp overseer/daemon/overseer.service /etc/systemd/system/overseer.service
   sudo cp overseer/daemon/overseer.timer   /etc/systemd/system/overseer.timer
   sudo sed -i \
     -e 's|__OVERSEER_USER__|overseer|g' \
     -e 's|__OVERSEER_GROUP__|overseer|g' \
     -e 's|__OVERSEER_INSTALL_DIR__|/opt/overseer|g' \
     /etc/systemd/system/overseer.service
   ```

2. Create `/opt/overseer/overseer.env` (mode `600`, owned by the service
   user) holding any secrets, e.g.:

   ```
   CISCO_CLIENT_ID=your-client-id
   CISCO_CLIENT_SECRET=your-client-secret
   ```

3. Enable and start the timer (not the service directly):

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now overseer.timer
   ```

### Check it

```sh
systemctl list-timers overseer.timer   # next/last run time
systemctl status overseer.service      # last run's result
journalctl -u overseer.service -f      # live logs
sudo systemctl start overseer.service  # trigger a run immediately, outside the schedule
```

### Change the interval

Edit `OnUnitActiveSec=` in the installed `overseer.timer`, then
`sudo systemctl daemon-reload && sudo systemctl restart overseer.timer`.

## Option B: crontab

Equivalent to the systemd setup above, for hosts without systemd or
where cron is already the house standard. Cron runs with a minimal
environment (no venv activation, no `PATH`), so the entry needs full
paths and to source your secrets explicitly:

```cron
# Every 30 minutes. Replace __OVERSEER_INSTALL_DIR__.
*/30 * * * * cd __OVERSEER_INSTALL_DIR__ && . __OVERSEER_INSTALL_DIR__/overseer.env && __OVERSEER_INSTALL_DIR__/.venv/bin/overseer run >> __OVERSEER_INSTALL_DIR__/overseer.log 2>&1
```

Install as the intended run-as user with `crontab -e` (not root's
crontab, unless you specifically want it running as root). `overseer.env`
is the same `KEY=value` file described in the systemd section above.

### Check it

```sh
crontab -l                              # confirm the entry is installed
tail -f __OVERSEER_INSTALL_DIR__/overseer.log   # last/ongoing run output
grep CRON /var/log/syslog               # cron's own invocation log (Debian/Ubuntu)
```

## Either way

- Both options just run `overseer run` — all dedup/state logic already
  lives in `storage/db.py`, so re-running on a schedule (or triggering an
  extra run manually) is safe: duplicates are skipped, not re-reported.
- Neither approach needs OverSeer's own process to stay resident; systemd
  and cron both start a fresh, short-lived `overseer run` process each
  time and exit when it's done.
