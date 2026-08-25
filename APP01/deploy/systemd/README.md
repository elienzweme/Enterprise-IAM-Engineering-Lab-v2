# APP01 systemd Service

This service runs the Enterprise IAM FastAPI application as the `iamadmin` account and automatically restarts it after a failure.

## Installation

```bash
sudo cp iam-platform.service /etc/systemd/system/iam-platform.service
sudo systemctl daemon-reload
sudo systemctl enable iam-platform.service
sudo systemctl start iam-platform.service

```

The live environment file must exist separately at:

```text
/opt/iam-platform/.env
```

The `.env` file must have `0600` permissions and must never be committed to Git.

## Validation

```bash
sudo systemctl is-enabled iam-platform.service
sudo systemctl is-active iam-platform.service
curl -sS -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8000/
```

Expected results are `enabled`, `active`, and `HTTP 200`.

## Logs

```bash
sudo journalctl -u iam-platform.service -n 50 --no-pager
```
