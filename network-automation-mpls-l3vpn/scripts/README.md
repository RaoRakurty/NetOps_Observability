# scripts/

## render_local.py

Renders every device's config without requiring Ansible.
Useful for quick template iteration in CI.

```bash
pip install jinja2 pyyaml
python3 scripts/render_local.py
ls output/
```

The renderer uses `StrictUndefined` so any missing host_vars key fails the
build immediately — handy for catching typos before they hit a router.
