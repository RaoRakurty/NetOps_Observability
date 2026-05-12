"""
Local renderer: simulates what Ansible's `template` module does, so we can
sanity-check the templates without an Ansible install. Walks every host in
inventory/host_vars, merges role group_vars + global all.yml, and renders the
appropriate role wrapper template into output/<host>.cfg.
"""
import os, glob, sys
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = os.path.dirname(os.path.abspath(__file__))
INV  = os.path.join(ROOT, "inventory")
TPL  = os.path.join(ROOT, "templates")
OUT  = os.path.join(ROOT, "output")
os.makedirs(OUT, exist_ok=True)

def load(path):
    with open(path) as f:
        return yaml.safe_load(f)

# --- load inventory groups ---
inv = load(os.path.join(INV, "hosts.yml"))
all_vars   = load(os.path.join(INV, "group_vars", "all.yml"))
role_vars  = {
    "p":  load(os.path.join(INV, "group_vars", "p_routers.yml")),
    "pe": load(os.path.join(INV, "group_vars", "pe_routers.yml")),
    "rr": load(os.path.join(INV, "group_vars", "rr_routers.yml")),
    "ce": load(os.path.join(INV, "group_vars", "ce_routers.yml")),
}
role_to_template = {
    "p":  "p_router.j2",
    "pe": "pe_router.j2",
    "rr": "rr_router.j2",
    "ce": "ce_router.j2",
}

# build host -> role and groups['pe_routers'] etc. for the bgp_rr template
groups = {"p_routers": [], "pe_routers": [], "rr_routers": [], "ce_routers": []}
host_role = {}
def walk(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in groups and isinstance(v, dict) and "hosts" in v:
                for h in v["hosts"]:
                    groups[k].append(h)
                    host_role[h] = k.split("_")[0]
            walk(v)
walk(inv)

# load every host_vars
hostvars = {}
for f in glob.glob(os.path.join(INV, "host_vars", "*.yml")):
    name = os.path.splitext(os.path.basename(f))[0]
    hostvars[name] = load(f)

env = Environment(
    loader=FileSystemLoader(TPL),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)

ok = 0
errors = []
for host in sorted(host_role):
    role = host_role[host]
    ctx  = {}
    ctx.update(all_vars)
    ctx.update(role_vars[role])
    ctx.update(hostvars[host])
    ctx["groups"]   = groups
    ctx["hostvars"] = hostvars
    ctx["inventory_hostname"] = host
    ctx["ansible_date_time"]  = {"iso8601": "render-test"}
    try:
        out = env.get_template(role_to_template[role]).render(**ctx)
        with open(os.path.join(OUT, f"{host}.cfg"), "w") as f:
            f.write(out)
        ok += 1
    except Exception as e:
        errors.append((host, role, str(e)))

print(f"Rendered {ok}/{len(host_role)} configs")
for h, r, e in errors:
    print(f"  FAIL {h} ({r}): {e}")
sys.exit(1 if errors else 0)
