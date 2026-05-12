# Building this lab in GNS3

GNS3 doesn't natively understand `containerlab` topologies, but the same
device list and link map can be reproduced in two steps.

## 1. Import the SR-OS image

* Add an SR-OS appliance:
  *File → Import appliance* → choose the **Nokia 7750 SR** appliance.
* GNS3 will ask for the qcow2 image (`sros-vm.qcow2`) and a license file.

## 2. Create the topology

Drop **16** SR-OS nodes onto the workspace and rename them per
`inventory/hosts.yml`:

| Role | Names                              |
|------|------------------------------------|
| P    | P1, P2, P3, P4, P5, P6, P7, P8     |
| PE   | PE1, PE2, PE3, PE4                 |
| RR   | RR1, RR2                           |
| CE   | CE1, CE2                           |

Then connect them according to the link table below — these are the
exact same endpoints used by `topology.clab.yml`:

```
P1 (1/1/1) ── P2 (1/1/1)
P2 (1/1/2) ── P3 (1/1/1)
P3 (1/1/2) ── P4 (1/1/1)
P5 (1/1/2) ── P6 (1/1/1)
P6 (1/1/3) ── P7 (1/1/2)
P7 (1/1/3) ── P8 (1/1/2)
P1 (1/1/2) ── P5 (1/1/1)
P2 (1/1/3) ── P6 (1/1/2)
P3 (1/1/3) ── P7 (1/1/1)
P4 (1/1/2) ── P8 (1/1/1)

PE1 (1/1/1) ── P1 (1/1/3)
PE2 (1/1/1) ── P5 (1/1/3)
PE3 (1/1/1) ── P4 (1/1/3)
PE4 (1/1/1) ── P8 (1/1/3)

RR1 (1/1/1) ── P2 (1/1/4)
RR2 (1/1/1) ── P7 (1/1/4)

CE1 (1/1/1) ── PE1 (1/1/2)
CE1 (1/1/2) ── PE2 (1/1/2)
CE2 (1/1/1) ── PE3 (1/1/2)
CE2 (1/1/2) ── PE4 (1/1/2)
```

## 3. Deploy the generated configs

After running `ansible-playbook playbooks/build_configs.yml` you will
have a config blob in `output/<hostname>.cfg` for each device.
Open the GNS3 console for that node and paste the config (or use SCP
to copy it to `cf3:` and execute `exec cf3:/<hostname>.cfg`).
