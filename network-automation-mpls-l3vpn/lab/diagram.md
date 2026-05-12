# Network Topology

```mermaid
flowchart LR
    subgraph CUST_LEFT[Customer-Left]
      CE1((CE1<br/>AS65001))
    end
    subgraph CUST_RIGHT[Customer-Right]
      CE2((CE2<br/>AS65002))
    end

    subgraph SP[Service Provider — AS65000]
      direction LR
      subgraph CORE[Flat ISIS-L2 Core + LDP]
        direction LR
        P1 --- P2 --- P3 --- P4
        P5 --- P6 --- P7 --- P8
        P1 --- P5
        P2 --- P6
        P3 --- P7
        P4 --- P8
      end
      RR1{{RR1}} --- P2
      RR2{{RR2}} --- P7
      PE1[PE1] --- P1
      PE2[PE2] --- P5
      PE3[PE3] --- P4
      PE4[PE4] --- P8
    end

    CE1 ===|eBGP per VRF| PE1
    CE1 ===|eBGP per VRF| PE2
    CE2 ===|eBGP per VRF| PE3
    CE2 ===|eBGP per VRF| PE4

    classDef pe fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef rr fill:#fff8e1,stroke:#ef6c00,stroke-width:2px
    classDef ce fill:#f1f8e9,stroke:#558b2f,stroke-width:2px
    class PE1,PE2,PE3,PE4 pe
    class RR1,RR2 rr
    class CE1,CE2 ce
```

## VRF service overview

| VRF   | RD         | RT (import/export) | CE1 loopback   | CE2 loopback   |
|-------|------------|--------------------|----------------|----------------|
| VRF-A | 65000:100  | target:65000:100   | 172.16.1.1/32  | 172.17.1.1/32  |
| VRF-B | 65000:200  | target:65000:200   | 172.16.2.1/32  | 172.17.2.1/32  |
| VRF-C | 65000:300  | target:65000:300   | 172.16.3.1/32  | 172.17.3.1/32  |

End-to-end reachability test from CE1 inside VRF-A:

```
A:CE1# ping router 100 172.17.1.1 source 172.16.1.1
```
