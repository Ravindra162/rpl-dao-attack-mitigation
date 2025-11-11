# RPL DAO Replay Attack Mitigation Simulation

This project implements a mitigation technique for DAO (Destination Advertisement Object) replay attacks in static RPL (Routing Protocol for Low-Power and Lossy Networks) networks using NS-3.

## Prerequisites

This simulation ran in **NS-3 Docker container** using the image:
```
marshallasch/ns3
```

## Setup Instructions

### 1. Pull and Run the NS-3 Docker Container

```bash
docker pull marshallasch/ns3

docker run -it -v /path/to/your/project:/ns3/ns-allinone-3.34/ns-3.34/scratch marshallasch/ns3
```

### 2. Verify Files in Container

Once inside the container, verify the simulation file is present:
```bash
ls /ns3/ns-allinone-3.34/ns-3.34/scratch/
```

You should add `mitigation.cc` in the scratch directory.

### 3. Build the Simulation

Navigate to the NS-3 directory and build:
```bash
cd /ns3/ns-allinone-3.34/ns-3.34/
./waf configure
./waf build
```

## Running Simulations

### Basic Simulation Command

```bash
./waf --run "scratch/mitigation"
```

### Simulation Parameters

The simulation supports the following command-line parameters:

| Parameter | Description | Default Value |
|-----------|-------------|---------------|
| `--nodes` | Number of nodes in the network | 20 |
| `--attackers` | Number of attacker nodes | 3 |
| `--duration` | Simulation duration in seconds | 60 |
| `--mitigation` | Enable/disable mitigation (true/false) | true |
| `--scenario` | Scenario name for output files | "default" |

### Example Commands

#### Baseline (No Attackers)
```bash
./waf --run "scratch/mitigation --scenario=baseline --nodes=20 --attackers=0 --duration=60 --mitigation=false"
```

#### With Mitigation Enabled
```bash
./waf --run "scratch/mitigation --scenario=with_mitigation --nodes=20 --attackers=3 --duration=60 --mitigation=true"
```

#### Without Mitigation (Vulnerable Network)
```bash
./waf --run "scratch/mitigation --scenario=without_mitigation --nodes=20 --attackers=3 --duration=60 --mitigation=false"
```
