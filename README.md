# FusionMAP
List of NMAP scripting engine (.nse) script for deep nmap scanning process.

### Installation & Usage

```bash
git clone https://github.com/MatrixTM26/FusionMAP.git
cd FusionMAP
```

```bash
nmap -p 80,443,8080 --script ./SensitiveFileCheck.nse <TARGET IP/DOMAIN>
```

```bash
nmap -p 80,443,8080 --script ./HttpEnvCheck.nse example.com
```
