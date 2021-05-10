<p align="center">
<img src="https://raw.githubusercontent.com/crowdsecurity/cs-cloudflare-bouncer/main/docs/assets/crowdsec_cloudfare.png" alt="CrowdSec" title="CrowdSec" width="280" height="300" />
</p>
<p align="center">
<img src="https://img.shields.io/badge/build-pass-green">
<img src="https://img.shields.io/badge/tests-pass-green">
</p>
<p align="center">
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>

# CrowdSec Cloudflare Bouncer

A bouncer that syncs the decisions made by CrowdSec with CloudFlare's firewall.

# Installation

## Install script

Download the [latest release](https://github.com/crowdsecurity/cs-cloudflare-bouncer/releases).

```bash
tar xzvf cs-cloudflare-bouncer.tgz
cd cs-cloudflare-bouncer/
sudo ./install.sh -t <CLOUDFLARE_API_TOKEN> -a <CLOUDFLARE_ACCOUNT_ID> -z <CLOUDFLARE_ZONE_ID>
systemctl status cs-cloudfare-bouncer
```


## From source

:warning: requires go >= 1.13

```bash
make release
cd cs-cloudflare-bouncer-vX.X.X
sudo ./install.sh
systemctl status cs-cloudflare-bouncer
```

# Configuration

Configuration file can be found at `/etc/crowdsec/cs-cloudfare-bouncer/cs-cloudfare-bouncer.yaml`

```yaml
# CrowdSec Config
crowdsec_lapi_url: http://localhost:8080/
crowdsec_lapi_key: ${LAPI_KEY}

# Cloudfare Config
cloudfare_api_token: ${CF_TOKEN}
cloudfare_account_id: ${CF_ACC_ID}
cloudfare_zone_id: ${CF_ZONE_ID}

cloudfare_ip_list_name: crowdsec

# Bouncer Config
update_frequency: 10s
action: block
daemon: true
log_mode: file
log_dir: /var/log/
log_level: info
```

# How it works

When the `cs-cloudflare-bouncer` service starts, it first creates a CloudFlare IP list (by default it is named as `crowdsec`). It also creates a firewall rule which applies certain action on all the IPs present in this list. By  default this action is `block` but can be changed in the configuration to either `allow`, `log`, `challenge`.


# Troubleshooting

 - Logs are in `/var/log/cs-cloudflare-bouncer.log`
 - You can view/interact directly in the ban list either with `cscli`
 - Service can be started/stopped with `systemctl start/stop cs-cloudfare-bouncer`
