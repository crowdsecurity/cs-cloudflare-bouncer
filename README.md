<p align="center">
<img src="https://raw.githubusercontent.com/crowdsecurity/cs-cloudflare-bouncer/main/docs/assets/crowdsec_cloudflare.png" alt="CrowdSec" title="CrowdSec" width="280" height="300" />
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

A bouncer that syncs the decisions made by CrowdSec with CloudFlare's firewall.Manages multi user, multi account, multi zone setup. 

# Installation

## Install script

Download the [latest release](https://github.com/crowdsecurity/cs-cloudflare-bouncer/releases).

```bash
tar xzvf cs-cloudflare-bouncer.tgz
cd cs-cloudflare-bouncer/
sudo ./install.sh # Use sudo ./install.sh --unattended  for automated setup
systemctl status cs-cloudflare-bouncer
```


## From source

:warning: requires go >= 1.13

```bash
make release
cd cs-cloudflare-bouncer-vX.X.X
sudo ./install.sh # Use sudo ./install.sh --unattended  for automated setup
systemctl status cs-cloudflare-bouncer
```

# Configuration

Configuration file can be found at `/etc/crowdsec/cs-cloudflare-bouncer/cs-cloudflare-bouncer.yaml`

```yaml
# CrowdSec Config
crowdsec_lapi_url: http://localhost:8080/
crowdsec_lapi_key: ${LAPI_KEY}
crowdsec_update_frequency: 10s

#Cloudflare Config. 
cloudflare_config:
  accounts: 
  - id: 
    token: 
    ip_list_name: crowdsec
    zones:
    - remediation: challenge # valid choices are either of challenge, js_challenge, block, allow, log
      zone_id: 

  update_frequency: 30s # the frequency to update the cloudflare IP list 

# Bouncer Config
daemon: true
log_mode: file
log_dir: /var/log/ 
log_level: info # valid choices are either debug, info, error 
```

## Cloudflare configuration

**Background:** In Cloudflare, each user can have access to multiple accounts. Each account can own/access multiple zones. In this context a zone can be considered as a domain. Each domain registered with cloudflare gets a distinct `zone_id`.

For each account the `id` and `token` are required.

For obtaining the `token`:
1. Sign in as a user who has access to the account.
2. Go to [Tokens](https://dash.cloudflare.com/profile/api-tokens) and create the token. The bouncer requires the follwing permissions to function.
![image](https://user-images.githubusercontent.com/28975399/119085543-8f8cf980-ba21-11eb-84bf-9a30d4ed922e.png)

For obtaining the account `id`, and `zone_id`:

1. Go to each of the "domain dashboard".
2. In the bottom left corner you would see the domain's `zone_id` and the owner account's `id`

# How it works

When the service starts, it creates a CloudFlare IP list for each specified account. (by default it is named as `crowdsec`. It then creates a firewall rule for each of the provided `zone` which applies certain remediation on all the IPs present in this list. By default this remediation is `challenge` but can be changed in the configuration to either `allow`, `log`, `challenge`, `js_challenge`.


# Troubleshooting

 - Logs are in `/var/log/cs-cloudflare-bouncer.log`
 - You can view/interact directly in the ban list either with `cscli`
 - Service can be started/stopped with `systemctl start/stop cs-cloudflare-bouncer`
