<p align="center">
<img src="https://github.com/crowdsecurity/cs-cloudflare-bouncer/raw/main/docs/assets/crowdsec_cloudfare.png" alt="CrowdSec" title="CrowdSec" width="280" height="300" />
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

A bouncer that syncs the decisions made by CrowdSec with CloudFlare's firewall. Manages multi user, multi account, multi zone setup. Supports IP, Country and AS scoped decisions.

# Installation

## Install script

Download the [latest release](https://github.com/crowdsecurity/cs-cloudflare-bouncer/releases).

```bash
tar xzvf crowdsec-cloudflare-bouncer.tgz
cd crowdsec-cloudflare-bouncer/
sudo ./install.sh
sudo crowdsec-cloudflare-bouncer -g <CLOUDFLARE_TOKEN1> <CLOUDFLARE_TOKEN2> -o cfg.yaml # auto-generate cloudflare config for provided space separated tokens 
sudo vi cfg.yaml # make changes as needed
sudo cat cfg.yaml > /etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml # Verify the generated config and paste it in bouncer's config.
sudo crowdsec-cloudflare-bouncer -s # this sets up IP lists and firewall rules at cloudflare for the provided config. 
sudo systemctl start crowdsec-cloudflare-bouncer # the bouncer now syncs the crowdsec decisions with cloudflare components.
```

## Using Docker 

Make sure you have docker or podman installed. In this guide we will use docker, but podman would work as a drop in replacement too.

### Initial Setup

```bash
git clone https://github.com/crowdsecurity/cs-cloudflare-bouncer.git
cd cs-cloudflare-bouncer
docker build . -t cs-cloudflare-bouncer
docker run cs-cloudflare-bouncer -g <CLOUDFLARE_TOKEN1> <CLOUDFLARE_TOKEN2> > cfg.yaml # auto-generate cloudflare config for provided space separated tokens 
vi cfg.yaml # add the appropriate crowdsec_lapi_url and crowdsec_lapi_key values. Make sure LAPI is accessible from the container.
```

The `crowdsec_lapi_key` can be obtained by running the following:
```bash
sudo cscli -oraw bouncers add cloudflarebouncer # -oraw flag can discarded for human friendly output.
```

The `crowdsec_lapi_url` must be accessible from the container.

### Run the bouncer:

```bash
docker run -v \
          $PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml\
          -p 2112:2112\
           crowdflare
```

## From source

:warning: requires go >= 1.16

```bash
make release
cd crowdsec-cloudflare-bouncer-vX.X.X
sudo ./install.sh
```
Rest of the steps are same as of the above method.

**Always run `/usr/bin/crowdsec-cloudflare-bouncer -d` to cleanup cloudflare components before editing the config files.**

# Configuration

Configuration file can be found at `/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml`

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
    ip_list_prefix: crowdsec
    default_action: challenge
    zones:
    - actions: 
      - challenge # valid choices are either of challenge, js_challenge, block
      zone_id:
    
  update_frequency: 30s # the frequency to update the cloudflare IP list 

# Bouncer Config
daemon: true
log_mode: file
log_dir: /var/log/ 
log_level: info # valid choices are either debug, info, error 
cache_path: /var/lib/crowdsec/crowdsec-cloudflare-bouncer/cache/cloudflare-cache.json

prometheus:
  enabled: true
  listen_addr: 127.0.0.1
  listen_port: 2112
```

## Cloudflare Configuration:

**Background:** In Cloudflare, each user can have access to multiple accounts. Each account can own/access multiple zones. In this context a zone can be considered as a domain. Each domain registered with cloudflare gets a distinct `zone_id`.


For obtaining the `token`:
1. Sign in as a user who has access to the desired account.
2. Go to [Tokens](https://dash.cloudflare.com/profile/api-tokens) and create the token. The bouncer requires the follwing permissions to function.
![image](https://raw.githubusercontent.com/crowdsecurity/cs-cloudflare-bouncer/main/docs/assets/token_permissions.png)

To automatically generate config for cloudflare check the  helper section below.

**Note:** If the zone is subscribed to a paid Cloudflare plan then it can be configured to support multiple types of actions. For free plan zones only one action is supported. The first action is applied as default action.

# Helpers

The bouncer's binary has built in helper scripts to do various operations.

### Auto config generator: 

Generates bouncer config by discovering all the accounts and the zones associated with provided list of tokens. 

Example Usage:

```bash
/usr/local/bin/crowdsec-cloudflare-bouncer -g <TOKEN_1>,<TOKEN_2>... -o ./cfg.yaml 
vi cfg.yaml # make changes as needed
cat cfg.yaml  > /etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml
```

**Note:** This script only generates cloudflare related config. By default it refers to the config at `/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml` for crowdsec configuration. 

Using custom config:
```bash
/usr/local/bin/crowdsec-cloudflare-bouncer -c ./cfg.yaml -g <TOKEN_1>,<TOKEN_2>... 
```

Output can be redirected to file provided by the `-o` flag. If the `-o` flag is absent generated config would be printed to stdout

### Cloudflare Setup: 

This only creates the required IP lists and firewall rules at cloudflare and exits.

Example Usage:
```bash
/usr/local/bin/crowdsec-cloudflare-bouncer -s 
```

### Cloudflare Cleanup: 

This deletes all IP lists and firewall rules at cloudflare which were created by the bouncer. It also deletes the local cache. 

Example Usage:
```bash
/usr/local/bin/crowdsec-cloudflare-bouncer -d 
```

# How it works

The service polls the CrowdSec Local API for new decisions. It then makes API calls to Cloudflare
to update IP lists and firewall rules depending upon the decision.


# Troubleshooting
 - Metrics can be seen at http://localhost:2112/metrics
 - Logs are in `/var/log/crowdsec-cloudflare-bouncer.log`
 - The cache is at `/var/lib/crowdsec/crowdsec-cloudflare-bouncer/cache/cloudflare-cache.json`. It can be inspected to see the state of bouncer and cloudflare components locally.
 - You can view/interact directly in the ban list either with `cscli`
 - Service can be started/stopped with `systemctl start/stop crowdsec-cloudflare-bouncer`
