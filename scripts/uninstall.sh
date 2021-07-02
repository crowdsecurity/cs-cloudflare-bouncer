#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-cloudflare-bouncer"
CONFIG_DIR="/etc/crowdsec/crowdsec-cloudflare-bouncer/"
LOG_FILE="/var/log/crowdsec-cloudflare-bouncer.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-cloudflare-bouncer.service"

uninstall() {
	systemctl stop crowdsec-cloudflare-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "crowdsec-cloudflare-bouncer uninstall successfully"