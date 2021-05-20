#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/cs-cloudflare-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-cloudflare-bouncer/"
LOG_FILE="/var/log/cs-cloudflare-bouncer.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-cloudflare-bouncer.service"

uninstall() {
	systemctl stop cs-cloudflare-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "cs-cloudflare-bouncer uninstall successfully"