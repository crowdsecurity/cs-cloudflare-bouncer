#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/cs-cloudfare-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-cloudfare-bouncer/"
LOG_FILE="/var/log/cs-cloudfare-bouncer.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-cloudfare-bouncer.service"

uninstall() {
	systemctl stop cs-cloudfare-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "cs-cloudfare-bouncer uninstall successfully"