#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-cloudflare-bouncer"
BIN_PATH="./cs-cloudflare-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-cloudflare-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-cloudflare-bouncer.service"

LAPI_KEY=""

gen_apikey() {
    which cscli > /dev/null
    if [[ $? == 0 ]]; then 
        echo "cscli found, generating bouncer api key."
        SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
        LAPI_KEY=`cscli bouncers add cs-cloudflare-bouncer-${SUFFIX} -o raw`
        READY="yes"
    else 
        echo "cscli not found, you will need to generate api key."
        READY="no"
    fi
}

gen_config_file() {
    LAPI_KEY=${LAPI_KEY} envsubst < ./config/cs-cloudflare-bouncer.yaml > "${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
}


install_cloudflare_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/cs-cloudflare-bouncer.yaml" "${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/cs-cloudflare-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}

start_service(){
    if [ "$READY" = "yes" ]; then
        systemctl start cs-cloudflare-bouncer.service
    else
        echo "service not started. You need to get an API key and configure it in ${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
    fi
    echo "The cs-cloudflare-bouncer service has been installed!"
}

show_help(){
    echo "Usage:"
    echo "    ./install.sh -h                               Display this help message."
    echo "    ./install.sh --unattended                     Install in unattended mode, cloudflare credentials need to be provided manually in the config file"

}

install_bouncer(){
    echo "Installing cs-cloudflare-bouncer"
    install_cloudflare_bouncer
    gen_apikey

    gen_config_file
    systemctl enable cs-cloudflare-bouncer.service
}


if ! [ $(id -u) = 0 ]; then
    echo "Please run the install script as root or with sudo"
    exit 1
fi

if [[ $# -eq 0 ]]; then
    install_bouncer 
    ${EDITOR:-vi} "${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
    start_service
    exit 0
else
    key="${1}"

    if [[ ${key} == "--unattended" ]]; then
        install_bouncer
        echo "Please provide your Cloudflare credentials at  ${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
        echo "After configuration run the command 'systemctl start cs-cloudflare-bouncer.service' to start the bouncer"
    elif [[ ${key} == "-h" ]]; then
        show_help
    else 
        echo "Unknown argument ${key}."
    fi
fi
