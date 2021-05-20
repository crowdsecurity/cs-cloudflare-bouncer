#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-cloudflare-bouncer"
BIN_PATH="./cs-cloudflare-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-cloudflare-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-cloudflare-bouncer.service"

LAPI_KEY=""
CF_TOKEN=""
CF_ACC_ID=""
CF_ZONE_ID=""

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
    LAPI_KEY=${LAPI_KEY} CF_TOKEN=${CF_TOKEN} CF_ACC_ID=${CF_ACC_ID} CF_ZONE_ID=${CF_ZONE_ID} envsubst < ./config/cs-cloudflare-bouncer.yaml > "${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
}

# gen_config_file() {
#     LAPI_KEY=${LAPI_KEY} envsubst < ./config/cs-cloudflare-bouncer.yaml > "${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
# }


install_cloudflare_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/cs-cloudflare-bouncer.yaml" "${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/cs-cloudflare-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}

read_cloudflare_creds(){
    read -p "Enter cloudflare API Token "  CF_TOKEN
    read -p "Enter cloudflare Account ID "  CF_ACC_ID
    read -p "Enter cloudflare Zone ID "  CF_ZONE_ID
}

while getopts t:a:z: flag
do
case "${flag}" in
    t) CF_TOKEN=${OPTARG};;
    a) CF_ACC_ID=${OPTARG};;
    z) CF_ZONE_ID=${OPTARG};;
esac
done

if ! [ $(id -u) = 0 ]; then
    echo "Please run the install script as root or with sudo"
    exit 1
fi

echo "Installing cs-cloudflare-bouncer"
install_cloudflare_bouncer
gen_apikey

if [ "$CF_TOKEN" = "" ] || [ "$CF_ZONE_ID" = "" ] || [ "$CF_ACC_ID" = "" ]; then
    read_cloudflare_creds
fi

gen_config_file
systemctl enable cs-cloudflare-bouncer.service
if [ "$READY" = "yes" ]; then
    systemctl start cs-cloudflare-bouncer.service
else
    echo "service not started. You need to get an API key and configure it in ${CONFIG_DIR}cs-cloudflare-bouncer.yaml"
fi
echo "The cs-cloudflare-bouncer service has been installed!"
