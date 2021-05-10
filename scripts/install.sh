#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/cs-cloudfare-bouncer"
BIN_PATH="./cs-cloudfare-bouncer"
CONFIG_DIR="/etc/crowdsec/cs-cloudfare-bouncer/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/cs-cloudfare-bouncer.service"

LAPI_KEY=""
CF_TOKEN=""
CF_ACC_ID=""
CF_ZONE_ID=""

gen_apikey() {
    which cscli > /dev/null
    if [[ $? == 0 ]]; then 
        echo "cscli found, generating bouncer api key."
        SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
        LAPI_KEY=`cscli bouncers add cs-cloudfare-bouncer-${SUFFIX} -o raw`
        READY="yes"
    else 
        echo "cscli not found, you will need to generate api key."
        READY="no"
    fi
}

 
 
gen_config_file() {
    LAPI_KEY=${LAPI_KEY} CF_TOKEN=${CF_TOKEN} CF_ACC_ID=${CF_ACC_ID} CF_ZONE_ID=${CF_ZONE_ID} envsubst < ./config/cs-cloudfare-bouncer.yaml > "${CONFIG_DIR}cs-cloudfare-bouncer.yaml"
}

# gen_config_file() {
#     LAPI_KEY=${LAPI_KEY} envsubst < ./config/cs-cloudfare-bouncer.yaml > "${CONFIG_DIR}cs-cloudfare-bouncer.yaml"
# }


install_cloudfare_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/cs-cloudfare-bouncer.yaml" "${CONFIG_DIR}cs-cloudfare-bouncer.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/cs-cloudfare-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}

read_cloudfare_creds(){
    read -p "Enter Cloudfare API Token "  CF_TOKEN
    read -p "Enter Cloudfare Account ID "  CF_ACC_ID
    read -p "Enter Cloudfare Zone ID "  CF_ZONE_ID
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

echo "Installing cs-cloudfare-bouncer"
install_cloudfare_bouncer
gen_apikey

if [ "$CF_TOKEN" = "" ] || [ "$CF_TOKEN" = "" ] || [ "$CF_TOKEN" = "" ]; then
    read_cloudfare_creds
fi

gen_config_file
systemctl enable cs-cloudfare-bouncer.service
if [ "$READY" = "yes" ]; then
    systemctl start cs-cloudfare-bouncer.service
else
    echo "service not started. You need to get an API key and configure it in ${CONFIG_DIR}cs-cloudfare-bouncer.yaml"
fi
echo "The cs-cloudfare-bouncer service has been installed!"
