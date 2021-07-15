module github.com/crowdsecurity/cs-cloudflare-bouncer

go 1.16

require (
	github.com/cloudflare/cloudflare-go v0.16.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/crowdsecurity/crowdsec v1.0.15-0.20210602122734-71c1d9431fda
	github.com/crowdsecurity/go-cs-bouncer v0.0.0-20210715153028-e96121f59525
	github.com/prometheus/client_golang v1.9.0
	github.com/sirupsen/logrus v1.8.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
