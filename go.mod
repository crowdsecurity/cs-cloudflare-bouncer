module github.com/crowdsecurity/cs-cloudflare-bouncer

go 1.16

require (
	github.com/cloudflare/cloudflare-go v0.40.1-0.20220527055342-b3795adaff97
	github.com/crowdsecurity/crowdsec v1.4.6
	github.com/crowdsecurity/go-cs-bouncer v0.0.2
	github.com/prometheus/client_golang v1.13.0
	github.com/sirupsen/logrus v1.9.0
	golang.org/x/time v0.0.0-20220411224347-583f2d630306 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v3 v3.0.1
)
