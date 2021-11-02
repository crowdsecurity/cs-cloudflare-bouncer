module github.com/crowdsecurity/cs-cloudflare-bouncer

go 1.16

require (
	github.com/cloudflare/cloudflare-go v0.16.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/crowdsecurity/crowdsec v1.2.1
	github.com/crowdsecurity/go-cs-bouncer v0.0.0-20211102140123-4cf1e1b3f89b
	github.com/logrusorgru/grokky v0.0.0-20180829062225-47edf017d42c // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible // indirect
	github.com/prometheus/client_golang v1.10.0
	github.com/sirupsen/logrus v1.8.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
