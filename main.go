package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cf"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/version"
)

const (
	DEFAULT_CONFIG_PATH = "/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml"
	name = "crowdsec-cloudflare-bouncer"
)

func main() {
	// Create go routine per cloudflare account
	// By using channels, after every nth second feed the decisions to each cf routine.
	// Each cf routine maintains it's own IP list and cache.

	configTokens := flag.String("g", "", "comma separated tokens to generate config for")
	configOutputPath := flag.String("o", "", "path to store generated config to")
	configPath := flag.String("c", "", "path to config file")
	onlySetup := flag.Bool("s", false, "only setup the ip lists and rules for cloudflare and exit")
	delete := flag.Bool("d", false, "delete IP lists and firewall rules which are created by the bouncer")
	ver := flag.Bool("version", false, "Display version information and exit")
	logAPIRequests := flag.Bool("lc", false, "logs API requests")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	flag.Parse()

	if *ver {
		version.Show()
		return
	}

	log.AddHook(&writer.Hook{ // Send logs with level fatal to stderr
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	if *delete && *onlySetup {
		log.Fatal("conflicting cli arguments, pass only one of '-d' or '-s' ")
	}

	if configPath == nil || *configPath == "" {
		*configPath = DEFAULT_CONFIG_PATH
	}

	if configTokens != nil && *configTokens != "" {
		cfgTokenString, err := cfg.ConfigTokens(*configTokens, *configPath)
		if err != nil {
			log.Fatal(err)
		}
		if configOutputPath != nil && *configOutputPath != "" {
			err := os.WriteFile(*configOutputPath, []byte(cfgTokenString), 0664)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Config successfully generated in %s", *configOutputPath)
		} else {
			fmt.Print(cfgTokenString)
		}
		return
	}

	configBytes, err := cfg.MergedConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load config: %v", err)
	}

	if *showConfig {
		fmt.Println(string(configBytes))
		return
	}

	conf, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		log.Fatal(err)
	}

	if *testConfig {
		log.Info("config is valid")
		return
	}

	if *delete || *onlySetup {
		log.SetOutput(os.Stdout)
	}

	APILogger := log.New()
	if *logAPIRequests {
		f, err := os.OpenFile(
			filepath.Join(conf.LogDir, "crowdsec-cloudflare-bouncer-api-calls.log"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		APILogger.SetOutput(f)
		APILogger.Level = log.DebugLevel
	} else {
		APILogger.SetOutput(io.Discard)
	}

	var csLAPI *csbouncer.StreamBouncer
	ctx := context.Background()

	zoneLocks := make([]cf.ZoneLock, 0)
	for _, account := range conf.CloudflareConfig.Accounts {
		for _, zone := range account.ZoneConfigs {
			zoneLocks = append(zoneLocks, cf.ZoneLock{ZoneID: zone.ID, Lock: &sync.Mutex{}})
		}
	}

	var workerTomb tomb.Tomb
	var serverTomb tomb.Tomb
	var dispatchTomb tomb.Tomb

	// lapiStreams are used to forward the decisions to all the workers
	lapiStreams := make([]chan *models.DecisionsStreamResponse, 0)
	APICountByToken := make(map[string]*uint32)

	for _, account := range conf.CloudflareConfig.Accounts {
		lapiStream := make(chan *models.DecisionsStreamResponse)
		lapiStreams = append(lapiStreams, lapiStream)

		var tokenCallCount uint32 = 0
		// we want same reference of tokenCallCount per account token
		if _, ok := APICountByToken[account.Token]; !ok {
			APICountByToken[account.Token] = &tokenCallCount
		}

		worker := cf.CloudflareWorker{
			Account:         account,
			APILogger:       APILogger,
			Ctx:             ctx,
			ZoneLocks:       zoneLocks,
			LAPIStream:      lapiStream,
			UpdateFrequency: conf.CloudflareConfig.UpdateFrequency,
			CFStateByAction: make(map[string]*cf.CloudflareState),
			TokenCallCount:  APICountByToken[account.Token],
		}
		if *onlySetup {
			workerTomb.Go(func() error {
				var err error = nil
				defer func() {
					workerTomb.Kill(err)
				}()

				worker.CFStateByAction = nil
				err = worker.Init()
				if err != nil {
					return err
				}
				err = worker.SetUpCloudflareResources()
				return err

			})
		} else if *delete {
			workerTomb.Go(func() error {
				var err error = nil
				defer func() {
					workerTomb.Kill(err)
				}()
				err = worker.Init()
				if err != nil {
					return nil
				}
				err = worker.DeleteExistingIPList()
				return err

			})
		} else {
			workerTomb.Go(func() error {
				err := worker.Run()
				return err
			})
		}
	}

	if !*onlySetup && !*delete {
		log.Infof("Starting %s %s", name, version.VersionStr())
		csLAPI = &csbouncer.StreamBouncer{
			APIKey:         conf.CrowdSecLAPIKey,
			APIUrl:         conf.CrowdSecLAPIUrl,
			TickerInterval: conf.CrowdsecUpdateFrequencyYAML,
			UserAgent:      fmt.Sprintf("%s/%s", name, version.VersionStr()),
			Opts: apiclient.DecisionsStreamOpts{
				Scopes:                 "ip,range,as,country",
				ScenariosNotContaining: strings.Join(conf.ExcludeScenariosContaining, ","),
				ScenariosContaining:    strings.Join(conf.IncludeScenariosContaining, ","),
				Origins:                strings.Join(conf.OnlyIncludeDecisionsFrom, ","),
			},
			CertPath: conf.CertPath,
			KeyPath:  conf.KeyPath,
			CAPath:   conf.CAPath,
		}
		if err := csLAPI.Init(); err != nil {
			log.Fatalf(err.Error())
		}
		dispatchTomb.Go(func() error {
			go func() {
				csLAPI.Run()
				log.Fatal("LAPI can't be reached")
			}()
			for {
				// broadcast decision to each worker
				decisions := <-csLAPI.Stream
				for _, lapiStream := range lapiStreams {
					lapiStream <- decisions
				}
			}
		})
	}

	if conf.PrometheusConfig.Enabled {
		serverTomb.Go(func() error {
			http.Handle("/metrics", promhttp.Handler())
			err := http.ListenAndServe(net.JoinHostPort(conf.PrometheusConfig.ListenAddress, conf.PrometheusConfig.ListenPort), nil)
			return err
		})
	}

	apiCallCounterWindow := time.NewTicker(time.Second)
	go func() {
		for {
			<-apiCallCounterWindow.C
			for token := range APICountByToken {
				atomic.SwapUint32(APICountByToken[token], 0)
			}
		}
	}()

	for {
		select {
		case <-workerTomb.Dying():
			dispatchTomb.Kill(nil)
			err := workerTomb.Err()
			if err != nil {
				log.Fatal(err)
			}
			if *onlySetup || *delete {
				if *delete {
					log.Info("deleted all cf config")

				} else {
					log.Info("setup complete")
				}
			}
			return
		case <-dispatchTomb.Dying():
			workerTomb.Kill(nil)
			log.Fatal("dispatch is dying")
		}
	}

}
