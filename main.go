package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

const DEFAULT_CONFIG_PATH string = "/etc/crowdsec/cs-cloudflare-bouncer/cs-cloudflare-bouncer.yaml"

var cachePath string = "/etc/crowdsec/cs-cloudflare-bouncer/cache.json"

func HandleSignals() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			case syscall.SIGTERM:
				exitChan <- 0
			}
		}
	}()
	code := <-exitChan
	log.Infof("Shutting down cloudflare-bouncer service")
	os.Exit(code)
}

func loadCachedStates(states *[]CloudflareState) error {
	if _, err := os.Stat(cachePath); err != nil {
		log.Debug("no cache found")
		return nil
	}
	f, err := os.Open(cachePath)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &states)
	return err
}

func dumpStates(states *[]CloudflareState) error {
	data, err := json.MarshalIndent(states, "", "	")
	if err != nil {
		return err
	}
	err = os.WriteFile(cachePath, data, 0666)
	if err != nil {
		return err
	}
	return nil
}

func deleteCacheIfExists() error {
	var err error
	if _, err = os.Stat(cachePath); err == nil {
		err = os.Remove(cachePath)
	}
	return err
}

func updateStates(states *[]CloudflareState, newStates map[string]*CloudflareState) {
	found := false
	for i, state := range *states {
		for _, receivedState := range newStates {
			if receivedState.AccountID == state.AccountID && receivedState.Action == state.Action {
				(*states)[i] = *receivedState
				found = true
			}
		}
	}
	if !found {
		for _, receivedState := range newStates {
			*states = append(*states, *receivedState)
		}
	}
}

func main() {

	// Create go routine per cloudflare account
	// By using channels, after every nth second feed the decisions to each cf routine.
	// Each cf routine maintains it's own IP list and cache.

	configTokens := flag.String("g", "", "comma separated tokens to generate config for")
	configPath := flag.String("c", "", "path to config file")
	onlySetup := flag.Bool("s", false, "only setup the ip lists and rules for cloudflare and exit")
	delete := flag.Bool("d", false, "delete IP lists and firewall rules which are created by the bouncer")

	flag.Parse()

	if *delete && *onlySetup {
		log.Fatal("conflicting cli arguements, pass only one of '-d' or '-s' ")
	}

	if configPath == nil || *configPath == "" {
		*configPath = DEFAULT_CONFIG_PATH
	}

	if configTokens != nil && *configTokens != "" {
		cfg, err := ConfigTokens(*configTokens, *configPath)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(cfg)
		return
	}
	conf, err := NewConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	csLapi := &csbouncer.StreamBouncer{
		APIKey:         conf.CrowdSecLAPIKey,
		APIUrl:         conf.CrowdSecLAPIUrl,
		TickerInterval: conf.CrowdsecUpdateFrequencyYAML,
	}

	if err := csLapi.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	zoneLocks := make([]ZoneLock, 0)
	for _, account := range conf.CloudflareConfig.Accounts {
		for _, zone := range account.ZoneConfigs {
			zoneLocks = append(zoneLocks, ZoneLock{ZoneID: zone.ID, Lock: &sync.Mutex{}})
		}
	}

	var workerTomb tomb.Tomb
	var serverTomb tomb.Tomb
	var dispatchTomb tomb.Tomb
	var stateTomb tomb.Tomb

	var wg sync.WaitGroup
	var Count prometheus.Counter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cloudflare_api_calls",
		Help: "The total number of API calls to cloudflare made by CrowdSec bouncer",
	})

	// lapiStreams are used to forward the decisions to all the workers
	lapiStreams := make([]chan *models.DecisionsStreamResponse, 0)
	stateStream := make(chan map[string]*CloudflareState)
	workerStates := make([]CloudflareState, 0)

	err = loadCachedStates(&workerStates)
	if err != nil {
		log.Fatal(err)
	}

	for _, account := range conf.CloudflareConfig.Accounts {
		lapiStream := make(chan *models.DecisionsStreamResponse)
		lapiStreams = append(lapiStreams, lapiStream)
		states := make(map[string]*CloudflareState)
		for _, s := range workerStates {
			//TODO  search can be avoided by having a map by account id
			tmp := s
			if s.AccountID == account.ID {
				states[s.Action] = &tmp
			}
		}

		wg.Add(1)
		worker := CloudflareWorker{
			Account:         account,
			Ctx:             ctx,
			ZoneLocks:       zoneLocks,
			LAPIStream:      lapiStream,
			UpdateFrequency: conf.CloudflareConfig.UpdateFrequency,
			Wg:              &wg,
			UpdatedState:    stateStream,
			CFStateByAction: states,
			Count:           Count,
		}
		if *onlySetup {
			workerTomb.Go(func() error {
				var err error = nil
				defer func() {
					workerTomb.Kill(err)
					stateStream <- nil
				}()

				worker.CFStateByAction = nil
				err = worker.Init()
				if err != nil {
					return err
				}
				err = worker.SetUpCloudflareIfNewState()
				return err

			})
		} else if *delete {
			workerTomb.Go(func() error {
				var err error = nil
				defer func() {
					workerTomb.Kill(err)
					stateStream <- nil
				}()
				err = worker.Init()
				if err != nil {
					return nil
				}
				err = worker.deleteExistingIPList()
				return err

			})
		} else {
			workerTomb.Go(func() error {
				err := worker.Run()
				return err
			})
		}
	}

	dispatchTomb.Go(func() error {
		go csLapi.Run()
		for {
			decisions := <-csLapi.Stream
			// broadcast decision to each worker
			for _, lapiStream := range lapiStreams {
				lapiStream <- decisions
			}
		}
	})

	stateTomb.Go(func() error {
		aliveWorkerCount := len(conf.CloudflareConfig.Accounts)
		for {
			newStates := <-stateStream
			if newStates == nil {
				aliveWorkerCount--
				if aliveWorkerCount == 0 {
					err := stateTomb.Killf("all workers are dead")
					return err
				}
			}
			updateStates(&workerStates, newStates)
			err := dumpStates(&workerStates)
			log.Debug("updated cache")
			if err != nil {
				log.Error(err)
				return err
			}
		}
	})

	serverTomb.Go(func() error {
		http.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe(":2112", nil)
		return err
	})

	if conf.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Fatalf("failed to notify: %v", err)
		}
		go HandleSignals()
	}

	for {
		select {
		case <-workerTomb.Dying():
			dispatchTomb.Kill(nil)
			err := workerTomb.Err()
			if err != nil {
				log.Fatal(err)
			}
			if *onlySetup || *delete {
				stateTomb.Wait()
				if *delete {
					err = deleteCacheIfExists()
					if err != nil {
						log.Errorf("while deleting cache got %s", err.Error())
					}
					log.Info("deleted all cf config")

				} else {
					log.Info("setup complete")
				}
			}
			stateTomb.Kill(nil)
			return
		case <-dispatchTomb.Dying():
			workerTomb.Kill(nil)
			stateTomb.Kill(nil)
			log.Fatal("dispatch is dying")

		case <-stateTomb.Dying():
			workerTomb.Kill(nil)
			dispatchTomb.Kill(nil)
			log.Fatal("state routine is dying")
		}
	}

}
