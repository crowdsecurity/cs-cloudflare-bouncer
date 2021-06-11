package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

func HandleSignals(ctx context.Context) {
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

func main() {

	// Create go routine per cloudflare account
	// By using channels, after every nth second feed the decisions to each cf routine.
	// Each cf routine maintains it's own IP list and cache.

	configTokens := flag.String("g", "", "comma separated tokens to generate config for")
	configPath := flag.String("c", "", "path to config file")
	flag.Parse()

	if configTokens != nil && *configTokens != "" {
		if configPath == nil || *configPath == "" {
			err := ConfigTokens(*configTokens, "/etc/crowdsec/cs-cloudflare-bouncer/cs-cloudflare-bouncer.yaml")
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err := ConfigTokens(*configTokens, *configPath)
			if err != nil {
				log.Fatal(err)
			}
		}
		return
	}
	if configPath == nil || *configPath == "" {
		log.Fatalf("config file required")
	}

	ctx := context.Background()
	conf, err := NewConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

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
		for _, zone := range account.Zones {
			zoneLocks = append(zoneLocks, ZoneLock{ZoneID: zone.ID, Lock: &sync.Mutex{}})
		}
	}

	// lapiStreams are used to forward the decisions to all the workers
	lapiStreams := make([]chan *models.DecisionsStreamResponse, 0)
	var workerTomb tomb.Tomb
	var wg sync.WaitGroup

	for _, account := range conf.CloudflareConfig.Accounts {
		lapiStream := make(chan *models.DecisionsStreamResponse)
		lapiStreams = append(lapiStreams, lapiStream)
		wg.Add(1)
		worker := CloudflareWorker{
			Account:         account,
			Ctx:             ctx,
			ZoneLocks:       zoneLocks,
			LAPIStream:      lapiStream,
			UpdateFrequency: conf.CloudflareConfig.UpdateFrequency,
			Wg:              &wg,
		}
		workerTomb.Go(func() error {
			err := worker.Run()
			return err
		})
	}
	var dispatchTomb tomb.Tomb

	dispatchTomb.Go(func() error {
		wg.Wait()
		go csLapi.Run()
		for {
			select {
			case decisions := <-csLapi.Stream:
				// broadcast decision to each worker
				for _, lapiStream := range lapiStreams {
					lapiStream <- decisions
				}
			}
		}
	})

	if conf.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Fatalf("failed to notify: %v", err)
		}
		go HandleSignals(ctx)
	}

	for {
		select {
		case <-workerTomb.Dying():
			dispatchTomb.Kill(nil)
			log.Fatal("at least one of the workers is dying, shutdown")
		case <-dispatchTomb.Dying():
			workerTomb.Kill(nil)
			log.Fatal("dispatch is dying")
		}
	}

}
