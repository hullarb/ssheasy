package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"golang.org/x/time/rate"
)

var (
	totalConnectionRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "connection_requests_total",
		Help: "The total number of connection requests",
	}, []string{"host"})
	totalBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bytes_total",
		Help: "The total number of bytes proxied",
	}, []string{"host", "dir"})
	totalConnections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "connections_total",
		Help: "The total number of connections",
	}, []string{"host"})
	activeConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "connections_active",
		Help: "The current number of active connections",
	}, []string{"host"})
	svcHost string
)

func init() {
	var err error
	svcHost, err = os.Hostname()
	if err != nil {
		panic(err)
	}
}

func startAdmin(addr, key string) {
	r := mux.NewRouter()
	r.Handle("/metrics", promhttp.Handler())
	s := r.PathPrefix("/config").Subrouter()
	s.HandleFunc("/rate", getRate).Methods("GET")
	s.HandleFunc("/rate", setRate).Methods("POST")
	s.HandleFunc("/blacklist", getBlackList).Methods("GET")
	s.HandleFunc("/blacklist", getBlackList).Methods("GET")
	s.HandleFunc("/srcblacklist", getSrcBlackList).Methods("GET")
	s.HandleFunc("	/srcblacklist", setSrcBlackList).Methods("POST")
	s.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("admin request from %s", r.RemoteAddr)
			if len(r.Header["Authorization"]) == 0 || r.Header["Authorization"][0] != "Basic "+key {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
	}

	log.Printf("admin starts on: %s", addr)
	go func() {
		log.Fatal("admin stopped", srv.ListenAndServe())
	}()
}

func getRate(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Free limit: %v, Max burst: %v, Limited rate: %v\n", freeLimit, maxBurst, maxLimitedRate)
}

type rateReq struct {
	FreeLimit int
	MaxBurst  int
	Rate      rate.Limit
}

func setRate(w http.ResponseWriter, r *http.Request) {
	var rr rateReq
	if err := json.NewDecoder(r.Body).Decode(&rr); err != nil {
		log.Printf("failed to decode rate req: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if rr.FreeLimit > 0 {
		freeLimit = rr.FreeLimit
	}
	if rr.MaxBurst > 0 {
		maxBurst = rr.MaxBurst
	}
	if rr.Rate > 0 {
		maxLimitedRate = rr.Rate
	}
	w.WriteHeader(http.StatusOK)
}

func setBlackList(w http.ResponseWriter, r *http.Request) {
	var blr struct {
		Hosts []string
	}
	if err := json.NewDecoder(r.Body).Decode(&blr); err != nil {
		log.Printf("failed to decode blacklist req: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	blacklistMu.Lock()
	blacklistedTargets = blr.Hosts
	blacklistMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func getBlackList(w http.ResponseWriter, r *http.Request) {
	blacklistMu.RLock()
	bh := blacklistedTargets
	blacklistMu.RUnlock()
	fmt.Fprintf(w, "Blacklisted Hosts: %v", bh)
}

func setSrcBlackList(w http.ResponseWriter, r *http.Request) {
	var blr struct {
		Hosts []string
	}
	if err := json.NewDecoder(r.Body).Decode(&blr); err != nil {
		log.Printf("failed to decode src blacklist req: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	blacklistSrcMu.Lock()
	blacklistedSources = blr.Hosts
	blacklistSrcMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func getSrcBlackList(w http.ResponseWriter, r *http.Request) {
	blacklistSrcMu.RLock()
	bh := blacklistedSources
	blacklistSrcMu.RUnlock()
	fmt.Fprintf(w, "Blacklisted Sources: %v", bh)
}
