package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/websocket"
	"golang.org/x/time/rate"
)

func main() {
	publicAddr := flag.String("pub", ":5555", "listener address")
	adminAddr := flag.String("priv", ":6666", "admin listener address")
	adminKey := flag.String("adm-key", "qtIazZDhzrYERShXuYpqRx", "admin api key")
	flag.Parse()
	if *publicAddr == "" || *adminAddr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	wmux := websocket.Server{
		Handshake: bootHandshake,
		Handler:   handleWss,
	}

	startAdmin(*adminAddr, *adminKey)
	r := mux.NewRouter()
	r.Handle("/ws", wmux)
	// http.Handle("/cl/", http.StripPrefix("/cl", http.FileServer(http.Dir("./html"))))
	// r.PathPrefix("/cl/").Handler(http.StripPrefix("/cl", http.FileServer(http.Dir("./html"))))
	r.PathPrefix("/cl/").Handler(http.StripPrefix("/cl", FileServer(Dir("./html"))))

	srv := http.Server{
		Addr:    *publicAddr,
		Handler: r,
	}
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		if err := srv.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	log.Printf("server starts on: %s", *publicAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
	wc := 0
	for {
		a := atomic.LoadInt64(&activeWebsocks)
		if a <= 0 {
			log.Printf("%d active websockets, terminating", a)
			break
		}
		time.Sleep(300 * time.Millisecond)
		wc++
		if wc%100 == 0 {
			log.Printf("%d websockets are active, waiting", a)
		}
	}
}

var activeWebsocks int64

func handleWss(wsconn *websocket.Conn) {
	var ac prometheus.Gauge
	defer func() {
		atomic.AddInt64(&activeWebsocks, -1)
		wsconn.Close()
		if ac != nil {
			ac.Dec()
		}
	}()
	atomic.AddInt64(&activeWebsocks, 1)
	id := wsconn.Config().Header.Get(reqIDHdr)
	l := logFromID(id)
	l.logf("request headers: %v", wsconn.Request().Header)
	blocked, ips := getIPAdress(wsconn)
	if blocked {
		l.logf("blocking ip: %v", ips)
		return
	}
	l.logf("handlewss from %v", ips)
	totalConnectionRequests.WithLabelValues(svcHost, ips[0]).Inc()
	err := wsconn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		log.Printf("failed to set red deadline: %v", err)
		return
	}
	buf := make([]byte, 2048)
	_, err = wsconn.Read(buf)
	if err != nil {
		l.logf("failed to read connection msg: %v", err)
		return
	}
	var cr struct {
		Host string
		Port int
	}
	err = json.NewDecoder(bytes.NewBuffer(buf)).Decode(&cr)
	if err != nil {
		l.logf("failed to decode connection request [%s]: %v", buf, err)
		return
	}
	err = wsconn.SetReadDeadline(time.Time{})
	if err != nil {
		l.logf("failed to reset connection deadline: %v", err)
		return
	}
	l.logf("connecting to %s on port %d", cr.Host, cr.Port)
	if !isAllowedTarger(cr.Host) {
		l.logf("WARNING: connecting to %s is not allowed", cr.Host)
		return
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", cr.Host, cr.Port))
	if err != nil {
		log.Printf("failed to connect: %v", err)
		return
	}
	defer conn.Close()
	totalConnections.WithLabelValues(svcHost, ips[0], fmt.Sprintf("%s:%d", cr.Host, cr.Port)).Inc()
	ac = activeConnections.WithLabelValues(svcHost, ips[0], fmt.Sprintf("%s:%d", cr.Host, cr.Port))
	ac.Inc()
	wsconn.PayloadType = websocket.BinaryFrame

	cw, wsw := newLimters(conn, wsconn, l)

	done := make(chan struct{})

	go ping(l, wsconn, done)

	alive := true
	mu := sync.Mutex{}

	go func() {
		n, err := io.Copy(&meteredWriter{
			w: cw,
			c: totalBytes.WithLabelValues(svcHost, ips[0], fmt.Sprintf("%s:%d", cr.Host, cr.Port), "up"),
		}, wsconn)
		er := "without error"
		if err != nil {
			er = fmt.Sprintf("with error %v", err)
		}
		l.logf("copying to server finished after copying %d bytes %s", n, er)
		mu.Lock()
		if alive {
			close(done)
			alive = false
		}
		mu.Unlock()
	}()
	go func() {
		n, err := io.Copy(&meteredWriter{
			w: wsw,
			c: totalBytes.WithLabelValues(svcHost, ips[0], fmt.Sprintf("%s:%d", cr.Host, cr.Port), "down"),
		}, conn)
		er := "without error"
		if err != nil {
			er = fmt.Sprintf("with error %v", err)
		}
		l.logf("copying from server finished after copying %d bytes %s", n, er)
		mu.Lock()
		if alive {
			close(done)
			alive = false
		}
		mu.Unlock()
	}()

	<-done
	l.logf("proxy quit")
}

func ping(l logger, ws *websocket.Conn, done chan struct{}) {
	w, err := ws.NewFrameWriter(websocket.PingFrame)
	if err != nil {
		l.logf("failed to create pingwriter: %v", err)
		return
	}
	ticker := time.Tick(20 * time.Second)
	for {
		select {
		case <-ticker:
			_, err = w.Write(nil)
			if err != nil {
				l.logf("failed to write ping msg: %v", err)
				return
			}
		case <-done:
			return
		}
	}
}

type rCtx struct {
	headers http.Header
}

const reqIDHdr = "X-Request-ID"

func bootHandshake(config *websocket.Config, r *http.Request) error {
	// config.Protocol = []string{"binary"}
	u, err := uuid.NewRandom()
	id := "not-uuid"
	if err == nil {
		id = u.String()
	}
	config.Header = make(http.Header)
	config.Header.Set(reqIDHdr, id)

	// r.Header.Set("Access-Control-Allow-Origin", "*")
	// r.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")

	return nil
}

var (
	blacklistedSources []string
	blacklistSrcMu     sync.RWMutex
	sourceRates        = map[string]*rate.Limiter{}
)

func getIPAdress(ws *websocket.Conn) (bool, []string) {
	// using sprintf as it panics locally
	var ips []string
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(ws.Request().Header.Get(h), ",")
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])

			ips = append(ips, ip)
		}
	}
	ips = append(ips, fmt.Sprintf("%v", ws.RemoteAddr()))
	blacklistSrcMu.RLock()
	defer blacklistSrcMu.RUnlock()
	if sourceRates[ips[0]] == nil {
		sourceRates[ips[0]] = rate.NewLimiter(rate.Limit(1), 1)
	}
	for _, bi := range blacklistedSources {
		for _, ip := range ips {
			if strings.HasPrefix(ip, bi) {
				return true, ips
			}
		}
	}
	return !sourceRates[ips[0]].Allow(), ips
}

var (
	blacklistedTargets = []string{"localhost", "127.0.0.1", "::1"}
	// blacklistedTargets = []string{}
	blacklistMu sync.RWMutex
)

func isAllowedTarger(host string) bool {
	blacklistMu.RLock()
	for _, h := range blacklistedTargets {
		if host == h {
			return false
		}
	}
	blacklistMu.RUnlock()

	return true
}

var (
	freeLimit                 = 1024 * 1024 * 1024
	maxLimitedRate rate.Limit = 100 * 1024
	maxBurst                  = 64 * 1024
)

func newLimters(w1, w2 io.Writer, logger logger) (*limitedWriter, *limitedWriter) {
	l := rate.NewLimiter(maxLimitedRate, maxBurst)
	return &limitedWriter{w: w1, limiter: l, log: logger}, &limitedWriter{w: w2, limiter: l, log: logger}
}

type limitedWriter struct {
	w       io.Writer
	written int
	limiter *rate.Limiter
	log     logger
}

func (w *limitedWriter) Write(b []byte) (n int, err error) {
	if w.written > freeLimit {
		if err := w.limiter.WaitN(context.Background(), len(b)); err != nil {
			w.log.logf("limiter wait error: %v", err)
		}
	}
	w.written += len(b)
	return w.w.Write(b)
}

type meteredWriter struct {
	w io.Writer
	c prometheus.Counter
}

func (w *meteredWriter) Write(b []byte) (n int, err error) {
	n, err = w.w.Write(b)
	w.c.Add(float64(n))
	return n, err
}

type logger string

func (l logger) logf(fmt string, args ...interface{}) {
	log.Printf(string(l)+fmt, args...)
}

func newLogger() logger {
	u, err := uuid.NewRandom()
	id := "not-uuid"
	if err == nil {
		id = u.String()
	}
	return logFromID(id)
}

func logFromID(id string) logger {
	return logger(id[:8] + " ")
}
