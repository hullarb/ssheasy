package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"syscall/js"

	"net"

	"github.com/hullarb/dom/net/ws"
	"golang.org/x/crypto/ssh"
)

var (
	sshCon    net.Conn
	sshClient *ssh.Client
)

var fpAccepted chan bool

func main() {

	init := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			if len(args) < 7 {
				log.Println("not enough argument to call init")
				return
			}
			host, port := args[2].String(), args[3].Int()
			usr, pass, key, bypassProxy, bypassFingerprint := args[4].String(), args[5].String(), args[6].String(), args[7].Bool(), args[8].Bool()
			sshCon = con(host, port, bypassProxy)
			fpAccepted = make(chan bool)

			if pass == "" && key == "" {
				log.Fatal("password or privatre key has to be provided")
			}
			var auth []ssh.AuthMethod
			if pass != "" {
				auth = append(auth, ssh.Password(pass))
			}
			if key != "" {
				signer, err := ssh.ParsePrivateKey([]byte(key))
				if err != nil {
					log.Fatalf("failed to parse pk %v", err)
				}
				auth = append(auth, ssh.PublicKeys(signer))
			}

			hostKeyCallback := showFingerprint
			if bypassFingerprint {
				hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					return nil
				}
			}
			cConf := &ssh.ClientConfig{
				User:            usr,
				Auth:            auth,
				HostKeyCallback: hostKeyCallback,
			}

			cc, nc, r, err := ssh.NewClientConn(sshCon, host, cConf)
			if err != nil {
				log.Fatalf("failed to create client conn %v", err)
			}

			sshClient = ssh.NewClient(cc, nc, r)

			s, err := sshClient.NewSession()
			if err != nil {
				log.Fatalf("failed to create new session %v", err)
			}

			so, err := s.StdoutPipe()
			if err != nil {
				log.Fatalf("failed to pipe stdout: %v", err)
			}
			se, err := s.StderrPipe()
			if err != nil {
				log.Fatalf("failed to pipe stderr: %v", err)
			}
			forwardOutStreams(so, se)
			inp, err := s.StdinPipe()
			if err != nil {
				log.Fatalf("failed to pipe stdinp: %v", err)
			}

			// Set up terminal modes
			modes := ssh.TerminalModes{
				ssh.ECHO:          1, // disable echoing
				ssh.ICRNL:         1,
				ssh.IXON:          1,
				ssh.IXANY:         1,
				ssh.IMAXBEL:       1,
				ssh.OPOST:         1,
				ssh.ONLCR:         1,
				ssh.ISIG:          1,
				ssh.ICANON:        1,
				ssh.IEXTEN:        1,
				ssh.ECHOE:         1,
				ssh.ECHOK:         1,
				ssh.ECHOCTL:       1,
				ssh.ECHOKE:        1,
				ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
				ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
			}

			// Request pseudo terminal
			rows, cols := args[0].Int(), args[1].Int()
			log.Printf("requesting %dx%d terminal", rows, cols)
			if err := s.RequestPty("xterm", rows, cols, modes); err != nil {
				log.Fatalf("request for pseudo terminal failed: %s", err)
			}

			// Start remote shell
			if err := s.Shell(); err != nil {
				log.Fatalf("failed to start shell: %s", err)
			}

			kcb := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				if len(args) < 1 {
					fmt.Println("onKey received empty args")
					return nil
				}
				// fmt.Printf("input written: %d[%v] (%v)\n", len(args), args[0], args[0].Type())
				//	writeToConsole(args[0].String())
				inp.Write([]byte(args[0].String()))
				return nil
			})
			js.Global().Get("term").Call("on", "data", kcb)
			nlcb := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				if len(args) < 1 {
					fmt.Println("onKey received empty args")
					return nil
				}
				fmt.Printf("linefeed event: %d[%v] (%v)\n", len(args), args[0], args[0].Type())
				writeToConsole("\n")
				inp.Write([]byte("\n"))
				return nil
			})
			js.Global().Get("term").Call("on", "lineFeed", nlcb)
			initSftp(sshClient)
			h := getwd()
			js.Global().Set("home", h)
			js.Global().Call("connected", fmt.Sprintf("Connected to %s@%s", usr, host), h)
		}()
		return nil
	})

	js.Global().Set("initConnection", init)
	js.Global().Set("acceptFingerprint", js.FuncOf(acceptFP))
	initFileBrowserAPI()

	fmt.Println("main is running")

	ch := make(chan struct{})
	<-ch
	fmt.Println("main exited")
}
func acceptFP(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		log.Println("not enough argument to call acceptFP")
		return nil
	}
	fpAccepted <- args[0].Bool()
	return nil
}
func showFingerprint(hostname string, remote net.Addr, key ssh.PublicKey) error {
	fp := FingerprintMD5(key)
	js.Global().Call("showServerKey", fp)
	a := <-fpAccepted
	if !a {
		return errors.New("user didn't accept host key")
	}
	return nil
}

func FingerprintMD5(key ssh.PublicKey) string {
	hash := md5.Sum(key.Marshal())
	out := ""
	for i := 0; i < 16; i++ {
		if i > 0 {
			out += ":"
		}
		out += fmt.Sprintf("%02x", hash[i]) // don't forget the leading zeroes
	}
	return out
}

func forwardOutStreams(o, e io.Reader) {
	go func() {
		ob := make([]byte, 2048)
		for {
			n, err := o.Read(ob)
			if err != nil {
				fmt.Printf("error reading from stdout: %v]\n", err)
				return
			}
			// fmt.Printf("read from stdout %d bytes: [%s][%v]\n", n, ob[:n], ob[:n])
			writeToConsole(string(ob[:n]))
		}
	}()
	go func() {
		eb := make([]byte, 2048)
		for {
			n, err := e.Read(eb)
			if err != nil {
				fmt.Printf("error reading from stderr: %v]\n", err)
				return
			}
			fmt.Printf("read from stderr %d bytes: [%s]\n", n, eb[:n])
			writeToConsole(string(eb[:n]))
		}
	}()
}

func writeToConsole(str string) {
	js.Global().Get("term").Call("write", str)
	// fmt.Printf("writeToConsole: [%s] returned\n", str)
}

func con(host string, port int, bypassProxy bool) net.Conn {
	l := js.Global().Get("window").Get("location")
	wsProtocol := "wss://"
	if l.Get("protocol").String() == "http:" {
		wsProtocol = "ws://"
	}
	url := wsProtocol + l.Get("host").String() + "/p"
	if bypassProxy {
		url = wsProtocol + host + ":" + strconv.FormatInt(int64(port), 10)
	}

	conn, err := ws.Dial(url)
	if err != nil {
		log.Fatalf("failed to open ws: %v", err)
	}

	if !bypassProxy {
		var buf bytes.Buffer
		err = json.NewEncoder(&buf).Encode(struct {
			Host string
			Port int
		}{host, port})
		if err != nil {
			log.Fatalf("failed to encode connection request: %v", err)
		}
		conn.Write(buf.Bytes())
	}

	return conn
}

func runCmd(cmd string) (string, error) {
	s, err := sshClient.NewSession()
	if err != nil {
		return "", err
	}
	res, err := s.CombinedOutput(cmd)
	return string(res), err
}

var (
	logOn = true
)

func logf(fmt string, vals ...interface{}) {
	if !logOn {
		return
	}
	if len(vals) == 0 {
		log.Print(fmt)
	} else {
		log.Printf(fmt, vals...)
	}
}
