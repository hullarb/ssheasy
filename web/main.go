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
	session   *ssh.Session
)

var fpAccepted chan bool

func main() {

	var onData js.Value

	init := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go func() {
			if !onData.Equal(js.Undefined()) {
				log.Print("calling dispose")
				onData.Call("dispose")
			}
			if len(args) < 7 {
				log.Println("not enough argument to call init")
				return
			}
			host, port := args[2].String(), args[3].Int()
			usr, pass, key, bypassProxy, bypassFingerprint, useWebauthKey := args[4].String(), args[5].String(), args[6].String(), args[7].Bool(), args[8].Bool(), args[9].Bool()
			var err error
			sshCon, err = con(host, port, bypassProxy)
			if err != nil {
				js.Global().Call("showErr", fmt.Sprintf("cannot connect to host: %v", err))
				return
			}
			fpAccepted = make(chan bool)

			if pass == "" && key == "" && !useWebauthKey {
				js.Global().Call("showErr", "provide a password or a privatre key or use webauthn key")
			}
			var auth []ssh.AuthMethod
			if key != "" {
				signer, err := ssh.ParsePrivateKey([]byte(key))
				if err != nil {
					if _, ok := err.(*ssh.PassphraseMissingError); ok && pass != "" {
						signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(pass))
						if err != nil {
							js.Global().Call("showErr", fmt.Sprintf("failed to parse private key: %v", err))
							return
						}
						pass = ""
					} else {
						if err != nil {
							js.Global().Call("showErr", fmt.Sprintf("failed to parse private key: %v", err))
							return
						}
					}
				}
				auth = append(auth, ssh.PublicKeys(signer))
			}

			if pass != "" {
				auth = append(auth, ssh.Password(pass))
			}

			if useWebauthKey {
				key := js.Global().Call("getSelectedWebauthnKey")
				x := key.Get("x").String()
				y := key.Get("y").String()
				hostName := key.Get("hostName").String()
				auth = []ssh.AuthMethod{ssh.PublicKeys(&webauthnSigner{sshPublicKey(x, y, hostName)})}
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
				js.Global().Call("showErr", fmt.Sprintf("failed to open ssh conn %v", err))
				log.Println("closing")
				sshCon.Close()
				return
			}

			sshClient = ssh.NewClient(cc, nc, r)

			session, err = sshClient.NewSession()
			if err != nil {
				js.Global().Call("showErr", fmt.Sprintf("failed to create new ssh session %v", err))
				sshCon.Close()
				return
			}

			so, err := session.StdoutPipe()
			if err != nil {
				js.Global().Call("showErr", fmt.Sprintf("failed to open stdout: %v", err))
				sshCon.Close()
				return
			}
			se, err := session.StderrPipe()
			if err != nil {
				js.Global().Call("showErr", fmt.Sprintf("failed to open stderr: %v", err))
				sshCon.Close()
				return
			}
			forwardOutStreams(so, se, sshCon)
			inp, err := session.StdinPipe()
			if err != nil {
				js.Global().Call("showErr", fmt.Sprintf("failed to open stdin: %v", err))
				sshCon.Close()
				return
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
			if err := session.RequestPty("xterm", rows, cols, modes); err != nil {
				js.Global().Call("showErr", fmt.Sprintf("failed to request a pseudo terminal: %s", err))
				sshCon.Close()
				return
			}

			// Start remote shell
			if err := session.Shell(); err != nil {
				js.Global().Call("showErr", fmt.Sprintf("failed to start ssh shell: %s", err))
				sshCon.Close()
				return
			}

			kcb := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				if len(args) < 1 {
					fmt.Println("onData received empty args")
					return nil
				}
				if _, err := inp.Write([]byte(args[0].String())); err != nil {
					js.Global().Call("showReconnect", err.Error())
					fmt.Printf("error writing to stdin: %v]\n", err)
					return fmt.Errorf("error writing to stdin: %v]\n", err)
				}
				return nil
			})
			onData = js.Global().Get("term").Call("onData", kcb)
			initSftp(sshClient)
			h := getwd()
			js.Global().Set("home", h)
			js.Global().Call("connected", fmt.Sprintf("Connected to %s@%s", usr, host), h)
		}()
		return nil
	})

	wc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if session == nil {
			return nil
		}
		rows, cols := args[0].Int(), args[1].Int()
		if err := session.WindowChange(rows, cols); err != nil {
			fmt.Printf("error requesting window size change: %v\n", err)
		}
		fmt.Println("session window size changed")
		return nil
	})

	js.Global().Set("initConnection", init)
	js.Global().Set("acceptFingerprint", js.FuncOf(acceptFP))
	js.Global().Set("changeWindowSize", wc)
	initFileBrowserAPI()
	js.Global().Set("parsePublicKey", parsePublicKey)

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

func forwardOutStreams(o, e io.Reader, con net.Conn) {
	go func() {
		ob := make([]byte, 2048)
		for {
			n, err := o.Read(ob)
			if err != nil {
				js.Global().Call("showReconnect", err.Error())
				fmt.Printf("error reading from stdout: %v]\n", err)
				con.Close()
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
				js.Global().Call("showReconnect", err.Error())
				fmt.Printf("error reading from stderr: %v]\n", err)
				con.Close()
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

func con(host string, port int, bypassProxy bool) (net.Conn, error) {
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
		return nil, fmt.Errorf("failed to open ws: %v", err)
	}

	if bypassProxy {
		return conn, nil
	}

	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(struct {
		Host string
		Port int
	}{host, port})
	if err != nil {
		return nil, fmt.Errorf("failed to encode connection request: %v", err)
	}
	conn.Write(buf.Bytes())
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read connection request response: %v %v", err, resp)
	}
	log.Printf("received con request response: %v", resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read connection request response: %v", err)
	}
	if resp.Status != "ok" {
		return nil, errors.New(resp.Error)
	}

	return conn, nil
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
