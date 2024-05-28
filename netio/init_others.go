//go:build 386 || amd64
// +build 386 amd64

package netio

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
)

var INIT_TYPE_ERROR = errors.New("init type error")

const TIMEOUT = 2

func loadTLSCertificate(certFile, keyFile string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Println("Error loading certificate:", err)
	}
	return cert
}

func InitNode(tcpType string, tcpService string, handlerFunc func(net.Conn), portReuse bool, reusedPort uint16) (err error) {
	//sni
	re1 := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+):`)
	match := re1.FindStringSubmatch(tcpService)
	var ipname = match[1]
	re2 := regexp.MustCompile(`^(192\.168|172\.(1[6-9]|2[0-9]|3[0-1])|10)\.`)
	//
	if tcpType == "connect" {
		/*
			f, err := os.OpenFile("keys.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				panic(err)
			}
			defer f.Close()
		*/
		//sni
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			NextProtos:         []string{"HTTP/2"},
			//KeyLogWriter:       f,
		}
		if re2.MatchString(match[1]) {
			tlsConfig.ServerName = ipname
		} else {
			domainname := iptodomain(ipname)
			if domainname == "no" {
				tlsConfig.ServerName = ipname
			} else {
				tlsConfig.ServerName = domainname
			}
		}

		conn, err := tls.Dial("tcp", tcpService, tlsConfig)
		if err != nil {
			log.Println("[-]ResolveTCPAddr error:", err)
			return err
		}

		go handlerFunc(conn)

		return nil
	} else if tcpType == "listen" {
		var err error
		var listener net.Listener

		tlsCfg := &tls.Config{
			Certificates:       []tls.Certificate{loadTLSCertificate("./ssl.crt", "./ssl.key")},
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			NextProtos:         []string{"HTTP/2"}, //not plain-text
		}

		listener, err = net.Listen("tcp", tcpService)

		if err != nil {
			log.Println("[-]ListenTCP error:", err)
			return err
		}

		//new
		tlsListener := tls.NewListener(listener, tlsCfg)
		//

		go func() {
			for {
				//conn, err := listener.Accept()
				conn, err := tlsListener.Accept()
				if err != nil {
					log.Println("[-]listener.Accept error:", err)
					// continue
					break
				}

				//if portReuse {
				//	appProtocol, data, timeout := isAppProtocol(conn)
				//	if appProtocol || (!appProtocol && timeout) {
				//		go func() {
				//			// port := strings.Split(tcpService, ":")[1]
				//			//addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", reusedPort))
				//			//if err != nil {
				//			//	log.Println("[-]ResolveTCPAddr error:", err)
				//			//	return
				//			//}
				//
				//			server, err := net.DialTCP("tcp", nil, addr)
				//			if err != nil {
				//				log.Println("[-]DialTCP error:", err)
				//				return
				//			}
				//
				//			Write(server, data)
				//			go NetCopy(conn, server)
				//			NetCopy(server, conn)
				//		}()
				//		continue
				//	}
				//}
				go handlerFunc(conn)
			}
		}()
	}
	return INIT_TYPE_ERROR
}
