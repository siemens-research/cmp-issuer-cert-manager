/*
Copyright 2026 Siemens AG.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	httpTimeout = 30 * time.Second
)

type TransportService interface {
	SendReceiveCMPMessage(request []byte) (response []byte, err error)
	Check() error
}

type CmpHttpClient struct {
	client    *http.Client
	serverURL string
}

func MakeCmpHttpClient(serverURL string, clientCert string, clientKey string,
	clientKeyPassphrase []byte, serverTrustroot string) (*CmpHttpClient, error) {
	if len(serverURL) == 0 {
		return nil, errors.New("no CMP upstream URL given")
	}
	log.Println("========== URL:", serverURL)
	if len(clientCert) == 0 {
		log.Println("No TLS client certificate provided, using default TLS configuration")
		return &CmpHttpClient{
			client: &http.Client{
				Timeout: httpTimeout,
			},
			serverURL: serverURL,
		}, nil
	}
	if len(clientKey) == 0 {
		return nil, errors.New("no TLS client key given")
	}
	if len(serverTrustroot) == 0 {
		return nil, errors.New("no TLS TrustAnchor given")
	}
	if debug {
		log.Println("========== len TLSClientCert:", len(clientCert))
		log.Println("========== len TLSClientKey:", len(clientKey))
		log.Println("========== len TLSTrusted: ", len(serverTrustroot))
	}
	decryptedKey, _, err := DecryptPrivKeyToPem(clientKey, clientKeyPassphrase)
	if err != nil {
		log.Println("Error decrypting TLS client key:", err.Error())
		return nil, err
	}
	tlscert, err := tls.X509KeyPair([]byte(clientCert), decryptedKey)
	if err != nil {
		log.Println("Error loading TLS client certificate and key:", err.Error())
		return nil, err
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM([]byte(serverTrustroot)); !ok {
		return nil, errors.New("failed to append TLS trust anchors to cert pool")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlscert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS12,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}
	return &CmpHttpClient{
		client:    client,
		serverURL: serverURL,
	}, nil
}

func (client *CmpHttpClient) Check() error {
	if client == nil || client.client == nil {
		return errors.New("HTTP client is not initialized")
	}
	_, err := client.client.Head(client.serverURL)
	client.client.CloseIdleConnections()
	return err
}

func (client *CmpHttpClient) SendReceiveCMPMessage(request []byte) (response []byte, err error) {

	respHTTP, err := client.client.Post(client.serverURL, "application/pkixcmp", bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("error during HTTP message transfer: %v", err)
	}
	defer respHTTP.Body.Close()

	if debug {
		log.Println("HTTP status code", respHTTP.Status)
		traceID := respHTTP.Header.Get("X-Trace-Id")
		if traceID != "" {
			log.Println("HTTP response X-Trace-Id:", traceID)
		}
		log.Println("HTTP response Content-Length:", respHTTP.ContentLength)
	}

	if respHTTP.StatusCode != 200 {
		log.Println("HTTP status code", respHTTP.Status)
		if respHTTP.StatusCode < 400 {
			return nil, errors.New("unsuitable HTTP response status code")
		}
		// continue because server may still provide CMP message
	}

	limitedBody := io.LimitReader(respHTTP.Body, 10*1024*1024) // 10MB limit
	response, err = io.ReadAll(limitedBody)

	if err != nil {
		return nil, fmt.Errorf("error reading HTTP response body: %v", err)
	}

	var ct string = respHTTP.Header.Get("Content-Type")
	if ct != "application/pkixcmp" {
		warn.Println("unexpected HTTP content type:", ct)
		if debug {
			log.Println("Body content:", string(response))
		}
		if strings.HasPrefix(ct, "text/html") {
			bodyStart := strings.Index(string(response), "<body>")
			bodyEnd := strings.Index(string(response), "</body>")
			if bodyStart != -1 && bodyEnd != -1 {
				text := string(response)[bodyStart+6 : bodyEnd]
				ct += " (body: " + text + ")"
			}
		}
		return nil, errors.New("HTTP response with status code '" + respHTTP.Status + "' does not contain CMP content, but " + ct)
	}
	return
}
