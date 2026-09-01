package main

import (
	"bytes"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/curve25519"
)

type RegisterRequest struct {
	Key         string `json:"key"`
	InstallID   string `json:"install_id"`
	WarpEnabled bool   `json:"warp_enabled"`
	FCMToken    string `json:"fcm_token"`
	TOS         string `json:"tos"`
	Locale      string `json:"locale"`
	Model       string `json:"model"`
	Type        string `json:"type"`
}

type RegisterResponse struct {
	ID      string `json:"id"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

const (
	ApiURL = "https://api.cloudflareclient.com/v0a737/reg"
)

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles("html/home.html"))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if err := tmpl.ExecuteTemplate(w, "home", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/get-conf", func(w http.ResponseWriter, r *http.Request) {
		privateKey := newPrivateKey()
		pubKey := derivePubKey(privateKey)
		pubKeyBase64 := b64.StdEncoding.EncodeToString(pubKey)

		res, err := registerWarp(pubKeyBase64)
		if err != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<pre>Error: %s</pre>", err.Error())
			return
		}

		config := buildWireGuardConfig(privateKey, res)

		w.Header().Set("Content-Type", "text/html")

		fmt.Fprintf(w, `<textarea id="config-text" readonly>%s</textarea><br><br><button onclick="copyConfig()">Copy</button>`, config)
	})

	fmt.Println("Running at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func newPrivateKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	return key
}

func derivePubKey(privateKey []byte) []byte {
	pub, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pub
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func currentTOS() string {
	t := time.Now()
	formattedTime := t.Format(time.RFC3339)

	return formattedTime
}

func registerWarp(pubKeyBase64 string) (*RegisterResponse, error) {
	reg := RegisterRequest{
		Key:         pubKeyBase64,
		InstallID:   "",
		WarpEnabled: true,
		FCMToken:    "",
		TOS:         currentTOS(),
		Locale:      "en_US",
		Model:       "PC",
		Type:        "Linux",
	}

	jsonData, err := json.Marshal(reg)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", ApiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	var result RegisterResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func buildWireGuardConfig(privateKey []byte, res *RegisterResponse) string {
	encodePrivateKey := b64.StdEncoding.EncodeToString(privateKey)

	config := fmt.Sprintf(`
[Interface]
PrivateKey = %s
Address = %s, %s
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s
PersistentKeepalive = 25
`,
		encodePrivateKey,
		res.Config.Interface.Addresses.V4,
		res.Config.Interface.Addresses.V6,
		res.Config.Peers[0].PublicKey,
		res.Config.Peers[0].Endpoint.Host,
	)

	return config
}
