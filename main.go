package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mendersoftware/log"
	"github.com/mendersoftware/mender/client"
	"github.com/mendersoftware/mender/utils"
)

var (
	menderClientCount        int
	maxWaitSteps             int
	inventoryUpdateFrequency int
	pollFrequency            int
	backendHost              string
	inventoryItems           string
	updateFailMsg            string
)

type FakeMenderAuthManager struct {
	idSrc       []byte
	tenantToken client.AuthToken
	store       *utils.MemStore
	keyStore    *Keystore
	seqNum      SeqnumGetter
}

func init() {
	flag.IntVar(&menderClientCount, "count", 100, "amount of fake mender clients to spawn")
	flag.IntVar(&maxWaitSteps, "wait", 45, "max. amount of time to wait between update steps")
	flag.IntVar(&inventoryUpdateFrequency, "invfreq", 30, "amount of time to wait between inventory updates")
	flag.StringVar(&backendHost, "backend", "https://localhost:8080", "entire URI to the backend")
	flag.StringVar(&inventoryItems, "inventory", "device_type:test,image_id:test,client_version:test", "inventory key:value pairs distinguished with ','")
	flag.StringVar(&updateFailMsg, "fail", "", "fail update with specified message")
	flag.IntVar(&pollFrequency, "pollfreq", 5, "how often to poll the backend")

	mrand.Seed(time.Now().UnixNano())
}

func main() {
	if len(os.Args) == 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.Parse()

	for i := 0; i < menderClientCount; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, RsaKeyLength)
		go fakeclient(key)
	}

	// block forever
	select {}
}

func fakeclient(sharedPrivateKey *rsa.PrivateKey) {
	isAuthenticated := false

	buf := make([]byte, 6)
	rand.Read(buf)
	fakeMACaddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])

	identityData := map[string]string{"mac": fakeMACaddress}
	encdata, _ := json.Marshal(identityData)

	ms := utils.NewMemStore()
	kstore := NewKeystore(ms, "")

	kstore.private = sharedPrivateKey

	api, err := client.New(client.Config{
		IsHttps:  false,
		NoVerify: true,
	})

	if err != nil {
		log.Errorf("Error creating client: %s", err)
	}

	authReq := client.NewAuth()

	mgr := &FakeMenderAuthManager{
		store:       ms,
		keyStore:    kstore,
		idSrc:       encdata,
		tenantToken: client.AuthToken("dummy"),
		seqNum:      NewFileSeqnum("test", ms),
	}

	updater := client.NewUpdate()
	authTokenResp := make([]byte, 2048)

	for {
		if isAuthenticated == false {
			authTokenResp, _ = authReq.Request(api, backendHost, mgr)
			if len(authTokenResp) > 0 {
				isAuthenticated = true
			}
			time.Sleep(5 * time.Second)
			continue
		}

		go sendInventoryUpdate(api.Request(client.AuthToken(authTokenResp)), backendHost)
		haveUpdate, _ := updater.GetScheduledUpdate(api.Request(client.AuthToken(authTokenResp)), backendHost)

		if haveUpdate != nil {
			u := haveUpdate.(client.UpdateResponse)
			performFakeUpdate(u.Image.URI, u.ID, api.Request(client.AuthToken(authTokenResp)))
		}

		time.Sleep(time.Duration(pollFrequency) * time.Second)
	}
}

func performFakeUpdate(url string, did string, token client.ApiRequester) {
	s := client.NewStatus()
	reportingCycle := []string{"downloading", "installing", "rebooting"}

	if len(updateFailMsg) > 0 {
		reportingCycle = append(reportingCycle, "failure")
	} else {
		reportingCycle = append(reportingCycle, "success")
	}

	for _, event := range reportingCycle {
		if event == "downloading" {
			err := downloadToDevNull(url)
			if err != nil {
				log.Fatal("failed to download update: ", err)
				return
			}
		}

		if event == "failure" {
			logUploader := client.NewLog()

			ld := client.LogData{
				DeploymentID: did,
				Messages:     []byte(fmt.Sprintf("{\"messages\": [{\"level\": \"debug\", \"message\": \"%s\", \"timestamp\": \"2012-11-01T22:08:41+00:00\"}]}", updateFailMsg)),
			}

			if err := logUploader.Upload(token, backendHost, ld); err != nil {
				log.Errorf("failed to deliver fail logs to backend: " + err.Error())
				return
			}
		}

		report := client.StatusReport{DeploymentID: did, Status: event}
		err := s.Report(token, backendHost, report)

		if err != nil {
			log.Error("error reporting update status: ", err.Error())
		}
		time.Sleep(time.Duration(mrand.Intn(maxWaitSteps)) * time.Second)
	}
}

func sendInventoryUpdate(token client.ApiRequester, server string) {
	t := time.NewTicker(time.Second * time.Duration(inventoryUpdateFrequency))

	var invitems []client.InventoryAttribute
	for _, e := range strings.Split(inventoryItems, ",") {
		pair := strings.Split(e, ":")
		if pair != nil {
			key := pair[0]
			value := pair[1]
			i := client.InventoryAttribute{Name: key, Value: value}
			invitems = append(invitems, i)
		}
	}

	count := 0
	for {
		log.Info("submitting inventory update with: ", invitems)
		ic := client.NewInventory()
		ic.Submit(token, server, invitems)
		count++
		<-t.C
	}
}

func downloadToDevNull(url string) error {
	devnull, err := os.OpenFile("/dev/null", os.O_APPEND|os.O_WRONLY, os.ModeAppend)

	if err != nil {
		return err
	}

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(devnull, resp.Body)

	if err != nil {
		return err
	}
	return nil
}
