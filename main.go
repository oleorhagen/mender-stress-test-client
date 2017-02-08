package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
	currentArtifact          string
	currentDeviceType        string
	debugMode                bool
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
	flag.IntVar(&maxWaitSteps, "wait", 1800, "max. amount of time to wait between update steps: download image, install, reboot, success/failure")
	flag.IntVar(&inventoryUpdateFrequency, "invfreq", 600, "amount of time to wait between inventory updates")
	flag.StringVar(&backendHost, "backend", "https://localhost:8080", "entire URI to the backend")
	flag.StringVar(&inventoryItems, "inventory", "device_type:test,image_id:test,client_version:test", "inventory key:value pairs distinguished with ','")
	flag.StringVar(&updateFailMsg, "fail", "", "fail update with specified message")

	flag.StringVar(&currentArtifact, "current_artifact", "test", "current installed artifact")
	flag.StringVar(&currentDeviceType, "current_device", "test", "current device type")

	flag.IntVar(&pollFrequency, "pollfreq", 600, "how often to poll the backend")
	flag.BoolVar(&debugMode, "debug", true, "debug output")
	mrand.Seed(time.Now().UnixNano())
}

func main() {
	flag.Parse()

	if len(os.Args) == 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if debugMode {
		log.SetLevel(log.DebugLevel)
	}

	randSource := mrand.NewSource(time.Now().UnixNano())
	for i := 0; i < menderClientCount; i++ {

		// use faster random instead of crypto safe random for speed boot during testing
		key, err := rsa.GenerateKey(mrand.New(randSource), RsaKeyLength)

		if err != nil {
			log.Fatal(err)
		}

		go clientScheduler(key)
	}

	// block forever
	select {}
}

func clientScheduler(sharedPrivateKey *rsa.PrivateKey) {
	clientUpdateTicker := time.NewTicker(time.Second * time.Duration(pollFrequency))
	clientInventoryTicker := time.NewTicker(time.Second * time.Duration(inventoryUpdateFrequency))

	api, err := client.New(client.Config{
		IsHttps:  true,
		NoVerify: true,
	})

	if err != nil {
		log.Fatal(err)
	}

	token := clientAuthenticate(api, sharedPrivateKey)

	for {
		select {
		case <-clientInventoryTicker.C:
			invItems := parseInventoryItems()
			sendInventoryUpdate(api, token, &invItems)

		case <-clientUpdateTicker.C:
			checkForNewUpdate(api, token)
		}
	}
}

func clientAuthenticate(c *client.ApiClient, sharedPrivateKey *rsa.PrivateKey) client.AuthToken {
	buf := make([]byte, 6)
	rand.Read(buf)
	fakeMACaddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
	log.Debug("created device with fake mac address: ", fakeMACaddress)

	identityData := map[string]string{"mac": fakeMACaddress}
	encdata, _ := json.Marshal(identityData)

	ms := utils.NewMemStore()
	kstore := NewKeystore(ms, "")

	// use a single share private key due to high CPU usage bottleneck in go routines
	kstore.private = sharedPrivateKey
	authReq := client.NewAuth()

	mgr := &FakeMenderAuthManager{
		store:       ms,
		keyStore:    kstore,
		idSrc:       encdata,
		tenantToken: client.AuthToken("dummy"),
		seqNum:      NewFileSeqnum("test", ms),
	}

	for {
		if authTokenResp, err := authReq.Request(c, backendHost, mgr); err == nil && len(authTokenResp) > 0 {
			return client.AuthToken(authTokenResp)
		} else if err != nil {
			log.Debug("not able to authorize client: ", err)
		}

		time.Sleep(time.Duration(pollFrequency) * time.Second)
	}
}

func checkForNewUpdate(c *client.ApiClient, token client.AuthToken) {
	updater := client.NewUpdate()

	haveUpdate, err := updater.GetScheduledUpdate(c.Request(client.AuthToken(token)), backendHost, client.CurrentUpdate{DeviceType: currentDeviceType, Artifact: currentArtifact})

	if err != nil {
		log.Info("failed when checking for new updates with: ", err.Error())
	}

	if haveUpdate != nil {
		u := haveUpdate.(client.UpdateResponse)
		performFakeUpdate(u.Artifact.Source.URI, u.ID, c.Request(client.AuthToken(token)))
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
		time.Sleep(15 + time.Duration(mrand.Intn(maxWaitSteps))*time.Second)
		if event == "downloading" {
			if err := downloadToDevNull(url); err != nil {
				log.Warn("failed to download update: ", err)
			}
		}

		if event == "failure" {
			logUploader := client.NewLog()

			ld := client.LogData{
				DeploymentID: did,
				Messages:     []byte(fmt.Sprintf("{\"messages\": [{\"level\": \"debug\", \"message\": \"%s\", \"timestamp\": \"2012-11-01T22:08:41+00:00\"}]}", updateFailMsg)),
			}

			if err := logUploader.Upload(token, backendHost, ld); err != nil {
				log.Warn("failed to deliver fail logs to backend: " + err.Error())
				return
			}
		}

		report := client.StatusReport{DeploymentID: did, Status: event}
		err := s.Report(token, backendHost, report)

		if err != nil {
			log.Warn("error reporting update status: ", err.Error())
		}
	}
}

func sendInventoryUpdate(c *client.ApiClient, token client.AuthToken, invAttrs *[]client.InventoryAttribute) {
	log.Debug("submitting inventory update with: ", invAttrs)
	if err := client.NewInventory().Submit(c.Request(client.AuthToken(token)), backendHost, invAttrs); err != nil {
		log.Warn("failed sending inventory with: ", err.Error())
	}
}

func downloadToDevNull(url string) error {
	log.Info("downloading url")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
	if err != nil {
		log.Error("failed grabbing update: ", url)
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(ioutil.Discard, resp.Body)

	if err != nil {
		return err
	}
	log.Debug("downloaded update successfully to /dev/null")
	return nil
}

func parseInventoryItems() []client.InventoryAttribute {
	var invAttrs []client.InventoryAttribute
	for _, e := range strings.Split(inventoryItems, ",") {
		pair := strings.Split(e, ":")
		if pair != nil {
			key := pair[0]
			value := pair[1]
			i := client.InventoryAttribute{Name: key, Value: value}
			invAttrs = append(invAttrs, i)
		}
	}
	return invAttrs
}
