package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/nats-io/nats.go"
	log "github.com/sirupsen/logrus"
)

const (
	SLICE_SIZE = 20
	getBlockTxsEndpoint = "/blocks/"
	oracleAddress       = "4FC5xSYb7zfRdUhm6oRmE11P2GJqSMY8UARPbHkmXEq6hTinXq4XNWdJs73BEV44MdmJ49Qo"
	oracleTxs           = "https://api.ergoplatform.com/api/v1/addresses/4FC5xSYb7zfRdUhm6oRmE11P2GJqSMY8UARPbHkmXEq6hTinXq4XNWdJs73BEV44MdmJ49Qo/transactions"
  ergUtxoEndpoint     = "https://node.nightowlcasino.io/utxo/byId/"
	rouletteErgoTree    = "1012040004000404054a0e203eff84aa4780a9cc612ed429b28c0cb2d17d5d6372a84c4050e68d234743042b0e20afd0d6cb61e86d15f2a0adc1e7e23df532ba3ff35f8ba88bed16729cae9330320400040205040404050f05120406050604080509050c040ad807d601b2a5730000d602b2db63087201730100d603e4c6a70404d6049e7cdb6801b2db6502fe9999a38cc7a7017302007303d6057ee4c6a7050405d6069972057204d607cb7304d1ed96830201938c7202017305938c7202028cb2db6308a7730600029597830501ed9372037307939e720473087205eded9372037309927206730a907206730bed937203730c939e7204730d7205eded937203730e927206730f9072067310ed9372037311937205720493c27201720793c272017207"
	minerFee            = 1500000 // 0.0015 ERG
)

type ErgBoxIds struct {
	Items []ErgTx `json:"items"`
}

type ErgTx struct {
  Id      string        `json:"id"`
  Outputs []ErgTxOutput `json:"outputs"`
}

type ErgTxOutput struct {
  BoxId               string    `json:"boxId"`
	AdditionalRegisters Registers `json:"additionalRegisters"`
}

type ErgTxOutputNode struct {
	BoxId               string        `json:"boxId"`
	Assets              []Tokens      `json:"assets"`
	AdditionalRegisters RegistersNode `json:"additionalRegisters"`
	ErgoTree            string        `json:"ergoTree"`
}

type Tokens struct {
	TokenId string `json:"tokenId"`
	Amount  int    `json:"amount"`
}

type serialized struct {
	BoxId string `json:"boxId"`
	Bytes string `json:"bytes"`
}

type Registers struct {
	R4 RegR4 `json:"R4"`
	R5 RegR5 `json:"R5"`
}

type RegistersNode struct {
	R4 string `json:"R4"`
	R5 string `json:"R5"`
	R6 string `json:"R6"`
}

type RegR4 struct {
	Value string `json:"renderedValue"`
}

type RegR5 struct {
	Value string `json:"renderedValue"`
}

type CombinedHashes struct {
  Hash  string   `json:"hash"`
  Boxes []string `json:"boxes"`
}

type ergBlockRandNum struct {
  mu sync.Mutex
  randNums map[string]string
}
var allErgBlockRandNums ergBlockRandNum

func (e *ergBlockRandNum) get(key string) (string, bool) {
	e.mu.Lock()
  defer e.mu.Unlock()
	val, ok := e.randNums[key]
	return val, ok
}

func (e *ergBlockRandNum) delete(key string) {
  e.mu.Lock()
  defer e.mu.Unlock()
  delete(e.randNums, key);
}

var combinedHashes = make([]CombinedHashes, SLICE_SIZE)
var nodeUser string
var nodePassword string
var ergNodeApiKey string
var walletPassword string
var index int
var nc *nats.Conn
var hostname string
var port string
var natsEndpoint string
var logger *log.Entry

func unlockWallet(client *retryablehttp.Client) ([]byte, error) {
  var ret []byte

  req, err := retryablehttp.NewRequest("POST", "https://node.nightowlcasino.io/wallet/unlock", bytes.NewBuffer([]byte(fmt.Sprintf("{\"pass\": \"%s\"}", walletPassword))))
  if err != nil {
    return ret, fmt.Errorf("error creating erg node lock wallet request - %s", err.Error())
  }
  req.SetBasicAuth(nodeUser, nodePassword)
  req.Header.Set("api_key", ergNodeApiKey)
  req.Header.Set("no-scanner-func", "lockWallet")
  req.Header.Set("Content-Type", "application/json")

  resp, err := client.Do(req)
  if err != nil {
    return ret, fmt.Errorf("error locking erg node wallet - %s", err.Error())
  }

  ret, err = ioutil.ReadAll(resp.Body)
  if err != nil {
    return ret, fmt.Errorf("error parsing erg node lock response - %s", err.Error())
  }

  return ret, nil
}

func lockWallet(client *retryablehttp.Client) ([]byte, error) {
  var ret []byte

  req, err := retryablehttp.NewRequest("GET", "https://node.nightowlcasino.io/wallet/lock", nil)
  if err != nil {
    return ret, fmt.Errorf("error creating erg node lock wallet request - %s", err.Error())
  }
  req.SetBasicAuth(nodeUser, nodePassword)
  req.Header.Set("api_key", ergNodeApiKey)
  req.Header.Set("no-scanner-func", "lockWallet")
  req.Header.Set("Content-Type", "application/json")

  resp, err := client.Do(req)
  if err != nil {
    return ret, fmt.Errorf("error locking erg node wallet - %s", err.Error())
  }

  ret, err = ioutil.ReadAll(resp.Body)
  if err != nil {
    return ret, fmt.Errorf("error parsing erg node lock response - %s", err.Error())
  }

  return ret, nil
}

func postErgOracleTx(client *retryablehttp.Client, payload []byte) ([]byte, error) {
  var ret []byte

  _, err := unlockWallet(client)
  if err != nil {
    return ret, err
  }

  defer lockWallet(client)

  req, err := retryablehttp.NewRequest("POST", "https://node.nightowlcasino.io/wallet/transaction/send", bytes.NewBuffer(payload))
  if err != nil {
    return ret, fmt.Errorf("error creating postErgOracleTx request - %s", err.Error())
  }
  req.SetBasicAuth(nodeUser, nodePassword)
  req.Header.Set("api_key", ergNodeApiKey)
  req.Header.Set("no-scanner-func", "postErgOracleTx")
  req.Header.Set("Content-Type", "application/json")

  resp, err := client.Do(req)
  if err != nil {
    return ret, fmt.Errorf("error submitting erg tx to node - %s", err.Error())
  }

  ret, err = ioutil.ReadAll(resp.Body)
  if err != nil {
    return ret, fmt.Errorf("error parsing erg tx response - %s", err.Error())
  }

  return ret, nil
}

func sendRandNum(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	boxId := req.URL.Query().Get("boxId")
	walletAddr := req.URL.Query().Get("walletAddr")
	game := mux.Vars(req)["game"]
  reqURL := req.URL
  urlPath := reqURL.Path
  logger.WithFields(log.Fields{"caller": "sendRandNum", "urlPath": urlPath, "boxId": boxId, "game": game, "walletAddr": walletAddr}).Info("sendRandNum called")

	go func(game string, boxId string, walletAddr string) {
		timeout := time.NewTicker(60 * time.Second)
		for {
			select {
			case <-timeout.C:
        logger.WithFields(log.Fields{"caller": "sendRandNum", "durationMs": time.Since(start).Milliseconds(), "boxId": boxId, "game": game, "walletAddr": walletAddr}).Error("timeout - random number not found")
				return
			default:
				if randNum, ok := allErgBlockRandNums.get(boxId); ok {
					topic := fmt.Sprintf("%s.%s", game, walletAddr)
					nc.Publish(topic, []byte(randNum))
          logger.WithFields(log.Fields{"caller": "sendRandNum", "durationMs": time.Since(start).Milliseconds(), "randNum": randNum, "boxId": boxId, "game": game, "walletAddr": walletAddr}).Info("successfully sent random number")
					return
				}
				time.Sleep(5 * time.Second)
			}
		}
	}(game, boxId, walletAddr)
  
  w.WriteHeader(http.StatusOK)
  fmt.Fprintf(w, "")
  return
}

func serializeErgBox(client *retryablehttp.Client, boxId string) (string, error) {
	var bytes serialized

	req, err := retryablehttp.NewRequest("GET", "https://node.nightowlcasino.io/utxo/withPool/byIdBinary/" + boxId, nil)
	if err != nil {
		return bytes.Bytes, fmt.Errorf("error creating getErgBoxes request - %s", err.Error())
	}
  req.SetBasicAuth(nodeUser, nodePassword)
  req.Header.Set("no-scanner-func", "serializeErgBox")

  resp, err := client.Do(req)
  if err != nil {
  	return bytes.Bytes, fmt.Errorf("error getting serializing erg box - %s", err.Error())
  }

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
  	return bytes.Bytes, fmt.Errorf("error parsing serialized erg box response - %s", err.Error())
  }

  err = json.Unmarshal(body, &bytes)
  if err != nil {
  	return bytes.Bytes, fmt.Errorf("error unmarshalling serialized erg box response - %s", err.Error())
  }

  return bytes.Bytes, nil
}

func getErgUtxoBox(client *retryablehttp.Client, boxId string) (ErgTxOutputNode, error) {
	var utxo ErgTxOutputNode

	req, err := retryablehttp.NewRequest("GET", "https://node.nightowlcasino.io/utxo/byId/" + boxId, nil)
	if err != nil {
		return utxo, fmt.Errorf("error creating getErgBoxes request - %s", err.Error())
	}
  req.SetBasicAuth(nodeUser, nodePassword)
  req.Header.Set("no-scanner-func", "getErgUtxoBox")

  resp, err := client.Do(req)
  if err != nil {
  	return utxo, fmt.Errorf("error getting erg utxo box - %s", err.Error())
  }

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
  	return utxo, fmt.Errorf("error parsing erg utxo box response - %s", err.Error())
  }

  err = json.Unmarshal(body, &utxo)
  if err != nil {
  	return utxo, fmt.Errorf("error unmarshalling erg utxo box response - %s", err.Error())
  }

  return utxo, nil
}

func buildResultSmartContractTx(betUtxo ErgTxOutputNode, r4, r5 uint64, betDataInput, oracleDataInput string) ([]byte, error) {
	// Build Erg Tx for node to sign
	assets := fmt.Sprintf(`{"tokenId": "%s", "amount": %d}`, betUtxo.Assets[0].TokenId, betUtxo.Assets[0].Amount)
	txToSign := []byte(fmt.Sprintf(`{
		"requests": [
			{
				"address": "%s",
				"value": %d,
				"assets": %s,
				"registers": {
					"R4": "04%02x",
					"R5": "04%02x"
				}
			}
		],
		"fee": %d,
		"inputsRaw": [
			"%s"
		],
		"dataInputsRaw": [
			"%s"
		]
	}`, betUtxo.AdditionalRegisters.R6, minerFee, assets, r4, r5, minerFee, betDataInput, oracleDataInput))

	return txToSign, nil
}

func encodeZigZag64(n uint64) uint64 {
	return (n << 1) ^ (n >> 63)
}

func main() {

  log.SetFormatter(&log.JSONFormatter{})
  log.SetLevel(log.InfoLevel)

  if value, ok := os.LookupEnv("HOSTNAME"); ok {
    hostname = value
  } else {
    var err error
    hostname, err = os.Hostname()
    if err != nil {
      log.Fatal("unable to get hostname")
    }
  }

	if value, ok := os.LookupEnv("PORT"); ok {
    port = value
  } else {
    port = "8089"
  }

	if value, ok := os.LookupEnv("NATS_ENDPOINT"); ok {
    natsEndpoint = value
  } else {
    natsEndpoint = nats.DefaultURL
  }

  logger = log.WithFields(log.Fields{
    "hostname": hostname,
    "appname":  "no-rng-svc",
  })

  // Connect to the nats server
	var err error
  nc, err = nats.Connect(natsEndpoint)
  if err != nil {
    logger.WithFields(log.Fields{"error": err.Error()}).Fatal("failed to connect to ':4222' nats server")
  }

	allErgBlockRandNums.randNums = make(map[string]string)
	index = 0
  
  nc.Subscribe("eth.hash", func(m *nats.Msg) {
		var hash CombinedHashes
    err = json.Unmarshal(m.Data, &hash)
    if err != nil {
      logger.WithFields(log.Fields{"error": err.Error()}).Error("failed to unmarshal CombinedHashes")
    } else {
			combinedHashes[index % SLICE_SIZE] = hash
			// the ERG BoxId random numbers are stored in a hash map and will be set to the 2nd ETH hash block Id
			// from the initially associated one
			if index >= 2 {
				h := combinedHashes[(index-2) % SLICE_SIZE]
				for _, boxId := range h.Boxes {
          allErgBlockRandNums.randNums[boxId] = hash.Hash[2:10]
				}
			}

      // when the slice size has reached 20 we will begin to remove old ERG BoxIds from the hash map
			if index >= 19 {
        old := combinedHashes[(index+1) % SLICE_SIZE]
        for _, boxId := range old.Boxes {
          allErgBlockRandNums.delete(boxId)
        }
      }

      index++
		}
  })
  logger.Info("subscribed to eth.hash")

  var ergTxs ErgBoxIds
	var ergUtxo ErgTxOutputNode

	t := &http.Transport{
    Dial: (&net.Dialer{
      Timeout: 3 * time.Second,
    }).Dial,
    MaxIdleConns:        100,
    MaxConnsPerHost:     100,
    MaxIdleConnsPerHost: 100,
    TLSHandshakeTimeout: 3 * time.Second,
  }

	retryClient := retryablehttp.NewClient()
  retryClient.HTTPClient.Transport = t
  retryClient.HTTPClient.Timeout = time.Second * 3
  retryClient.Logger = nil
  retryClient.RetryWaitMin = 100 * time.Millisecond
  retryClient.RetryWaitMax = 150 * time.Millisecond
  retryClient.RetryMax = 2
  retryClient.RequestLogHook = func(l retryablehttp.Logger, r *http.Request, i int) {
    retryCount := i
    if retryCount > 0 {
      fmt.Println("failed to get oracle txs, retrying")
    }
  }

  // https://api.ergoplatform.com/api/v1/addresses/xxxx/transactions
	txsReq, err := retryablehttp.NewRequest("GET", oracleTxs, nil)
  if err != nil {
    fmt.Println("failed to get oracle transactions")
  }

  resp, err := retryClient.Do(txsReq)
  if err != nil {
		fmt.Printf("error calling ergo api explorer - %s\n", err.Error())
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    fmt.Printf("error reading erg txs body - %s\n", err.Error())
  }

  err = json.Unmarshal(body, &ergTxs)
  if err != nil {
    fmt.Printf("error unmarshalling erg txs - %s\n", err.Error())
  }

	for _, ergTx := range ergTxs.Items {

		// convert R4 rendered value to []string
		r4 := ergTx.Outputs[0].AdditionalRegisters.R4.Value
		// remove surrounding brackets [ and ]
	  r4 = strings.TrimPrefix(r4, "[")
	  r4 = strings.TrimSuffix(r4, "]")
		//ethHashIds := strings.Split(r4, ",")

		// convert R5 rendered value to [][]string
		r5 := ergTx.Outputs[0].AdditionalRegisters.R5.Value
	  // remove surrounding brackets [ and ]
	  r5 = strings.TrimPrefix(r5, "[")
	  r5 = strings.TrimSuffix(r5, "]")
	  // add , to the back of string to help for the split
		r5 = r5 + ","
		ergBoxIdsSlices := strings.Split(r5, "],")
		// remove last element because it's empty
		ergBoxIdsSlices = ergBoxIdsSlices[:len(ergBoxIdsSlices)-1]

	  for i, ergBoxIdsSlice := range ergBoxIdsSlices {
			// remove leading [
			ergBoxIdsClean := strings.TrimPrefix(ergBoxIdsSlice, "[")
	  	ergBoxIds := strings.Split(ergBoxIdsClean, ",")

			if len(ergBoxIds) > 0 && ergBoxIds[0] != "" {
				for j, boxId := range ergBoxIds {
					start := time.Now()
					utxoReq, err := retryablehttp.NewRequest("GET", ergUtxoEndpoint + boxId, nil)
					if err != nil {
						fmt.Println("failed to get roulette bet utxos")
					}
          utxoReq.SetBasicAuth(nodeUser, nodePassword)

					resp, err = retryClient.Do(utxoReq)
					if err != nil {
						fmt.Printf("error calling ergo node - %s\n", err.Error())
					}
					defer resp.Body.Close()

					body, err = ioutil.ReadAll(resp.Body)
					if err != nil {
						fmt.Printf("error reading erg utxo body - %s\n", err.Error())
					}

					err = json.Unmarshal(body, &ergUtxo)
					if err != nil {
						fmt.Printf("error unmarshalling erg utxo - %s\n", err.Error())
					}

					//fmt.Printf("r4: %s\nr5: %s\nr6: %s\n", ergUtxo.AdditionalRegisters.R4, ergUtxo.AdditionalRegisters.R5, ergUtxo.AdditionalRegisters.R6)
					serializedOracleBox, _ := serializeErgBox(retryClient, ergTx.Outputs[0].BoxId)
					serializedBetBox, _ := serializeErgBox(retryClient, ergUtxo.BoxId)
					txUnsigned, _ := buildResultSmartContractTx(ergUtxo, encodeZigZag64(uint64(i)), encodeZigZag64(uint64(j)), serializedBetBox, serializedOracleBox)
					txSigned, err := postErgOracleTx(retryClient, txUnsigned)
					logger.WithFields(log.Fields{"caller": "postErgOracleTx", "durationMs": time.Since(start).Milliseconds(), "txId": string(txSigned)}).Info("successfully sent tx to result smart contract")
				}
			}
	  }
	}

  r := mux.NewRouter()
	r.HandleFunc("/random-number/{game}", sendRandNum).Methods("GET")
  http.Handle("/", r)
  logger.Infof("serving on port %s", port)
  http.ListenAndServe(":"+port, r)

  nc.Drain()
  os.Exit(0)
}