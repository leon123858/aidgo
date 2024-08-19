package aidgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type Contract struct {
	Action  int      `json:"action"`
	Code    string   `json:"code"`
	Address string   `json:"address"`
	Args    []string `json:"args"`
}

type UTXO struct {
	Txid    string  `json:"txid"`
	Vout    int     `json:"vout"`
	Amount  float64 `json:"amount"`
	Address string  `json:"address"`
}

type OurChainService struct {
	baseURL      string
	privateKey   string
	ownerAddress string
}

func NewBlockchainService(privateKey, ownerAddress, baseURL string) *OurChainService {
	return &OurChainService{
		baseURL:      baseURL,
		privateKey:   privateKey,
		ownerAddress: ownerAddress,
	}
}

func (s *OurChainService) SetBaseURL(baseURL string) {
	s.baseURL = baseURL
}

func (s *OurChainService) fetchJSON(url string, method string, body interface{}) (interface{}, error) {
	var req *http.Request
	var err error

	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(method, url, bytes.NewBuffer(jsonBody))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(resp.Body)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return nil, err
	}

	if result["result"] != "success" {
		return nil, fmt.Errorf("request failed: %v", result["message"])
	}

	return result["data"], nil
}

func (s *OurChainService) GetContractMessage(targetAddress string, args []string) (string, error) {
	if args == nil {
		args = []string{""}
	}

	body := map[string]interface{}{
		"address":   targetAddress,
		"arguments": args,
	}

	result, err := s.fetchJSON(s.baseURL+"get/contractmessage", "POST", body)
	if err != nil {
		return "", err
	}

	message, ok := result.(string)
	if !ok {
		return "", errors.New("invalid message in response")
	}

	return message, nil
}
