package aidgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
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

func (s *OurChainService) fetchJSON(url string, method string, body interface{}) (map[string]interface{}, error) {
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

	return result["data"].(map[string]interface{}), nil
}

func (s *OurChainService) GetUtxoList(fee float64, targetAddress string, amount float64) (map[string]interface{}, error) {
	url := fmt.Sprintf("%sget/utxo?address=%s", s.baseURL, s.ownerAddress)
	data, err := s.fetchJSON(url, "GET", nil)
	if err != nil {
		return nil, err
	}

	utxoList, ok := data["utxoList"].([]interface{})
	if !ok {
		return nil, errors.New("invalid UTXO list format")
	}

	// Shuffle the UTXO list
	rand.Shuffle(len(utxoList), func(i, j int) {
		utxoList[i], utxoList[j] = utxoList[j], utxoList[i]
	})

	totalAmount := amount + fee
	inputList := []map[string]interface{}{}
	for _, utxo := range utxoList {
		utxoMap, ok := utxo.(map[string]interface{})
		if !ok {
			continue
		}
		inputList = append(inputList, utxoMap)
		utxoAmount, ok := utxoMap["amount"].(float64)
		if !ok {
			continue
		}
		totalAmount -= utxoAmount
		if totalAmount <= 0 {
			break
		}
	}

	if totalAmount > 0 {
		return nil, errors.New("error: not enough money")
	}

	outputList := []map[string]interface{}{}
	currentAmount := 0.0
	for _, input := range inputList {
		currentAmount += input["amount"].(float64)
	}
	charge := currentAmount - amount - fee
	if charge > 0 {
		outputList = append(outputList, map[string]interface{}{
			"address": s.ownerAddress,
			"amount":  charge,
		})
	}
	outputList = append(outputList, map[string]interface{}{
		"address": targetAddress,
		"amount":  amount,
	})

	return map[string]interface{}{
		"inputs":  inputList,
		"outputs": outputList,
	}, nil
}

func (s *OurChainService) GetUtxo(fee float64, targetAddress string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%sget/utxo?address=%s", s.baseURL, s.ownerAddress)
	data, err := s.fetchJSON(url, "GET", nil)
	if err != nil {
		return nil, err
	}

	utxoList, ok := data["utxoList"].([]interface{})
	if !ok {
		return nil, errors.New("invalid UTXO list format")
	}

	// Shuffle the UTXO list
	rand.Shuffle(len(utxoList), func(i, j int) {
		utxoList[i], utxoList[j] = utxoList[j], utxoList[i]
	})

	for _, utxo := range utxoList {
		utxoMap, ok := utxo.(map[string]interface{})
		if !ok {
			continue
		}
		amount, ok := utxoMap["amount"].(float64)
		if !ok || amount <= fee {
			continue
		}

		return map[string]interface{}{
			"input": map[string]interface{}{
				"txid": utxoMap["txid"],
				"vout": utxoMap["vout"],
			},
			"output": map[string]interface{}{
				"address": targetAddress,
				"amount":  amount - fee,
			},
		}, nil
	}

	return nil, errors.New("error: no utxo available")
}

func (s *OurChainService) CreateTx(fee float64, targetAddress string, contract Contract) (map[string]interface{}, error) {
	utxo, err := s.GetUtxo(fee, targetAddress)
	if err != nil {
		return nil, err
	}

	body := map[string]interface{}{
		"inputs":   []interface{}{utxo["input"]},
		"outputs":  []interface{}{utxo["output"]},
		"contract": contract,
	}

	return s.fetchJSON(s.baseURL+"rawtransaction/create", "POST", body)
}

func (s *OurChainService) SignContract(rawTx string) (string, error) {
	body := map[string]interface{}{
		"rawTransaction": rawTx,
		"privateKey":     s.privateKey,
	}

	result, err := s.fetchJSON(s.baseURL+"rawtransaction/sign", "POST", body)
	if err != nil {
		return "", err
	}

	complete, ok := result["complete"].(bool)
	if !ok || !complete {
		return "", errors.New("signing incomplete")
	}

	hex, ok := result["hex"].(string)
	if !ok {
		return "", errors.New("invalid hex in response")
	}

	return hex, nil
}

func (s *OurChainService) SendTx(signedTx string) (string, error) {
	body := map[string]interface{}{
		"rawTransaction": signedTx,
	}

	result, err := s.fetchJSON(s.baseURL+"rawtransaction/send", "POST", body)
	if err != nil {
		return "", err
	}

	txid, ok := result["txid"].(string)
	if !ok {
		return "", errors.New("invalid txid in response")
	}

	return txid, nil
}

func (s *OurChainService) SendMoney(fee float64, targetAddress string, amount float64) (string, error) {
	utxoList, err := s.GetUtxoList(fee, targetAddress, amount)
	if err != nil {
		return "", err
	}

	createTxBody := map[string]interface{}{
		"inputs":  utxoList["inputs"],
		"outputs": utxoList["outputs"],
		"contract": Contract{
			Action:  0,
			Code:    "",
			Address: "",
			Args:    []string{},
		},
	}

	createTxResult, err := s.fetchJSON(s.baseURL+"rawtransaction/create", "POST", createTxBody)
	if err != nil {
		return "", err
	}

	hex, ok := createTxResult["hex"].(string)
	if !ok {
		return "", errors.New("invalid hex in create transaction response")
	}

	signedTx, err := s.SignContract(hex)
	if err != nil {
		return "", err
	}

	return s.SendTx(signedTx)
}

func (s *OurChainService) DeployContract(fee float64, targetAddress string, code string, args []string) (map[string]string, error) {
	if args == nil {
		args = []string{""}
	}

	contract := Contract{
		Action:  1,
		Code:    code,
		Address: targetAddress,
		Args:    args,
	}

	rawTx, err := s.CreateTx(fee, "", contract)
	if err != nil {
		return nil, err
	}

	hex, ok := rawTx["hex"].(string)
	if !ok {
		return nil, errors.New("invalid hex in create transaction response")
	}

	signedTx, err := s.SignContract(hex)
	if err != nil {
		return nil, err
	}

	txid, err := s.SendTx(signedTx)
	if err != nil {
		return nil, err
	}

	contractAddress, ok := rawTx["contractAddress"].(string)
	if !ok {
		return nil, errors.New("invalid contract address in response")
	}

	return map[string]string{
		"txid":            txid,
		"contractAddress": contractAddress,
	}, nil
}

func (s *OurChainService) CallContract(fee float64, targetAddress string, code string, args []string) (string, error) {
	if args == nil {
		args = []string{""}
	}

	contract := Contract{
		Action:  2,
		Code:    code,
		Address: targetAddress,
		Args:    args,
	}

	rawTx, err := s.CreateTx(fee, "", contract)
	if err != nil {
		return "", err
	}

	hex, ok := rawTx["hex"].(string)
	if !ok {
		return "", errors.New("invalid hex in create transaction response")
	}

	signedTx, err := s.SignContract(hex)
	if err != nil {
		return "", err
	}

	return s.SendTx(signedTx)
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

	message, ok := result["message"].(string)
	if !ok {
		return "", errors.New("invalid message in response")
	}

	return message, nil
}
