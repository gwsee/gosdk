package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/scheduler"
	"github.com/terasum/viper"
)

const (
	// TRANSACTION type
	TRANSACTION = "tx_"
	// CONTRACT type
	CONTRACT = "contract_"
	// BLOCK type
	BLOCK = "block_"
	// ACCOUNT type
	ACCOUNT = "account_"
	// NODE type
	NODE = "node_"
	// CERT type
	CERT = "cert_"
	// SUB type
	SUB = "sub_"
	// ARCHIVE type
	ARCHIVE = "archive_"
	// MQ type
	MQ = "mq_"
	// RADAR type
	RADAR = "radar_"

	DefaultNamespace          = "global"
	DefaultResendTime         = 10
	DefaultFirstPollInterval  = 100
	DefaultFirstPollTime      = 10
	DefaultSecondPollInterval = 1000
	DefaultSecondPollTime     = 10
	DefaultReConnectTime      = 10000
)

var (
	logger = common.GetLogger("rpc")
	once   = sync.Once{}
)

// RPC represents rpc apis
type RPC struct {
	hrm                httpRequestManager
	dispatcher         *scheduler.Dispatcher
	namespace          string
	resTime            int64
	firstPollInterval  int64
	firstPollTime      int64
	secondPollInterval int64
	secondPollTime     int64
	reConnTime         int64
}

func (rpc *RPC) String() string {
	nodes := rpc.hrm.nodes
	var nodeString string
	nodeString += "["
	for i, v := range nodes {
		nodeString += "{\"index\":" + strconv.Itoa(i) + ", \"url:\"" + v.url + "}"
		if i < len(nodes)-1 {
			nodeString += ", "
		}
	}
	nodeString += "]"
	return "\"namespace\":" + rpc.namespace + ", \"nodeUrl\":" + nodeString
}

// NewRPC get a RPC instance with default conf directory path "../conf"
func NewRPC() *RPC {
	return NewRPCWithPath(common.DefaultConfRootPath)
}

// NewRPCWithPath get a RPC instance with user defined root conf directory path
// the default conf root file structure should like this:
//
//      conf
//		├── certs
//		│   ├── ecert.cert
//		│   ├── ecert.priv
//		│   ├── sdkcert.cert
//		│   ├── sdkcert.priv
//		│   ├── tls
//		│   │   ├── tls_peer.cert
//		│   │   ├── tls_peer.priv
//		│   │   └── tlsca.ca
//		│   ├── unique.priv
//		│   └── unique.pub
//		└── hpc.toml
func NewRPCWithPath(confRootPath string) *RPC {
	vip := viper.New()
	vip.SetConfigFile(filepath.Join(confRootPath, common.DefaultConfRelPath))
	err := vip.ReadInConfig()
	if err != nil {
		panic(fmt.Sprintf("read conf from %s error", filepath.Join(confRootPath, common.DefaultConfRelPath)))
	}

	common.InitLog(vip)

	httpRequestManager := newHTTPRequestManager(vip, confRootPath)

	namespace := vip.GetString(common.NamespaceConf)
	logger.Debugf("[CONFIG]: %s = %v", common.NamespaceConf, namespace)

	resTime := vip.GetInt64(common.PollingResendTime)
	logger.Debugf("[CONFIG]: %s = %v", common.PollingResendTime, resTime)

	firstPollInterval := vip.GetInt64(common.PollingFirstPollingInterval)
	logger.Debugf("[CONFIG]: %s = %v", common.PollingFirstPollingInterval, firstPollInterval)

	firstPollTime := vip.GetInt64(common.PollingFirstPollingTimes)
	logger.Debugf("[CONFIG]: %s = %v", common.PollingFirstPollingTimes, firstPollTime)

	secondPollInterval := vip.GetInt64(common.PollingSecondPollingInterval)
	logger.Debugf("[CONFIG]: %s = %v", common.PollingSecondPollingInterval, secondPollInterval)

	secondPollTime := vip.GetInt64(common.PollingSecondPollingTimes)
	logger.Debugf("[CONFIG]: %s = %v", common.PollingSecondPollingTimes, secondPollTime)

	reConnTime := vip.GetInt64(common.ReConnectTime)
	logger.Debugf("[CONFIG]: %s = %v", common.ReConnectTime, reConnTime)

	// Start dispatcher for retry sendTx
	dispatcher := scheduler.NewDispatcher(10)
	dispatcher.Run()

	return &RPC{
		hrm:                *httpRequestManager,
		dispatcher:         dispatcher,
		namespace:          namespace,
		resTime:            resTime,
		firstPollInterval:  firstPollInterval,
		firstPollTime:      firstPollTime,
		secondPollInterval: secondPollInterval,
		secondPollTime:     secondPollTime,
		reConnTime:         reConnTime,
	}
}

// DefaultRPC return a *RPC with some default configs
func DefaultRPC(nodes ...*Node) *RPC {
	rpc := &RPC{
		namespace:          DefaultNamespace,
		resTime:            DefaultResendTime,
		firstPollInterval:  DefaultFirstPollInterval,
		firstPollTime:      DefaultFirstPollTime,
		secondPollInterval: DefaultSecondPollInterval,
		secondPollTime:     DefaultSecondPollTime,
		reConnTime:         DefaultReConnectTime,
		hrm:                *defaultHTTPRequestManager(),
	}
	rpc.hrm.nodes = nodes

	return rpc
}

// Namespace setter
func (rpc *RPC) Namespace(ns string) *RPC {
	rpc.namespace = ns
	return rpc
}

// ResendTimes setter
func (rpc *RPC) ResendTimes(resTime int64) *RPC {
	rpc.resTime = resTime
	return rpc
}

// FirstPollInterval setter
func (rpc *RPC) FirstPollInterval(fpi int64) *RPC {
	rpc.firstPollInterval = fpi
	return rpc
}

// FirstPollTime setter
func (rpc *RPC) FirstPollTime(fpt int64) *RPC {
	rpc.firstPollTime = fpt
	return rpc
}

// SecondPollInterval setter
func (rpc *RPC) SecondPollInterval(spi int64) *RPC {
	rpc.secondPollInterval = spi
	return rpc
}

// SecondPollTime setter
func (rpc *RPC) SecondPollTime(spt int64) *RPC {
	rpc.secondPollTime = spt
	return rpc
}

// ReConnTime setter
func (rpc *RPC) ReConnTime(rct int64) *RPC {
	rpc.reConnTime = rct
	return rpc
}

// Https use sets the https related options
func (rpc *RPC) Https(tlscaPath, tlspeerCertPath, tlspeerPrivPath string) *RPC {
	vip := viper.New()
	vip.Set(common.SecurityHttps, true)
	vip.Set(common.SecurityTlsca, tlscaPath)
	vip.Set(common.SecurityTlspeerCert, tlspeerCertPath)
	vip.Set(common.SecurityTlspeerPriv, tlspeerPrivPath)

	rpc.hrm.client = newHTTPClient(vip, ".")
	rpc.hrm.isHTTP = true

	for i := 0; i < len(rpc.hrm.nodes); i++ {
		rpc.hrm.nodes[i].url = "https://" + strings.Split(rpc.hrm.nodes[i].url, "//")[1]
	}

	return rpc
}

func (rpc *RPC) AddNode(url, rpcPort, wsPort string) *RPC {
	rpc.hrm.nodes = append(rpc.hrm.nodes, newNode(url, rpcPort, wsPort, rpc.hrm.isHTTP))

	return rpc
}

func (rpc *RPC) Tcert(cfca bool, sdkcertPath, sdkcertPrivPath, uniquePubPath, uniquePrivPath string) *RPC {
	vip := viper.New()
	vip.Set(common.PrivacyCfca, cfca)
	vip.Set(common.PrivacySendTcert, true)
	vip.Set(common.PrivacySDKcertPath, sdkcertPath)
	vip.Set(common.PrivacySDKcertPrivPath, sdkcertPrivPath)
	vip.Set(common.PrivacyUniquePubPath, uniquePubPath)
	vip.Set(common.PrivacyUniquePrivPath, uniquePrivPath)

	rpc.hrm.tcm = NewTCertManager(vip, ".")

	return rpc
}

// BindNodes generate a new RPC instance that bind with given indexes
func (rpc *RPC) BindNodes(nodeIndexes ...int) (*RPC, error) {
	if len(nodeIndexes) == 0 {
		return rpc, nil
	}
	proxy := *rpc
	proxy.hrm.nodes = make([]*Node, len(nodeIndexes))
	proxy.hrm.nodeIndex = 0

	limit := len(rpc.hrm.nodes)
	for i := 0; i < len(nodeIndexes); i++ {
		if nodeIndexes[i] > limit {
			return nil, fmt.Errorf("nodeIndex %d is out of range", i)
		}
		proxy.hrm.nodes[i] = rpc.hrm.nodes[nodeIndexes[i]-1]
	}
	return &proxy, nil
}

// package method name and params to JsonRequest
func (rpc *RPC) jsonRPC(method string, params ...interface{}) *JSONRequest {
	req := &JSONRequest{
		Method:    method,
		Version:   JSONRPCVersion,
		ID:        1,
		Namespace: rpc.namespace,
		Params:    params,
	}
	return req
}

// call is a function to get response result commodiously
func (rpc *RPC) call(method string, params ...interface{}) (json.RawMessage, StdError) {
	req := rpc.jsonRPC(method, params...)
	return rpc.callWithReq(req)
}

// callWithReq is a function to get response origin data
func (rpc *RPC) callWithReq(req *JSONRequest) (json.RawMessage, StdError) {
	body, sysErr := json.Marshal(req)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	data, err := rpc.hrm.SyncRequest(body)
	if err != nil {
		return nil, err
	}

	var resp *JSONResponse
	if sysErr = json.Unmarshal(data, &resp); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	if resp.Code != SuccessCode {
		return nil, NewServerError(resp.Code, resp.Message)
	}

	return resp.Result, nil
}

// callWithSpecificUrl is a function to get response form specific url
func (rpc *RPC) callWithSpecificURL(method string, url string, params ...interface{}) (json.RawMessage, StdError) {
	req := rpc.jsonRPC(method, params...)

	body, sysErr := json.Marshal(req)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	data, err := rpc.hrm.SyncRequestSpecificURL(body, url)
	if err != nil {
		return nil, err
	}

	var resp *JSONResponse
	if sysErr = json.Unmarshal(data, &resp); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	if resp.Code != SuccessCode {
		return nil, NewServerError(resp.Code, resp.Message)
	}

	return resp.Result, nil
}

// Call call and get tx receipt directly without polling
func (rpc *RPC) Call(method string, param interface{}) (*TxReceipt, StdError) {
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}
	var receipt TxReceipt
	if sysErr := json.Unmarshal(data, &receipt); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return &receipt, nil
}

// CallByPolling call and get tx receipt by polling
func (rpc *RPC) CallByPolling(method string, param interface{}, isPrivateTx bool) (*TxReceipt, StdError) {
	var (
		req    *JSONRequest
		data   json.RawMessage
		hash   string
		err    StdError
		sysErr error
	)
	// if simulate is false, transaction need to resend
	req = rpc.jsonRPC(method, param)

	for i := int64(0); i < rpc.resTime; i++ {
		if data, err = rpc.callWithReq(req); err != nil {
			if err.Code() == DuplicateTransactionsCode {
				// -32007: 交易重复
				s := strings.Split(string(data), " ")
				if len(s) >= 3 {
					hash = s[2]
				}
				txReceipt, innErr, success := rpc.GetTxReceiptByPolling(hash, isPrivateTx)
				err = innErr
				if success {
					return txReceipt, err
				}
				continue
			} else if err.Code() == GetResponseErrorCode || err.Code() == SystemErrorCode {
				// resend
			} else if err.Code() != SystemBusyCode && err.Code() != DataNotExistCode {
				// -9999: 获取响应失败
				// -32001: 查询的数据不存在
				// -32006: 系统繁忙
				return nil, err
			}
		} else {
			if sysErr = json.Unmarshal(data, &hash); sysErr != nil {
				return nil, NewSystemError(sysErr)
			}
			txReceipt, innErr, success := rpc.GetTxReceiptByPolling(hash, isPrivateTx)
			err = innErr
			if success {
				return txReceipt, err
			}
			continue
		}
		//if code is -9999 -32001 and -32006, we should sleep then resend
		time.Sleep(time.Millisecond * time.Duration(rpc.firstPollInterval+rpc.secondPollInterval))
	}
	return nil, NewRequestTimeoutError(errors.New("request time out"))
}

// GetTxReceiptByPolling get tx receipt by polling
func (rpc *RPC) GetTxReceiptByPolling(txHash string, isPrivateTx bool) (*TxReceipt, StdError, bool) {
	var (
		err     StdError
		receipt *TxReceipt
	)
	txHash = chPrefix(txHash)

	for j := int64(0); j < rpc.firstPollTime; j++ {
		receipt, err = rpc.GetTxReceipt(txHash, isPrivateTx)
		if err != nil {
			if err.Code() == BalanceInsufficientCode {
				return nil, err, true
			} else if err.Code() != DataNotExistCode && err.Code() != SystemBusyCode {
				return nil, err, true
			}
			time.Sleep(time.Millisecond * time.Duration(rpc.firstPollInterval))
		} else {
			return receipt, nil, true
		}
	}
	for j := int64(0); j < rpc.secondPollTime; j++ {
		receipt, err = rpc.GetTxReceipt(txHash, isPrivateTx)
		if err != nil {
			if err.Code() == BalanceInsufficientCode {
				return nil, err, true
			} else if err.Code() != DataNotExistCode && err.Code() != SystemBusyCode {
				return nil, err, true
			}
			time.Sleep(time.Millisecond * time.Duration(rpc.firstPollInterval))
		} else {
			return receipt, nil, true
		}
	}
	return nil, NewGetResponseError(errors.New("polling failure")), false
}

/*---------------------------------- node ----------------------------------*/

// GetNodes 获取区块链节点信息
func (rpc *RPC) GetNodes() ([]NodeInfo, StdError) {
	data, err := rpc.call(NODE + "getNodes")
	if err != nil {
		return nil, err
	}
	var nodeInfo []NodeInfo
	if sysErr := json.Unmarshal(data, &nodeInfo); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	return nodeInfo, nil
}

// GetNodeHash 获取随机节点hash
func (rpc *RPC) GetNodeHash() (string, StdError) {
	data, err := rpc.call(NODE + "getNodeHash")
	if err != nil {
		return "", err
	}
	hash := []byte(data)
	return string(hash), nil
}

// GetNodeHashByID 从指定节点获取hash
func (rpc *RPC) GetNodeHashByID(id int) (string, StdError) {
	url := rpc.hrm.nodes[id-1].url
	data, err := rpc.callWithSpecificURL(NODE+"getNodeHash", url)
	if err != nil {
		return "", err
	}

	var hash string
	if sysErr := json.Unmarshal(data, &hash); sysErr != nil {
		return "", NewSystemError(sysErr)
	}
	return hash, nil
}

// DeleteNodeVP 删除VP节点
func (rpc *RPC) DeleteNodeVP(hash string) (bool, StdError) {
	method := NODE + "deleteVP"
	param := newMapParam("nodehash", hash)
	_, err := rpc.call(method, param.Serialize())
	if err != nil {
		return false, err
	}
	return true, nil
}

// DeleteNodeNVP 删除NVP节点
func (rpc *RPC) DeleteNodeNVP(hash string) (bool, StdError) {
	method := NODE + "deleteNVP"
	param := newMapParam("nodehash", hash)
	_, err := rpc.call(method, param.Serialize())
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetNodeStates 获取节点状态信息
func (rpc *RPC) GetNodeStates() ([]NodeStateInfo, StdError) {
	method := NODE + "getNodeStates"
	data, err := rpc.call(method)
	if err != nil {
		return nil, err
	}

	var list []NodeStateInfo
	if sysErr := json.Unmarshal(data, &list); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return list, nil
}

/*---------------------------------- block ----------------------------------*/

// GetLatestBlock returns information about the latest block
func (rpc *RPC) GetLatestBlock() (*Block, StdError) {
	method := BLOCK + "latestBlock"

	data, stdErr := rpc.call(method)
	if stdErr != nil {
		return nil, stdErr
	}

	blockRaw := BlockRaw{}

	sysErr := json.Unmarshal(data, &blockRaw)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	block, stdErr := blockRaw.ToBlock()
	if stdErr != nil {
		return nil, NewSystemError(sysErr)
	}

	return block, nil
}

// GetBlocks returns a list of blocks from start block number to end block number
// isPlain indicates if the result includes transaction information. if false, includes, otherwise not.
func (rpc *RPC) GetBlocks(from, to uint64, isPlain bool) ([]*Block, StdError) {
	if from == 0 || to == 0 || to < from {
		return nil, NewSystemError(errors.New("参数必须为非0正整数，且to应该大于from"))
	}

	method := BLOCK + "getBlocks"

	mp := newMapParam("from", from)
	mp.addKV("to", to)
	mp.addKV("isPlain", isPlain)

	data, stdErr := rpc.call(method, mp.Serialize())
	if stdErr != nil {
		return nil, stdErr
	}

	var blockRaws []BlockRaw

	sysErr := json.Unmarshal(data, &blockRaws)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	blocks := make([]*Block, 0, len(blockRaws))

	for _, v := range blockRaws {
		block, stdErr := v.ToBlock()
		if stdErr != nil {
			return nil, stdErr
		}

		blocks = append(blocks, block)
	}

	return blocks, nil

}

// GetBlockByHash returns information about a block by hash.
// If the param isPlain value is true, it returns block excluding transactions. If false,
// it returns block including transactions.
func (rpc *RPC) GetBlockByHash(blockHash string, isPlain bool) (*Block, StdError) {
	method := BLOCK + "getBlockByHash"

	data, stdErr := rpc.call(method, blockHash, isPlain)
	if stdErr != nil {
		return nil, stdErr
	}

	blockRaw := BlockRaw{}
	if sysErr := json.Unmarshal(data, &blockRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	block, stdErr := blockRaw.ToBlock()
	if stdErr != nil {
		return nil, stdErr
	}

	return block, nil
}

// GetBatchBlocksByHash returns a list of blocks by a list of specific block hash.
func (rpc *RPC) GetBatchBlocksByHash(blockHashes []string, isPlain bool) ([]*Block, StdError) {
	method := BLOCK + "getBatchBlocksByHash"

	mp := newMapParam("hashes", blockHashes)
	mp.addKV("isPlain", isPlain)

	data, stdErr := rpc.call(method, mp.Serialize())
	if stdErr != nil {
		return nil, stdErr
	}

	var blockRaws []BlockRaw

	sysErr := json.Unmarshal(data, &blockRaws)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	blocks := make([]*Block, 0, len(blockRaws))

	for _, v := range blockRaws {
		block, stdErr := v.ToBlock()
		if stdErr != nil {
			return nil, stdErr
		}

		blocks = append(blocks, block)
	}

	return blocks, nil
}

// GetBlockByNumber returns information about a block by number. If the param isPlain
// value is true, it returns block excluding transactions. If false, it returns block
// including transactions.
// blockNum can use `latest`, means get latest block
func (rpc *RPC) GetBlockByNumber(blockNum interface{}, isPlain bool) (*Block, StdError) {
	method := BLOCK + "getBlockByNumber"

	data, stdErr := rpc.call(method, blockNum, isPlain)
	if stdErr != nil {
		return nil, stdErr
	}

	var blockRaw BlockRaw

	sysErr := json.Unmarshal(data, &blockRaw)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	block, stdErr := blockRaw.ToBlock()
	if stdErr != nil {
		return nil, stdErr
	}

	return block, nil
}

// GetBatchBlocksByNumber returns a list of blocks by a list of specific block number.
func (rpc *RPC) GetBatchBlocksByNumber(blockNums []uint64, isPlain bool) ([]*Block, StdError) {
	method := BLOCK + "getBatchBlocksByNumber"

	mp := newMapParam("numbers", blockNums)
	mp.addKV("isPlain", isPlain)

	data, stdErr := rpc.call(method, mp.Serialize())
	if stdErr != nil {
		return nil, stdErr
	}

	var blockRaws []BlockRaw

	sysErr := json.Unmarshal(data, &blockRaws)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	blocks := make([]*Block, 0, len(blockRaws))

	for _, v := range blockRaws {
		block, stdErr := v.ToBlock()
		if stdErr != nil {
			return nil, stdErr
		}

		blocks = append(blocks, block)
	}

	return blocks, nil
}

// GetAvgGenTimeByBlockNum calculates the average generation time of all blocks
// for the given block number.
func (rpc *RPC) GetAvgGenTimeByBlockNum(from, to uint64) (int64, StdError) {
	if from == 0 || to == 0 || to < from {
		return -1, NewSystemError(errors.New("参数必须为非0正整数，且to应该大于from"))
	}

	method := BLOCK + "getAvgGenerateTimeByBlockNumber"

	mp := newMapParam("from", from)
	mp.addKV("to", to)

	data, stdErr := rpc.call(method, mp.Serialize())
	if stdErr != nil {
		return -1, stdErr
	}

	str := strings.Replace(string(data), "\"", "", 2)

	if strings.Index(str, "0x") == 0 || strings.Index(str, "-0x") == 0 {
		str = strings.Replace(str, "0x", "", 1)
	}

	avgTime, sysErr := strconv.ParseInt(str, 16, 64)
	if sysErr != nil {
		return -1, NewSystemError(sysErr)
	}

	return avgTime, nil
}

// GetBlocksByTime returns the number of blocks, starting block and ending block
// at specific time periods.
// startTime and endTime are timestamps
func (rpc *RPC) GetBlocksByTime(startTime, endTime uint64) (*BlockInterval, StdError) {
	if endTime < startTime {
		return nil, NewSystemError(errors.New("startTime必须小于endTime"))
	}

	method := BLOCK + "getBlocksByTime"

	mp := newMapParam("startTime", startTime)
	mp.addKV("endTime", endTime)

	data, stdErr := rpc.call(method, mp.Serialize())
	if stdErr != nil {
		return nil, stdErr
	}

	var blockNumRaw BlockIntervalRaw

	sysErr := json.Unmarshal(data, &blockNumRaw)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	blockNum, stdErr := blockNumRaw.ToBlockInterval()
	if stdErr != nil {
		return nil, stdErr
	}

	return blockNum, nil
}

// QueryTPS queries the block generation speed and tps within a given time range.
func (rpc *RPC) QueryTPS(startTime, endTime uint64) (*TPSInfo, StdError) {
	if endTime < startTime {
		return nil, NewSystemError(errors.New("startTime必须小于endTime"))
	}

	method := BLOCK + "queryTPS"

	mp := newMapParam("startTime", startTime)
	mp.addKV("endTime", endTime)

	data, stdErr := rpc.call(method, mp.Serialize())
	if stdErr != nil {
		return nil, stdErr
	}

	items := strings.Split(string(data), ";")

	startTimeStr := items[0][12:]
	endTimeStr := items[1][9:]
	totalBlock, sysErr := strconv.ParseUint(strings.Split(items[2], ":")[1], 0, 64)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	blockPerSec, sysErr := strconv.ParseFloat(strings.Split(items[3], ":")[1], 64)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	tps, sysErr := strconv.ParseFloat(strings.Split(strings.Trim(items[4], "\""), ":")[1], 64)
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	return &TPSInfo{
		StartTime:     startTimeStr,
		EndTime:       endTimeStr,
		TotalBlockNum: totalBlock,
		BlocksPerSec:  blockPerSec,
		Tps:           tps,
	}, nil
}

// GetGenesisBlock returns current genesis block number.
// result is hex string
func (rpc *RPC) GetGenesisBlock() (string, StdError) {
	method := BLOCK + "getGenesisBlock"

	data, stdErr := rpc.call(method)
	if stdErr != nil {
		return "", stdErr
	}

	var result string
	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return "", NewSystemError(sysErr)
	}

	return result, nil
}

// GetChainHeight returns the current chain height.
// result is hex string
func (rpc *RPC) GetChainHeight() (string, StdError) {
	method := BLOCK + "getChainHeight"

	data, stdErr := rpc.call(method)
	if stdErr != nil {
		return "", stdErr
	}

	var result string
	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return "", NewSystemError(sysErr)
	}

	return result, nil
}

/*---------------------------------- transaction ----------------------------------*/

// GetTransactionsByBlkNum 根据区块号查询范围内的交易
func (rpc *RPC) GetTransactionsByBlkNum(start, end uint64) ([]TransactionInfo, StdError) {
	qtr := &QueryTxRange{
		From: start,
		To:   end,
	}
	method := TRANSACTION + "getTransactions"
	param := qtr.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var txsRaw []TransactionRaw
	if sysErr := json.Unmarshal(data, &txsRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	txs := make([]TransactionInfo, 0, len(txsRaw))
	for _, txRaw := range txsRaw {
		t, err := txRaw.ToTransaction()
		if err != nil {
			return nil, err
		}
		txs = append(txs, *t)
	}
	return txs, nil
}

// GetDiscardTx 获取所有非法交易
func (rpc *RPC) GetDiscardTx() ([]TransactionInfo, StdError) {
	method := TRANSACTION + "getDiscardTransactions"
	data, err := rpc.call(method)
	if err != nil {
		return nil, err
	}

	var txsRaw []TransactionRaw
	if sysErr := json.Unmarshal(data, &txsRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	txs := make([]TransactionInfo, 0, len(txsRaw))
	for _, txRaw := range txsRaw {
		t, err := txRaw.ToTransaction()
		if err != nil {
			return nil, err
		}
		txs = append(txs, *t)
	}
	return txs, nil
}

// GetTransactionByHash 通过交易hash获取交易
// 参数txHash应该是"0x...."的形式
func (rpc *RPC) GetTransactionByHash(txHash string) (*TransactionInfo, StdError) {
	method := TRANSACTION + "getTransactionByHash"
	param := txHash
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var tx TransactionRaw
	if sysErr := json.Unmarshal(data, &tx); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return tx.ToTransaction()
}

func (rpc *RPC) GetPrivateTransactionByHash(txHash string) (*TransactionInfo, StdError) {
	method := TRANSACTION + "getPrivateTransactionByHash"
	param := txHash
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var tx TransactionRaw
	if sysErr := json.Unmarshal(data, &tx); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return tx.ToTransaction()
}

// GetBatchTxByHash 批量获取交易
func (rpc *RPC) GetBatchTxByHash(hashes []string) ([]TransactionInfo, StdError) {
	mp := newMapParam("hashes", hashes)
	method := TRANSACTION + "getBatchTransactions"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var txsRaw []TransactionRaw
	if sysErr := json.Unmarshal(data, &txsRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	txs := make([]TransactionInfo, 0, len(txsRaw))
	for _, txRaw := range txsRaw {
		t, err := txRaw.ToTransaction()
		if err != nil {
			return nil, err
		}
		txs = append(txs, *t)
	}
	return txs, nil
}

// GetTxByBlkHashAndIdx 通过区块hash和交易序号返回交易信息
func (rpc *RPC) GetTxByBlkHashAndIdx(blkHash string, index uint64) (*TransactionInfo, StdError) {
	method := TRANSACTION + "getTransactionByBlockHashAndIndex"
	data, err := rpc.call(method, blkHash, index)
	if err != nil {
		return nil, err
	}

	var tx TransactionRaw
	if sysErr := json.Unmarshal(data, &tx); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return tx.ToTransaction()
}

// GetTxByBlkNumAndIdx 通过区块号和交易序号查询交易
func (rpc *RPC) GetTxByBlkNumAndIdx(blkNum, index uint64) (*TransactionInfo, StdError) {
	method := TRANSACTION + "getTransactionByBlockNumberAndIndex"
	data, err := rpc.call(method, strconv.FormatUint(blkNum, 10), index)
	if err != nil {
		return nil, err
	}

	var tx TransactionRaw
	if sysErr := json.Unmarshal(data, &tx); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return tx.ToTransaction()
}

// GetTxAvgTimeByBlockNumber 通过区块号区间获取交易平均处理时间
func (rpc *RPC) GetTxAvgTimeByBlockNumber(from, to uint64) (uint64, StdError) {
	mp := newMapParam("from", from)
	mp.addKV("to", to)
	method := TRANSACTION + "getTxAvgTimeByBlockNumber"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return 0, err
	}

	var avgTime string
	if sysErr := json.Unmarshal(data, &avgTime); sysErr != nil {
		return 0, NewSystemError(sysErr)
	}
	result, sysErr := strconv.ParseUint(avgTime, 0, 64)
	if err != nil {
		return 0, NewSystemError(sysErr)
	}
	return result, nil
}

// GetBatchReceipt 批量获取回执
func (rpc *RPC) GetBatchReceipt(hashes []string) ([]TxReceipt, StdError) {
	mp := newMapParam("hashes", hashes)
	method := TRANSACTION + "getBatchReceipt"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var txs []TxReceipt
	if sysErr := json.Unmarshal(data, &txs); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return txs, nil
}

// GetTransactionsCountByTime 查询指定时间区间内的交易数量
func (rpc *RPC) GetTransactionsCountByTime(startTime, endTime uint64) (uint64, StdError) {
	mp := newMapParam("startTime", startTime).addKV("endTime", endTime)
	method := TRANSACTION + "getTransactionsCountByTime"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return 0, err
	}

	var hexCount string
	if sysError := json.Unmarshal(data, &hexCount); sysError != nil {
		return 0, NewSystemError(err)
	}
	count, sysErr := strconv.ParseUint(hexCount, 0, 64)
	if sysErr != nil {
		return 0, NewSystemError(sysErr)
	}
	return count, nil
}

// GetBlkTxCountByHash 通过区块hash获取区块上交易数
func (rpc *RPC) GetBlkTxCountByHash(blkHash string) (uint64, StdError) {
	method := TRANSACTION + "getBlockTransactionCountByHash"
	param := blkHash
	data, err := rpc.call(method, param)
	if err != nil {
		return 0, err
	}

	var hexCount string
	if sysError := json.Unmarshal(data, &hexCount); sysError != nil {
		return 0, NewSystemError(err)
	}
	count, sysErr := strconv.ParseUint(hexCount, 0, 64)
	if sysErr != nil {
		return 0, NewSystemError(sysErr)
	}
	return count, nil
}

// GetBlkTxCountByNumber 通过区块number获取区块上交易数
func (rpc *RPC) GetBlkTxCountByNumber(blkNum string) (uint64, StdError) {
	method := TRANSACTION + "getBlockTransactionCountByNumber"
	param := blkNum
	data, err := rpc.call(method, param)
	if err != nil {
		return 0, err
	}

	var hexCount string
	if sysError := json.Unmarshal(data, &hexCount); sysError != nil {
		return 0, NewSystemError(err)
	}
	count, sysErr := strconv.ParseUint(hexCount, 0, 64)
	if sysErr != nil {
		return 0, NewSystemError(sysErr)
	}
	return count, nil
}

// GetSignHash 获取交易签名哈希
func (rpc *RPC) GetSignHash(transaction *Transaction) (string, StdError) {
	method := TRANSACTION + "getSignHash"
	param := transaction.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return "", err
	}

	var hash string
	if sysError := json.Unmarshal(data, &hash); sysError != nil {
		return "", NewSystemError(err)
	}
	return hash, nil
}

// GetTxCount 获取链上所有交易数量
func (rpc *RPC) GetTxCount() (*TransactionsCount, StdError) {
	mehtod := TRANSACTION + "getTransactionsCount"
	data, err := rpc.call(mehtod)
	if err != nil {
		return nil, err
	}

	var txRaw TransactionsCountRaw
	if sysErr := json.Unmarshal(data, &txRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	txCount, sysErr := txRaw.ToTransactionsCount()
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return txCount, nil
}

// GetTxCountByContractAddr 查询区块间指定合约的交易量 txExtra过滤是否带有额外字段
func (rpc *RPC) GetTxCountByContractAddr(from, to uint64, address string, txExtra bool) (*TransactionsCountByContract, StdError) {
	mp := newMapParam("from", from).addKV("to", to).addKV("address", address).addKV("txExtra", txExtra)
	method := TRANSACTION + "getTransactionsCountByContractAddr"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var countRaw *TransactionsCountByContractRaw
	if sysErr := json.Unmarshal(data, &countRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	count, sysErr := countRaw.ToTransactionsCountByContract()
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return count, nil
}

// GetTransactionsCountByMethodID 查询区块区间交易数量（by method ID）
func (rpc *RPC) GetTransactionsCountByMethodID(from, to uint64, address string, methodID string) (*TransactionsCountByContract, StdError) {
	mp := newMapParam("from", from).addKV("to", to).addKV("address", address).addKV("methodID", methodID)
	method := TRANSACTION + "getTransactionsCountByMethodID"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var countRaw *TransactionsCountByContractRaw
	if sysErr := json.Unmarshal(data, &countRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	count, sysErr := countRaw.ToTransactionsCountByContract()
	if sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return count, nil
}

// GetTxByTime 根据范围时间戳查询交易信息
func (rpc *RPC) GetTxByTime(start, end uint64) ([]TransactionInfo, StdError) {
	mp := newMapParam("startTime", start).addKV("endTime", end)
	method := TRANSACTION + "getTransactionsByTime"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var txsRaw []TransactionRaw
	if sysErr := json.Unmarshal(data, &txsRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	txs := make([]TransactionInfo, 0, len(txsRaw))
	for _, txRaw := range txsRaw {
		t, err := txRaw.ToTransaction()
		if err != nil {
			return nil, err
		}
		txs = append(txs, *t)
	}
	return txs, nil
}

// GetDiscardTransactionsByTime 查询指定时间区间内的非法交易
func (rpc *RPC) GetDiscardTransactionsByTime(start, end uint64) ([]TransactionInfo, StdError) {
	mp := newMapParam("startTime", start).addKV("endTime", end)
	method := TRANSACTION + "getDiscardTransactionsByTime"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var txsRaw []TransactionRaw
	if sysErr := json.Unmarshal(data, &txsRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	txs := make([]TransactionInfo, 0, len(txsRaw))
	for _, txRaw := range txsRaw {
		t, err := txRaw.ToTransaction()
		if err != nil {
			return nil, err
		}
		txs = append(txs, *t)
	}
	return txs, nil
}

// GetNextPageTxs 获取下一页的交易
func (rpc *RPC) GetNextPageTxs(blkNumber, txIndex, minBlkNumber, maxBlkNumber, separated, pageSize uint64, containCurrent bool, contractAddr string) ([]TransactionInfo, StdError) {
	method := TRANSACTION + "getNextPageTransactions"
	param := &TransactionPageArg{
		strconv.FormatUint(blkNumber, 10),
		strconv.FormatUint(maxBlkNumber, 10),
		strconv.FormatUint(minBlkNumber, 10),
		txIndex, separated, pageSize, containCurrent, contractAddr}
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var txsRaw []TransactionRaw
	if sysErr := json.Unmarshal(data, &txsRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	txs := make([]TransactionInfo, 0, len(txsRaw))
	for _, txRaw := range txsRaw {
		t, err := txRaw.ToTransaction()
		if err != nil {
			return nil, err
		}
		txs = append(txs, *t)
	}
	return txs, nil
}

// GetPrevPageTxs 获取上一页的交易
func (rpc *RPC) GetPrevPageTxs(blkNumber, txIndex, minBlkNumber, maxBlkNumber, separated, pageSize uint64, containCurrent bool, contractAddr string) ([]TransactionInfo, StdError) {
	method := TRANSACTION + "getPrevPageTransactions"
	param := &TransactionPageArg{
		strconv.FormatUint(blkNumber, 10),
		strconv.FormatUint(maxBlkNumber, 10),
		strconv.FormatUint(minBlkNumber, 10),
		txIndex, separated, pageSize, containCurrent, contractAddr}
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var txsRaw []TransactionRaw
	if sysErr := json.Unmarshal(data, &txsRaw); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	txs := make([]TransactionInfo, 0, len(txsRaw))
	for _, txRaw := range txsRaw {
		t, err := txRaw.ToTransaction()
		if err != nil {
			return nil, err
		}
		txs = append(txs, *t)
	}
	return txs, nil
}

// GetTxReceipt 通过交易hash获取交易回执
// 参数txHash应该是"0x...."的形式
func (rpc *RPC) GetTxReceipt(txHash string, isPrivateTx bool) (*TxReceipt, StdError) {
	var method string
	txHash = chPrefix(txHash)
	if isPrivateTx {
		method = TRANSACTION + "getPrivateTransactionReceipt"
	} else {
		method = TRANSACTION + "getTransactionReceipt"
	}
	param := txHash
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var txr TxReceipt
	if sysErr := json.Unmarshal(data, &txr); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	txr.PrivTxHash = txHash
	return &txr, nil
}

// SendTx 同步发送交易
func (rpc *RPC) SendTx(transaction *Transaction) (*TxReceipt, StdError) {
	method := TRANSACTION + "sendTransaction"
	param := transaction.Serialize()
	if transaction.simulate {
		return rpc.Call(method, param)
	}
	return rpc.CallByPolling(method, param, transaction.isPrivateTx)
}

// SendTxAsync 异步发送交易
func (rpc *RPC) SendTxAsync(transaction *Transaction, handler AsyncHandler) bool {
	job := func() {
		asyncResult := Asyncify(rpc.SendTx)(transaction)
		res, err := asyncResult.GetResult()
		if err != nil {
			handler.OnFailure(err)
		} else {
			handler.OnSuccess(res)
		}
	}
	return rpc.dispatcher.AddJob(job)
}

/*---------------------------------- contract ----------------------------------*/

// CompileContract Compile contract rpc
func (rpc *RPC) CompileContract(code string) (*CompileResult, StdError) {
	data, err := rpc.call(CONTRACT+"compileContract", code)
	if err != nil {
		return nil, err
	}

	var cr CompileResult
	if sysErr := json.Unmarshal(data, &cr); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}
	return &cr, nil
}

// DeployContract Deploy contract rpc
func (rpc *RPC) DeployContract(transaction *Transaction) (*TxReceipt, StdError) {
	var method string
	if transaction.isPrivateTx {
		method = CONTRACT + "deployPrivateContract"
	} else {
		method = CONTRACT + "deployContract"
	}
	transaction.isDeploy = true
	param := transaction.Serialize()
	if transaction.simulate {
		return rpc.Call(method, param)
	}
	return rpc.CallByPolling(method, param, transaction.isPrivateTx)
}

// DeployContractAsync deploy contract async rpc
func (rpc *RPC) DeployContractAsync(transaction *Transaction, handler AsyncHandler) bool {
	job := func() {
		asyncResult := Asyncify(rpc.DeployContract)(transaction)
		res, err := asyncResult.GetResult()
		if err != nil {
			handler.OnFailure(err)
		} else {
			handler.OnSuccess(res)
		}
	}
	return rpc.dispatcher.AddJob(job)
}

// InvokeContract invoke contract rpc
func (rpc *RPC) InvokeContract(transaction *Transaction) (*TxReceipt, StdError) {
	var method string
	if transaction.isPrivateTx {
		method = CONTRACT + "invokePrivateContract"
	} else {
		method = CONTRACT + "invokeContract"
	}
	transaction.isInvoke = true
	param := transaction.Serialize()

	if transaction.simulate {
		return rpc.Call(method, param)
	}
	return rpc.CallByPolling(method, param, transaction.isPrivateTx)
}

// GetCode 获取合约字节编码
func (rpc *RPC) GetCode(contractAddress string) (string, StdError) {
	method := CONTRACT + "getCode"
	param := contractAddress
	data, err := rpc.call(method, param)
	if err != nil {
		return "", err
	}

	var code string
	if sysErr := json.Unmarshal(data, &code); sysErr != nil {
		return "", NewSystemError(sysErr)
	}

	return code, nil
}

// GetContractCountByAddr 获取合约数量
func (rpc *RPC) GetContractCountByAddr(accountAddress string) (uint64, StdError) {
	method := CONTRACT + "getContractCountByAddr"
	param := accountAddress
	data, err := rpc.call(method, param)
	if err != nil {
		return 0, err
	}

	var hexCount string
	if sysError := json.Unmarshal(data, &hexCount); sysError != nil {
		return 0, NewSystemError(err)
	}
	count, sysErr := strconv.ParseUint(hexCount, 0, 64)
	if sysErr != nil {
		return 0, NewSystemError(sysErr)
	}
	return count, nil
}

// EncryptoMessage 获取同态加密之后的账户余额以及转账金额
func (rpc *RPC) EncryptoMessage(balance, amount uint64, invalidHmValue string) (*BalanceAndAmount, StdError) {
	mp := newMapParam("balance", balance).addKV("amount", amount).addKV("invalidHmValue", invalidHmValue)
	method := CONTRACT + "encryptoMessage"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var balanceAndAmount *BalanceAndAmount
	if sysError := json.Unmarshal(data, &balanceAndAmount); sysError != nil {
		return nil, NewSystemError(err)
	}

	return balanceAndAmount, nil
}

// CheckHmValue 获取收款方对所有未验证同态交易的验证结果
func (rpc *RPC) CheckHmValue(rawValue []uint64, encryValue []string, invalidHmValue string) (*ValidResult, StdError) {
	mp := newMapParam("rawValue", rawValue).addKV("encryValue", encryValue).addKV("invalidHmValue", invalidHmValue)
	method := CONTRACT + "checkHmValue"
	param := mp.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}

	var validResutl *ValidResult
	if sysError := json.Unmarshal(data, &validResutl); sysError != nil {
		return nil, NewSystemError(err)
	}

	return validResutl, nil
}

// InvokeContractAsync invoke contract async rpc
func (rpc *RPC) InvokeContractAsync(transaction *Transaction, handler AsyncHandler) bool {
	job := func() {
		asyncResult := Asyncify(rpc.InvokeContract)(transaction)
		res, err := asyncResult.GetResult()
		if err != nil {
			handler.OnFailure(err)
		} else {
			handler.OnSuccess(res)
		}
	}
	return rpc.dispatcher.AddJob(job)
}

// MaintainContract 管理合约 opcode
// 1.升级合约
// 2.冻结
// 3.解冻
func (rpc *RPC) MaintainContract(transaction *Transaction) (*TxReceipt, StdError) {
	method := CONTRACT + "maintainContract"
	transaction.isMaintain = true
	param := transaction.Serialize()
	return rpc.CallByPolling(method, param, transaction.isPrivateTx)
}

// MaintainContractAsync maintain contract async
func (rpc *RPC) MaintainContractAsync(transaction *Transaction, handler AsyncHandler) bool {
	job := func() {
		asyncResult := Asyncify(rpc.MaintainContract)(transaction)
		res, err := asyncResult.GetResult()
		if err != nil {
			handler.OnFailure(err)
		} else {
			handler.OnSuccess(res)
		}
	}
	return rpc.dispatcher.AddJob(job)
}

// GetContractStatus 获取合约状态
func (rpc *RPC) GetContractStatus(contractAddress string) (string, StdError) {
	method := CONTRACT + "getStatus"
	param := contractAddress
	data, err := rpc.call(method, param)
	if err != nil {
		return "", err
	}
	result := string([]byte(data))
	return result, nil
}

// GetCreator 查询合约部署者
func (rpc *RPC) GetCreator(contractAddress string) (string, StdError) {
	method := CONTRACT + "getCreator"
	param := contractAddress
	data, err := rpc.call(method, param)
	if err != nil {
		return "", err
	}
	var accountAddress string
	if sysError := json.Unmarshal(data, &accountAddress); sysError != nil {
		return "", NewSystemError(err)
	}
	return accountAddress, nil
}

// GetCreateTime 查询合约部署时间
func (rpc *RPC) GetCreateTime(contractAddress string) (string, StdError) {
	method := CONTRACT + "getCreateTime"
	param := contractAddress
	data, err := rpc.call(method, param)
	if err != nil {
		return "", err
	}
	var dateTime string
	if sysError := json.Unmarshal(data, &dateTime); sysError != nil {
		return "", NewSystemError(err)
	}
	return dateTime, nil
}

// GetDeployedList 获取已部署的合约列表
func (rpc *RPC) GetDeployedList(address string) ([]string, StdError) {
	method := CONTRACT + "getDeployedList"
	param := address
	data, err := rpc.call(method, param)
	if err != nil {
		return nil, err
	}
	var result []string
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, NewSystemError(err)
	}
	return result, nil
}

// InvokeContractReturnHash for pressure test
// Deprecated:
func (rpc *RPC) InvokeContractReturnHash(transaction *Transaction) (string, StdError) {
	method := CONTRACT + "invokeContract"
	param := transaction.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return "", err
	}

	var hash string
	if sysErr := json.Unmarshal(data, &hash); err != nil {
		return "", NewSystemError(sysErr)
	}

	return hash, nil
}

// SendTxReturnHash for pressure test
// Deprecated:
func (rpc *RPC) SendTxReturnHash(transaction *Transaction) (string, StdError) {
	method := TRANSACTION + "sendTransaction"
	param := transaction.Serialize()
	data, err := rpc.call(method, param)
	if err != nil {
		return "", err
	}

	var hash string
	if sysErr := json.Unmarshal(data, &hash); err != nil {
		return "", NewSystemError(sysErr)
	}

	return hash, nil
}

/*---------------------------------- sub ----------------------------------*/

// GetWebSocketClient 获取WebSocket客户端
func (rpc *RPC) GetWebSocketClient() *WebSocketClient {
	once.Do(func() {
		globalWebSocketClient = &WebSocketClient{
			conns:   make(map[int]*connectionWrapper, len(rpc.hrm.nodes)),
			hrm:     &rpc.hrm,
			rwMutex: sync.RWMutex{},
		}
	})

	return globalWebSocketClient
}

/*---------------------------------- mq ----------------------------------*/

// GetMqClient 获取mq客户端
func (rpc *RPC) GetMqClient() *MqClient {
	once.Do(func() {
		mqClient = &MqClient{
			mqConns: make(map[uint]*mqWrapper, len(rpc.hrm.nodes)),
			hrm:     &rpc.hrm,
		}
	})

	return mqClient
}

/*---------------------------------- archive ----------------------------------*/

// Snapshot makes the snapshot for given the future block number or current the latest block number.
// It returns the snapshot id for the client to query.
// blockHeight can use `latest`, means make snapshot now
func (rpc *RPC) Snapshot(blockHeight interface{}) (string, StdError) {
	method := ARCHIVE + "snapshot"

	data, stdErr := rpc.call(method, blockHeight)
	if stdErr != nil {
		return "", stdErr
	}

	var result string

	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return "", NewSystemError(sysErr)
	}

	return result, nil
}

// QuerySnapshotExist checks if the given snapshot existed, so you can confirm that
// the last step Archive.Snapshot is successful.
func (rpc *RPC) QuerySnapshotExist(filterID string) (bool, StdError) {
	method := ARCHIVE + "querySnapshotExist"

	data, stdErr := rpc.call(method, filterID)
	if stdErr != nil {
		return false, stdErr
	}

	var result bool

	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return false, NewSystemError(sysErr)
	}

	return result, nil
}

// CheckSnapshot will check that the snapshot is correct. If correct, returns true.
// Otherwise, returns false.
func (rpc *RPC) CheckSnapshot(filterID string) (bool, StdError) {
	method := ARCHIVE + "checkSnapshot"

	data, stdErr := rpc.call(method, filterID)
	if stdErr != nil {
		return false, stdErr
	}

	var result bool

	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return false, NewSystemError(sysErr)
	}

	return result, nil
}

// DeleteSnapshot delete snapshot by id
func (rpc *RPC) DeleteSnapshot(filterID string) (bool, StdError) {
	method := ARCHIVE + "deleteSnapshot"

	data, stdErr := rpc.call(method, filterID)
	if stdErr != nil {
		return false, stdErr
	}

	var result bool

	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return false, NewSystemError(sysErr)
	}

	return result, nil
}

// ListSnapshot returns all the existed snapshot information.
func (rpc *RPC) ListSnapshot() (Manifests, StdError) {
	method := ARCHIVE + "listSnapshot"

	data, stdErr := rpc.call(method)
	if stdErr != nil {
		return nil, stdErr
	}

	var result Manifests
	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	return result, nil
}

// ReadSnapshot returns the snapshot information for the given snapshot ID.
func (rpc *RPC) ReadSnapshot(filterID string) (*Manifest, StdError) {
	method := ARCHIVE + "readSnapshot"

	data, stdErr := rpc.call(method, filterID)
	if stdErr != nil {
		return nil, stdErr
	}

	var result Manifest
	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	return &result, nil
}

// Archive will archive data of the given snapshot. If successful, returns true.
func (rpc *RPC) Archive(filterID string, sync bool) (bool, StdError) {
	method := ARCHIVE + "archive"

	data, stdErr := rpc.call(method, filterID, sync)
	if stdErr != nil {
		return false, stdErr
	}

	var result bool

	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return false, NewSystemError(sysErr)
	}

	return result, nil
}

// Restore restores datas that have been archived for given snapshot. If successful, returns true.
func (rpc *RPC) Restore(filterID string, sync bool) (bool, StdError) {
	method := ARCHIVE + "restore"

	data, stdErr := rpc.call(method, filterID, sync)
	if stdErr != nil {
		return false, stdErr
	}

	var result bool
	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return false, NewSystemError(sysErr)
	}

	return result, nil
}

// RestoreAll restores all datas that have been archived. If successful, returns true.
func (rpc *RPC) RestoreAll(sync bool) (bool, StdError) {
	method := ARCHIVE + "restoreAll"

	data, stdErr := rpc.call(method, sync)
	if stdErr != nil {
		return false, stdErr
	}

	var result bool
	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return false, NewSystemError(sysErr)
	}

	return result, nil
}

// QueryArchiveExist checks if the given snapshot has been archived.
func (rpc *RPC) QueryArchiveExist(filterID string) (bool, StdError) {
	method := ARCHIVE + "queryArchiveExist"

	data, stdErr := rpc.call(method, filterID)
	if stdErr != nil {
		return false, stdErr
	}

	var result bool

	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return false, NewSystemError(sysErr)
	}

	return result, nil
}

// Pending returns all pending snapshot requests in ascend sort.
func (rpc *RPC) Pending() ([]SnapshotEvent, StdError) {
	method := ARCHIVE + "pending"

	data, stdErr := rpc.call(method)
	if stdErr != nil {
		return nil, stdErr
	}

	var result []SnapshotEvent
	if sysErr := json.Unmarshal(data, &result); sysErr != nil {
		return nil, NewSystemError(sysErr)
	}

	return result, nil
}

/*---------------------------------- cert ----------------------------------*/

// GetTCert 获取TCert
// Deprecated:
func (rpc *RPC) GetTCert(index uint) (string, StdError) {
	return rpc.hrm.getTCert(rpc.hrm.nodes[index].url)
}

/*---------------------------------- account ----------------------------------*/

// GetBalance 获取账户余额
func (rpc *RPC) GetBalance(account string) (string, StdError) {
	account = chPrefix(account)
	method := ACCOUNT + "getBalance"
	param := account
	data, err := rpc.call(method, param)
	if err != nil {
		return "", err
	}

	var balance string
	if sysErr := json.Unmarshal(data, &balance); sysErr != nil {
		return "", NewSystemError(sysErr)
	}
	return balance, nil
}

/*---------------------------------- radar ----------------------------------*/

func (rpc *RPC) ListenContract(srcCode, addr string) (string, StdError) {
	method := RADAR + "registerContract"
	param := newMapParam("source", srcCode)
	param.addKV("addrsss", addr)

	data, err := rpc.call(method, param.Serialize())
	if err != nil {
		return "", err
	}

	return string(data), nil
}
