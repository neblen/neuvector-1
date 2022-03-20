package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/nvk8sapi/neuvectorcrd"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

var Host share.CLUSHost = share.CLUSHost{
	Platform: share.PlatformDocker,
}
var Ctrler, parentCtrler share.CLUSController

type ctrlEnvInfo struct {
	startsAt       time.Time
	procDir        string
	cgroupMemory   string
	cgroupCPUAcct  string
	runInContainer bool
	debugCPath     bool
}

// wys controller 10个全局变量
// wys Go语言在声明变量的时候，会自动对变量对应的内存区域进行初始化操作。每个变量会被初始化成其类型的默认值

var ctrlEnv ctrlEnvInfo
var exitingFlag int32

var evqueue cluster.ObjectQueueInterface
var auditQueue cluster.ObjectQueueInterface
var messenger cluster.MessengerInterface
var cacher cache.CacheInterface
var scanner scan.ScanInterface
var orchConnector orchConnInterface
var timerWheel *utils.TimerWheel

// const 变量名 类型 = 表达式
const statsInterval uint32 = 5

// 在golang中，很多方法接收的时间参数都是time.Duration类型 controllerStartGapThreshold 这个常量就是一个时间为2分钟的time.Duration类型
const controllerStartGapThreshold = time.Duration(time.Minute * 2)
const memoryRecyclePeriod uint32 = 10                     // minutes
const memControllerTopPeak uint64 = 4 * 512 * 1024 * 1024 // 2 GB (inc. allinone case)
const memSafeGap uint64 = 64 * 1024 * 1024                // 64 MB

// Unlike in enforcer, only read host IPs in host mode, so no need to enter host network namespace
func getHostModeHostIPs() {
	ifaces := global.SYS.GetGlobalAddrs(true)

	Ctrler.Ifaces = make(map[string][]share.CLUSIPAddr)
	for name, addrs := range ifaces {
		Ctrler.Ifaces[name] = []share.CLUSIPAddr{}
		for _, addr := range addrs {
			if utils.IsIPv4(addr.IP) {
				Ctrler.Ifaces[name] = append(Ctrler.Ifaces[name], share.CLUSIPAddr{
					IPNet: addr,
					Scope: share.CLUSIPAddrScopeNAT,
				})
			}
		}
	}
}

func getLocalInfo(selfID string, pid2ID map[int]string) error {
	host, err := global.RT.GetHost()
	if err != nil {
		return err
	}
	Host = *host
	Host.CgroupVersion = global.SYS.GetCgroupVersion()
	ctrlEnv.startsAt = time.Now().UTC()
	if ctrlEnv.runInContainer {
		dev, meta, err := global.RT.GetDevice(selfID)
		if err != nil {
			return err
		}
		Ctrler.CLUSDevice = *dev

		_, parent := global.RT.GetParent(meta, pid2ID)
		if parent != "" {
			dev, _, err = global.RT.GetDevice(parent)
			if err != nil {
				return err
			}
			parentCtrler.CLUSDevice = *dev
		}
	} else {
		Ctrler.ID = Host.ID
		Ctrler.Pid = os.Getpid()
		Ctrler.NetworkMode = "host"
		Ctrler.PidMode = "host"
		Ctrler.CreatedAt = time.Now()
		Ctrler.StartedAt = time.Now()
		getHostModeHostIPs()
	}
	Ctrler.HostID = Host.ID
	Ctrler.HostName = Host.Name
	Ctrler.Ver = Version

	ctrlEnv.cgroupMemory, _ = global.SYS.GetContainerCgroupPath(0, "memory")
	ctrlEnv.cgroupCPUAcct, _ = global.SYS.GetContainerCgroupPath(0, "cpuacct")
	return nil
}

// A heuristic way to decide if this is a new cluster installation.
// This is called right after the controller joins the cluster. If this is
// the oldest controller or the oldest controller started not very long before,
// It's likely all controllers starts together and this is a new cluster.
// 一种确定这是否是新集群安装的启发式方法。
// 这是在控制器加入集群后立即调用的。 如果这是
// 最旧的控制器或最旧的控制器在不久前启动，
// 很可能所有控制器都一起启动，这是一个新集群。
func likelyNewCluster() bool {
	clusHelper := kv.GetClusterHelper()
	all := clusHelper.GetAllControllers()

	if len(all) <= 1 {
		return true
	}

	var oldest *share.CLUSController
	for _, c := range all {
		if oldest == nil || c.StartedAt.Before(oldest.StartedAt) {
			oldest = c
		}
	}

	log.WithFields(log.Fields{"oldest": oldest.ID}).Info()

	if oldest.ID == Ctrler.ID {
		return true
	}

	// If all controllers start within the reasonable duration, consider them
	// to be starting together
	// 如果所有控制器都在合理的时间内启动，考虑它们
	// 一起开始
	if Ctrler.StartedAt.Sub(oldest.StartedAt) < controllerStartGapThreshold {
		return true
	}

	return false
}

func flushEventQueue() {
	evqueue.Flush()
	auditQueue.Flush()
	cacher.FlushAdmCtrlStats()
}

///
type localSystemInfo struct {
	mutex sync.Mutex
	stats share.ContainerStats
}

var gInfo localSystemInfo

func updateStats() {
	cpuSystem, _ := global.SYS.GetHostCPUUsage()
	mem, _ := global.SYS.GetContainerMemoryUsage(ctrlEnv.cgroupMemory)
	cpu, _ := global.SYS.GetContainerCPUUsage(ctrlEnv.cgroupCPUAcct)

	// 互斥锁是一种常用的控制共享资源访问的方法，它能够保证同一时间只有一个 goroutine 可以访问共享资源
	gInfo.mutex.Lock()
	system.UpdateStats(&gInfo.stats, mem, cpu, cpuSystem)
	gInfo.mutex.Unlock()
}

// utility functions for enforcer dispatcher
func isGroupMember(name, id string) bool {
	return cacher.IsGroupMember(name, id)
}

func getConfigKvData(key string) ([]byte, bool) {
	return cacher.GetConfigKvData(key)
}

// TODO: sidecar implementation might have two app pods
func adjustContainerPod(selfID string, containers []*container.ContainerMeta) string {
	for _, c := range containers {
		if v, ok := c.Labels["io.kubernetes.sandbox.id"]; ok {
			if v == selfID {
				log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Update")
				return c.ID
			}
		}
		if c.Sandbox != "" && c.Sandbox == selfID {
			log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Update")
			return c.ID
		}
	}
	return selfID
}

func main() {
	var joinAddr, advAddr, bindAddr string
	var err error

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "CTL"})

	connLog := log.New()
	connLog.Out = os.Stdout
	connLog.Level = log.InfoLevel
	connLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	scanLog := log.New()
	scanLog.Out = os.Stdout
	scanLog.Level = log.InfoLevel
	scanLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	mutexLog := log.New()
	mutexLog.Out = os.Stdout
	mutexLog.Level = log.InfoLevel
	mutexLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	log.WithFields(log.Fields{"version": Version}).Info("START")

	// bootstrap := flag.Bool("b", false, "Bootstrap cluster")
	//wys join is the svc address of the neuvector
	//wys 从命令行中读取相应的参数 如果没有读到则用默认值
	join := flag.String("j", "", "Cluster join address")
	adv := flag.String("a", "", "Cluster advertise address")
	bind := flag.String("b", "", "Cluster bind address")
	rtSock := flag.String("u", "", "Container socket URL")
	debug := flag.Bool("d", false, "Enable control path debug")
	restPort := flag.Uint("p", api.DefaultControllerRESTAPIPort, "REST API server port")
	fedPort := flag.Uint("fed_port", 11443, "Fed REST API server port")
	rpcPort := flag.Uint("rpc_port", 0, "Cluster server RPC port")
	lanPort := flag.Uint("lan_port", 0, "Cluster Serf LAN port")
	grpcPort := flag.Uint("grpc_port", 0, "Cluster GRPC port")
	internalSubnets := flag.String("n", "", "Predefined internal subnets")
	persistConfig := flag.Bool("pc", false, "Persist configurations")
	admctrlPort := flag.Uint("admctrl_port", 20443, "Admission Webhook server port")
	crdvalidatectrlPort := flag.Uint("crdvalidatectrl_port", 30443, "general crd Webhook server port")
	pwdValidUnit := flag.Uint("pwd_valid_unit", 1440, "")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
		scanLog.SetLevel(log.DebugLevel)
		ctrlEnv.debugCPath = true
	}
	if *join != "" {
		// Join addresses might not be all ready. Accept whatever input is, resolve them
		// when starting the cluster.
		// 连接地址可能还没有准备好。 接受任何输入，解决它们
		// 启动集群时。
		joinAddr = *join
		log.WithFields(log.Fields{"join": joinAddr}).Info()
	}
	if *adv != "" {
		ips, err := utils.ResolveIP(*adv)
		if err != nil || len(ips) == 0 {
			log.WithFields(log.Fields{"advertise": *adv}).Error("Invalid adv address. Exit!")
			os.Exit(-2)
		}

		advAddr = ips[0].String()
		log.WithFields(log.Fields{"advertise": advAddr}).Info()
	}
	if *bind != "" {
		bindAddr = *bind
		log.WithFields(log.Fields{"bind": bindAddr}).Info()
	}
	if *restPort > 65535 || *fedPort > 65535 || *rpcPort > 65535 || *lanPort > 65535 {
		log.Error("Invalid port value. Exit!")
		os.Exit(-2)
	}

	// Set global objects at the very first
	// wys 初始化对应的平台，网络，正在运行中的容器等信息
	// wys 同时初始化global包中的三个全局变量 SYS RT ORCH
	//var SYS *system.SystemTools
	//var RT container.Runtime
	//var ORCH *orchHub
	// global包的位置 /home/wys/code/sourcecode/neuvector/neuvector-5.0.0-preview.1/share/global/global.go
	platform, flavor, network, containers, err := global.SetGlobalObjects(*rtSock, resource.Register)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to initialize")
		os.Exit(-2)
	}
	// wys log: 2022-03-17T11:16:27.144|INFO|CTL|main.main: Container socket connected - endpoint= runtime=docker
	log.WithFields(log.Fields{"endpoint": *rtSock, "runtime": global.RT.String()}).Info("Container socket connected")
	if platform == share.PlatformKubernetes {
		k8sVer, ocVer := global.ORCH.GetVersion()
		// wys log: 2022-03-17T11:16:27.144|INFO|CTL|main.main: - k8s=1.20.10 oc=
		log.WithFields(log.Fields{"k8s": k8sVer, "oc": ocVer}).Info()
	}

	if _, err = global.ORCH.GetOEMVersion(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unsupported OEM platform. Exit!")
		os.Exit(-2)
	}

	var selfID string

	//wys 判断controller在容器内运行
	//wys func位置 /home/wys/code/sourcecode/neuvector/neuvector-5.0.0-preview.1/share/system/cgroup_linux.go
	ctrlEnv.runInContainer = global.SYS.IsRunningInContainer()
	if ctrlEnv.runInContainer {
		//wys 获取该容器的ID
		selfID, _, err = global.SYS.GetSelfContainerID()
		if selfID == "" {
			log.WithFields(log.Fields{"error": err}).Error("Unsupported system. Exit!")
			os.Exit(-2)
		}
	} else {
		log.Info("Not running in container.")
	}

	if platform == share.PlatformKubernetes {
		selfID = adjustContainerPod(selfID, containers)
	}

	// Container port can be injected after container is up. Wait for at least one.
	//wys 获取所有运行中的容器的Pid与containerId的映射关系
	//wys basic map类型的变量默认初始值为nil，需要使用make()函数来分配内存
	//wys basic make(map[KeyType]ValueType, [cap]) cap表示map的容量，该参数虽然不是必须的，但是我们应该在初始化map的时候就为其指定一个合适的容量。
	//wys basic 在Go语言中对于引用类型的变量，我们在使用的时候不仅要声明它，还要为它分配内存空间，否则我们的值就没办法存储。
	//wys basic 而对于值类型的声明不需要分配内存空间，是因为它们在声明的时候已经默认分配好了内存空间。
	//wys basic make也是用于内存分配的，区别于new，它只用于slice、map以及chan的内存创建，而且它返回的类型就是这三个类型本身，
	//wys basic 而不是他们的指针类型，因为这三种类型就是引用类型，所以就没有必要返回他们的指针了。
	pid2ID := make(map[int]string)
	for _, meta := range containers {
		if meta.Pid != 0 {
			pid2ID[meta.Pid] = meta.ID
		}
	}

	for {
		// Get local host and controller info
		// translate: 获取本地主机和控制器信息
		if err = getLocalInfo(selfID, pid2ID); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to get local device information")
			os.Exit(-2)
		}

		// wys len函数是Go语言中的内置函数
		// wys len函数作用是用于计算数组(包括数组指针)、切片(slice)、map、channel、字符串等数据类型的长度，注意，结构休(struct)、整型布尔等不能作为参数传给len函数。
		if len(Ctrler.Ifaces) > 0 {
			break
		}

		log.Info("Wait for local interface ...")
		time.Sleep(time.Second * 4)
	}

	Host.Platform = platform
	Host.Flavor = flavor
	Host.Network = network
	Host.StorageDriver = global.RT.GetStorageDriver()

	//wys 获取controller的namespace
	Ctrler.Domain = global.ORCH.GetDomain(Ctrler.Labels)
	parentCtrler.Domain = global.ORCH.GetDomain(parentCtrler.Labels)
	resource.NvAdmSvcNamespace = Ctrler.Domain
	if platform == share.PlatformKubernetes {
		resource.AdjustAdmWebhookName()
	}

	// Assign controller interface/IP scope
	// translate:分配控制器接口/IP 范围
	if ctrlEnv.runInContainer {
		networks, err := global.RT.ListNetworks()
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error reading container networks")
			os.Exit(-2)
		}

		meta := container.ContainerMeta{
			ID:      Ctrler.ID,
			Name:    Ctrler.Name,
			NetMode: Ctrler.NetworkMode,
			Labels:  Ctrler.Labels,
		}
		global.ORCH.SetIPAddrScope(Ctrler.Ifaces, &meta, networks)
	}

	log.WithFields(log.Fields{"host": Host}).Info("")
	log.WithFields(log.Fields{"ctrler": Ctrler}).Info("")

	// Other objects
	//hml 创建一个1h的时间轮,延时执行
	timerWheel = utils.NewTimerWheel()
	timerWheel.Start()

	dev := &common.LocalDevice{
		Host:   &Host,
		Ctrler: &Ctrler,
	}

	eventLogKey := share.CLUSControllerEventLogKey(Host.ID, Ctrler.ID)
	// wys evqueue全局变量初始化
	evqueue = cluster.NewObjectQueue(eventLogKey, cluster.DefaultMaxQLen)
	// wys note go中 = 是赋值， := 是声明变量并赋值。
	auditLogKey := share.CLUSAuditLogKey(Host.ID, Ctrler.ID)
	// wys auditQueue全局变量初始化
	auditQueue = cluster.NewObjectQueue(auditLogKey, 128)
	// wys messenger全局变量初始化
	messenger = cluster.NewMessenger(Host.ID, Ctrler.ID)

	//hml 感觉是初始化规则信息(比如group信息，文件访问信息，进程信息等)
	// ======== yyihuiyanjiu
	// 初始化config.go 中 clusHelper clusHelperImpl cfgHelper
	kv.Init(Ctrler.ID, dev.Ctrler.Ver, Host.Platform, Host.Flavor, *persistConfig, isGroupMember, getConfigKvData)
	// 初始化rule_uuid.go 中 uuidProcCache结构体指针
	ruleid.Init()

	// Start cluster
	clusterCfg := &cluster.ClusterConfig{
		ID:            Ctrler.ID,
		Server:        true,
		Debug:         false,
		Ifaces:        Ctrler.Ifaces,
		JoinAddr:      joinAddr,
		AdvertiseAddr: advAddr,
		BindAddr:      bindAddr,
		RPCPort:       *rpcPort,
		LANPort:       *lanPort,
		DataCenter:    cluster.DefaultDataCenter,
		EnableDebug:   *debug,
	}
	self, lead, err := clusterStart(clusterCfg)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Failed to start cluster. Exit!")
		os.Exit(-2)
	}

	Ctrler.Leader = (lead == self)
	Ctrler.ClusterIP = self
	if Ctrler.Leader {
		recordLeadChangeEvent(share.CLUSEvControllerLeadElect, lead, "")
	}

	// get grpc port before put controller info to cluster
	var grpcServer *cluster.GRPCServer
	if *grpcPort == 0 {
		*grpcPort = cluster.DefaultControllerGRPCPort
	}
	Ctrler.RPCServerPort = uint16(*grpcPort)

	//hml related to consul
	//wys 将Ctrler信息存到consul中并带上此时的国际标准时间
	ctlrPutLocalInfo()

	// In the normal cases, initial deployment, rolling upgrade, if the controller starts as the leader
	// it means this is the initial deployment case and it is the first controller; however, in the case
	// when 2 of 3 controllers are lost, it's possible one of two new controllers can be elected
	// as the lead.
	// 正常情况下，初始部署，滚动升级，如果控制器作为leader启动
	// 这意味着这是初始部署案例，它是第一个控制器； 但是，在这种情况下
	// 当 3 个控制器中的 2 个丢失时，可能会选出两个新控制器之一
	// 作为主角。

	// Considerations:
	// - We trust the KV store can resolve the stored KV correctly and consistently;
	// - For the new controller as leader at startup (following logic), it's OK to restore the config
	// even there might be other controllers are much older.
	// - SyncInit() is to sync in-memory data, such as graph. Sync from the oldest controller. The new
	// lead should perform sync as well unless it's a new cluster installation.
	// - Wait until initial sync is done to start calculating policies. Policy calculation is based on
	// in-memory graph.
	// - When a controller becomes leader, it's OK to do a full backup, because backup is to copy data
	// from the KV store to the files.
	// - When a controller becomes leader, it should NOT sync policy from the memory to the KV store,
	// because we are not sure if graph is all synced. It doesn't seem necessary either.
	// - When the cluster leader is re-elected and there was a leader-loss for at least a short period, we
	// call CtrlFailRecovery(). Sync from the lead controller but only if it has run a while, this is
	// important because the new leader maybe just started and does not possess the graph data.
	//注意事项：
	// - 我们相信 KV 存储可以正确且一致地解析存储的 KV；
	// - 对于启动时作为leader的新控制器（遵循逻辑），恢复配置就可以了
	// 甚至可能还有其他控制器更老。
	// - SyncInit() 用于同步内存中的数据，例如图形。 从最旧的控制器同步。 新的
	// 除非是新的集群安装，否则领导也应该执行同步。
	// - 等待初始同步完成以开始计算策略。 策略计算基于
	// 内存图。
	// - 当一个controller成为leader后，做full backup就可以了，因为backup就是复制数据
	// 从 KV 存储到文件。
	// - 当控制器成为领导者时，它不应该将策略从内存同步到 KV 存储，
	// 因为我们不确定图形是否全部同步。 似乎也没有必要。
	// - 当集群领导者重新选举并且领导者丢失至少很短的时间时，我们
	// 调用 CtrlFailRecovery()。 从主控制器同步，但前提是它已经运行了一段时间，这是
	// 很重要，因为新的领导者可能刚刚开始并且没有图表数据。

	// 判断是否是新的集群
	isNewCluster := likelyNewCluster()

	log.WithFields(log.Fields{"ctrler": Ctrler, "lead": lead, "self": self, "new-cluster": isNewCluster}).Info()

	purgeFedRulesOnJoint := false
	if Ctrler.Leader {
		// See [NVSHAS-5490]:
		// clusterHelper.AcquireLock() may fail with error "failed to create session: Unexpected response code: 500 (Missing node registration)".
		// It indicates that the node is not yet registered in the catalog.
		// It's possibly because controller attempts to create a session immediately after starting Consul but actually Consul is not ready yet.
		// Even it's rare, we might need to allow Consul some time to initialize and sync the node registration to the catalog.
		// 表示该节点还没有在目录中注册。
		// 这可能是因为控制器在启动 Consul 后立即尝试创建会话，但实际上 Consul 还没有准备好。
		// 即使很少见，我们可能需要给 Consul 一些时间来初始化和同步节点注册到目录。
		clusHelper := kv.GetClusterHelper()
		for i := 0; i < 6; i++ {
			lock, err := clusHelper.AcquireLock(share.CLUSLockUpgradeKey, time.Duration(time.Second))
			if err != nil {
				log.WithFields(log.Fields{"i": i, "err": err}).Info("retry for session creation")
				time.Sleep(time.Second)
				continue
			}
			clusHelper.ReleaseLock(lock)
			break
		}

		// Initiate installation ID if the controller is the first, ignore if ID is already set.
		// 如果控制器是第一个，则启动安装 ID，如果已设置 ID，则忽略。
		clusHelper.PutInstallationID()

		// Restore persistent config.
		// Calling restore is unnecessary if this is not a new cluster installation, but not a big issue,
		// assuming the PV should have the latest config.
		// 恢复持久化配置。
		// 如果这不是新的集群安装，则无需调用 restore，但不是大问题，
		// 假设 PV 应该有最新的配置。
		fedRole, _ := kv.GetConfigHelper().Restore()
		// wys ==号 直接判断字符串是否相等
		if fedRole == api.FedRoleJoint {
			// fed rules are not restored on joint cluster but there might be fed rules left in kv so
			// 	we need to clean up fed rules & revisions in kv
			// if not using persist storage, the returned fedRole is always empty string
			// 馈送规则不会在联合集群上恢复，但可能有馈送规则留在 kv 中所以
			// 我们需要清理 kv 中的馈送规则和修订
			// 如果不使用持久存储，则返回的 fedRole 始终为空字符串
			purgeFedRulesOnJoint = true
		}

		if *internalSubnets != "" {
			// basic: strings.Split函数用于将指定的分隔符切割字符串，并返回切割后的字符串切片
			// basic: strings.Split(s, sep)
			// basic: s	待分割的字符串 字符串类型的参数
			// basic: sep 分隔符 字符串类型的参数
			subnets := strings.Split(*internalSubnets, ",")
			for _, subnet := range subnets {
				if _, _, err := net.ParseCIDR(subnet); err != nil {
					log.WithFields(log.Fields{"subnet": subnet}).Error("Invalid format!")
					os.Exit(-2)
				}
			}
			cfg := common.DefaultSystemConfig
			cfg.InternalSubnets = subnets

			clusHelper.PutSystemConfigRev(&cfg, 0)
		}
	}

	// All controllers start at same time in a new cluster. Because the lead load the PV,
	// non-lead can get here first and upgrade the KV. The sequence is not correct.
	// So, for the new cluster, we only want the lead to upgrade the KV. In the rolling
	// upgrade case, (not new cluster), the new controller (not a lead) should upgrade
	// the KV so it can behave correctly. The old lead won't be affected, in theory.
	// 所有控制器在新集群中同时启动。 因为lead负载PV，
	// 非lead可以先到这里升级KV。 顺序不正确。
	// 所以，对于新的集群，我们只希望leader升级KV。 在滚动中
	// 升级情况，（不是新集群），新控制器（不是领导）应该升级
	// KV，以便它可以正确运行。 理论上，旧的lead不会受到影响。
	if Ctrler.Leader || !isNewCluster {
		kv.GetClusterHelper().UpgradeClusterKV()
		kv.GetClusterHelper().FixMissingClusterKV()
	}

	if Ctrler.Leader {
		kv.ValidateWebhookCert()
		setConfigLoaded()
	} else {
		// The lead can take some time to restore the PV. Synchronize here so when non-lead
		// read from the KV, such as policy list, it knows the data is complete.
		// 线索可能需要一些时间来恢复 PV。 同步这里所以当非铅
		// 从KV中读取，比如policy list，就知道数据是完整的。
		waitConfigLoaded(isNewCluster)
		kv.ValidateWebhookCert()
	}

	// pre-build compliance map
	//hml 将合规性的报告提前读入内存
	common.GetComplianceMeta()

	// start orchestration connection.
	// orchConnector should be created before LeadChangeCb is registered.
	// 开始编排连接。
	// orchConnector 应该在注册 LeadChangeCb 之前创建。
	orchObjChan := make(chan *resource.Event, 32)
	orchScanChan := make(chan *resource.Event, 16)

	// Initialize cache
	// - Start policy learning thread and build learnedPolicyRuleWrapper from KV
	// 初始化缓存
	// - 启动策略学习线程并从 KV 构建learnedPolicyRuleWrapper
	cctx := cache.Context{
		LocalDev:                 dev,
		EvQueue:                  evqueue,
		AuditQueue:               auditQueue,
		Messenger:                messenger,
		OrchChan:                 orchObjChan,
		TimerWheel:               timerWheel,
		DebugCPath:               ctrlEnv.debugCPath,
		ConnLog:                  connLog,
		MutexLog:                 mutexLog,
		ScanLog:                  scanLog,
		StartFedRestServerFunc:   rest.StartFedRestServer,
		StopFedRestServerFunc:    rest.StopFedRestServer,
		StartStopFedPingPollFunc: rest.StartStopFedPingPoll,
	}
	//hml 初始化cache信息
	//wys location:/home/wys/code/sourcecode/neuvector/neuvector-5.0.0-preview.1/controller/cache/cache.go
	cacher = cache.Init(&cctx, Ctrler.Leader, lead)
	cache.ScannerChangeNotify(Ctrler.Leader)

	sctx := scan.Context{
		AuditQueue: auditQueue,
		ScanChan:   orchScanChan,
		TimerWheel: timerWheel,
		MutexLog:   mutexLog,
		ScanLog:    scanLog,
	}
	//hml 初始化扫描的registry仓库信息,
	scanner = scan.Init(&sctx, Ctrler.Leader)
	scan.ScannerChangeNotify(Ctrler.Leader)

	// Orch connector should be started after cacher so the listeners are ready
	// Orch 连接器应该在缓存器之后启动，以便监听器准备好
	orchConnector = newOrchConnector(orchObjChan, orchScanChan, Ctrler.Leader)
	orchConnector.Start()
	if dev.Host.Platform == share.PlatformKubernetes && dev.Host.Flavor == share.FlavorOpenShift {
		resource.AdjustAdmResForOC()
	}

	// GRPC should be started after cacher as the handler are cache functions
	// GRPC 应该在缓存器之后启动，因为处理程序是缓存函数
	grpcServer, _ = startGRPCServer(uint16(*grpcPort))

	// init rest server context before listening KV object store, as federation server can be started from there.
	// 在监听 KV 对象存储之前初始化休息服务器上下文，因为联邦服务器可以从那里启动。
	rctx := rest.Context{
		LocalDev:     dev,
		EvQueue:      evqueue,
		AuditQueue:   auditQueue,
		Messenger:    messenger,
		Cacher:       cacher,
		Scanner:      scanner,
		RESTPort:     *restPort,
		FedPort:      *fedPort,
		PwdValidUnit: *pwdValidUnit,
	}
	rest.InitContext(&rctx)

	// Registry cluster event handlers
	// 注册集群事件处理程序
	cluster.RegisterLeadChangeWatcher(leadChangeHandler, lead)
	//hml 查看节点集群的状态 需要和consul结合
	cluster.RegisterNodeWatcher(ctlrMemberUpdateHandler)

	// Sync follows the lead so must be after leadChangeHandler registered.
	// 同步跟随lead，所以必须在leadChangeHandler 注册之后。
	//hml 同步lead信息
	cache.SyncInit(isNewCluster)

	//hml 注册对应的存储对象和更新的操作
	//wys 注册三种StoreWatcher 一种StateWatcher
	//wys 这是一个watcher函数  监控的地址有变化  就会执行回调函数
	//wys 函数位置 /home/wys/code/sourcecode/neuvector/neuvector-5.0.0-preview.1/share/cluster/intfs.go
	cluster.RegisterStoreWatcher(share.CLUSObjectStore, cache.ObjectUpdateHandler, false)
	cluster.RegisterStateWatcher(cache.ClusterMemberStateUpdateHandler)
	cluster.RegisterStoreWatcher(share.CLUSScannerStore, cache.ScannerUpdateHandler, false)
	cluster.RegisterStoreWatcher(share.CLUSScanStateStore, cache.ScanUpdateHandler, false)

	if m := kv.GetClusterHelper().GetFedMembership(); m != nil {
		access.UpdateUserRoleForFedRoleChange(m.FedRole)
	}

	// start rest server
	rest.LoadInitCfg(Ctrler.Leader) // Load config from ConfigMap

	nvcrd.Init(Ctrler.Leader)
	// To prevent crd webhookvalidating timeout need queue the crd and process later.
	// 为了防止 crd webhookvalidating timeout 需要排队 crd 并稍后处理。
	go rest.CrdQueueProc()
	go rest.StartRESTServer()

	if platform == share.PlatformKubernetes {
		rest.LeadChangeNotify(Ctrler.Leader)
		if Ctrler.Leader {
			//sync the neuvector admission control to k8s admission control
			//将neuvector准入控制同步到k8s准入控制
			cacher.SyncAdmCtrlStateToK8s(resource.NvAdmSvcName, resource.NvAdmValidatingName)
		}
		go rest.CleanupSessCfgCache()
		//sync the admission webhook in neuvector to k8s
		//将neuvector中的admission webhook同步到k8s
		go rest.AdmissionRestServer(*admctrlPort, false, *debug)
		go rest.CrdValidateRestServer(*crdvalidatectrlPort, false, *debug)
	}

	go rest.FedPollingClient(Ctrler.Leader, purgeFedRulesOnJoint)

	// make(chan 元素类型, [缓冲大小])
	// 创建一个容量为1的有缓冲区通道
	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	logController(share.CLUSEvControllerStart)
	logController(share.CLUSEvControllerJoin)

	go func() {
		var memStatsControllerResetMark uint64 = memControllerTopPeak - memSafeGap

		// time.Ticker 结构体，这个对象以指定的时间间隔重复的向通道 C 发送时间值
		// func Tick(d Duration) <-chan Time
		ticker := time.Tick(time.Second * time.Duration(5))
		memStatTicker := time.Tick(time.Minute * time.Duration(memoryRecyclePeriod))
		statsTicker := time.Tick(time.Second * time.Duration(statsInterval))

		if limit, err := global.SYS.GetContainerMemoryLimitUsage(ctrlEnv.cgroupMemory); err == nil {
			if limit/2 > memSafeGap {
				memStatsControllerResetMark = limit/2 - memSafeGap
			}
			log.WithFields(log.Fields{"Limit": limit, "Controlled_At": memStatsControllerResetMark}).Info("Memory Resource")
		}

		// for allinone and controller
		// 用于 allinone 和控制器
		go global.SYS.MonitorMemoryPressureEvents(memStatsControllerResetMark, memoryPressureNotification)
		for {
			select {
			case <-ticker:
				// When cluster has no lead, write to the cluster fails silently
				// 当集群没有lead时，写入集群会静默失败
				if !clusterFailed {
					flushEventQueue()
				}
			case <-statsTicker:
				updateStats()
			case <-memStatTicker:
				global.SYS.ReCalculateMemoryMetrics(memStatsControllerResetMark)
			case <-c_sig:
				logController(share.CLUSEvControllerStop)
				flushEventQueue()
				done <- true
			}
		}
	}()

	<-done

	log.Info("Exiting ...")
	atomic.StoreInt32(&exitingFlag, 1)

	cache.Close()
	orchConnector.Close()
	ctrlDeleteLocalInfo()
	cluster.LeaveCluster(true)
	grpcServer.Stop()
}
