package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/pipe"
	"github.com/neuvector/neuvector/agent/probe"
	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const goroutineStackSize = 1024 * 1024

var containerTaskExitChan chan interface{} = make(chan interface{}, 1)
var errRestartChan chan interface{} = make(chan interface{}, 1)
var restartChan chan interface{} = make(chan interface{}, 1)
var monitorExitChan chan interface{} = make(chan interface{}, 1)

var Host share.CLUSHost = share.CLUSHost{
	Platform: share.PlatformDocker,
	Network:  share.NetworkDefault,
}
var Agent, parentAgent share.CLUSAgent
var agentEnv AgentEnvInfo

var evqueue cluster.ObjectQueueInterface
var messenger cluster.MessengerInterface
var agentTimerWheel *utils.TimerWheel
var prober *probe.Probe
var bench *Bench
var grpcServer *cluster.GRPCServer
var scanUtil *scanUtils.ScanUtil
var fileWatcher *fsmon.FileWatch

var connLog *log.Logger = log.New()
var nvSvcPort, nvSvcBrPort string
var driver string
var exitingFlag int32
var exitingTaskFlag int32

var walkerTask *workerlet.Tasker

func shouldExit() bool {
	return (atomic.LoadInt32(&exitingFlag) != 0)
}

func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func isAgentContainer(id string) bool {
	return id == Agent.ID || id == parentAgent.ID
}

func getHostIPs() {
	addrs := getHostAddrs()
	Host.Ifaces, gInfo.hostIPs, gInfo.jumboFrameMTU = parseHostAddrs(addrs, Host.Platform, Host.Network)
	if tun := global.ORCH.GetHostTunnelIP(addrs); tun != nil {
		Host.TunnelIP = tun
	}

	if global.ORCH.ConsiderHostsAsInternal() {
		addHostSubnets(Host.Ifaces, gInfo.localSubnetMap)
	}
	mergeLocalSubnets(gInfo.internalSubnets)
}

func getLocalInfo(selfID string, pid2ID map[int]string) error {
	host, err := global.RT.GetHost()
	if err != nil {
		return err
	}
	Host = *host
	Host.CgroupVersion = global.SYS.GetCgroupVersion()

	getHostIPs()

	if networks, err := global.RT.ListNetworks(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error reading container networks")
	} else {
		gInfo.networks = networks
	}

	agentEnv.startsAt = time.Now().UTC()
	if agentEnv.runInContainer {
		dev, meta, err := global.RT.GetDevice(selfID)
		if err != nil {
			return err
		}
		Agent.CLUSDevice = *dev

		_, parent := global.RT.GetParent(meta, pid2ID)
		if parent != "" {
			dev, _, err := global.RT.GetDevice(parent)
			if err != nil {
				return err
			}
			parentAgent.CLUSDevice = *dev
			if parentAgent.PidMode == "host" {
				Agent.PidMode = "host"
			}
		}
	} else {
		Agent.ID = Host.ID
		Agent.Pid = os.Getpid()
		Agent.NetworkMode = "host"
		Agent.PidMode = "host"
		Agent.SelfHostname = Host.Name
		Agent.Ifaces = Host.Ifaces
	}
	Agent.HostName = Host.Name
	Agent.HostID = Host.ID
	Agent.Ver = Version

	agentEnv.cgroupMemory, _ = global.SYS.GetContainerCgroupPath(0, "memory")
	agentEnv.cgroupCPUAcct, _ = global.SYS.GetContainerCgroupPath(0, "cpuacct")
	return nil
}

// Sort existing containers, move containers share network ns to other containers to the front.
// Only need to consider containers in the set, not those already exist.
//对现有容器进行排序，将共享网络ns的容器移动到其他容器的前面。
//只需要考虑集合中的容器，而不是已经存在的容器。
func sortContainerByNetMode(ids utils.Set) []*container.ContainerMetaExtra {
	sorted := make([]*container.ContainerMetaExtra, 0, ids.Cardinality())
	for id := range ids.Iter() {
		if info, err := global.RT.GetContainer(id.(string)); err == nil {
			sorted = append(sorted, info)
		}
	}

	return container.SortContainers(sorted)
}

// Sort existing containers, move containers share network ns to other containers to the front.
// Only for Container Start from Probe channel
//对现有容器进行排序，将共享网络ns的容器移动到其他容器的前面。
//仅用于容器从探测通道启动
func sortProbeContainerByNetMode(starts utils.Set) []*container.ContainerMetaExtra {
	sorted := make([]*container.ContainerMetaExtra, 0, starts.Cardinality())
	for start := range starts.Iter() {
		s := start.(*share.ProbeContainerStart)
		if info, err := global.RT.GetContainer(s.Id); err == nil {
			if info.Running && info.Pid == 0 { // cri-o: fault-tolerent for http channel errors
				info.Pid = s.RootPid_alt
				log.WithFields(log.Fields{"id": s.Id, "rootPid": info.Pid}).Debug("PROC: Update")
			}
			sorted = append(sorted, info)
		}
	}

	return container.SortContainers(sorted)
}

// Enforcer cannot run together with enforcer.
// With SDN, enforcer can run together with controller; otherwise, port conflict will prevent them from running.
// Enforcer不能与Enforcer同时运行。
//有了SDN, enforcer可以和controller一起运行;否则，端口冲突将导致无法运行。
func checkAntiAffinity(containers []*container.ContainerMeta, skips ...string) error {
	skipSet := utils.NewSet()
	for _, skip := range skips {
		skipSet.Add(skip)
	}

	for _, c := range containers {
		if skipSet.Contains(c.ID) {
			continue
		}

		if v, ok := c.Labels[share.NeuVectorLabelRole]; ok {
			if strings.Contains(v, share.NeuVectorRoleEnforcer) {
				return fmt.Errorf("Must not run with another enforcer")
			}
		}
	}
	return nil
}

func cbRerunKube(cmd, cmdRemap string) {
	if Host.CapKubeBench {
		bench.RerunKube(cmd, cmdRemap)
	}
}

func waitContainerTaskExit() {
	// Wait for container task gorouting exiting and container ports' are restored.
	// If clean-up doesn't star, it's possible that container task queue get stuck.
	// In that case, call clean-up function directly and move forward. If the clean-up
	// already started, keep waiting.
	//等待容器任务gorouting exit，并恢复容器端口。
	//如果清理没有启动，它可能是容器的任务队列卡住。
	//在这种情况下，直接调用清理函数并向前移动。如果清理
	//已经启动，继续等待。
	for {
		select {
		case <-containerTaskExitChan:
			return
		case <-time.After(time.Second * 4):
			if atomic.LoadInt32(&exitingTaskFlag) == 0 {
				containerTaskExit()
				return
			}
		}
	}
}

func dumpGoroutineStack() {
	log.Info("Enforcer goroutine stack")
	buf := make([]byte, goroutineStackSize)
	bytes := runtime.Stack(buf, true)
	if bytes > 0 {
		log.Printf("%s", buf[:bytes])
	}
}

// TODO: sidecar implementation might have two app pods
//idecar的实现可能有两个app pods
func adjustContainerPod(selfID string, containers []*container.ContainerMeta) string {
	for _, c := range containers {
		if v, ok := c.Labels["io.kubernetes.sandbox.id"]; ok {
			if v == selfID {
				log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Update")
				return c.ID
			}
		}

		if c.Sandbox != c.ID { // a child
			if c.Sandbox == selfID {
				log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Update ")
				return c.ID
			}
		}
	}
	return selfID
}

func main() {
	var joinAddr, advAddr, bindAddr string
	var err error

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "AGT"})

	connLog.Out = os.Stdout
	connLog.Level = log.InfoLevel
	connLog.Formatter = &utils.LogFormatter{Module: "AGT"}

	log.WithFields(log.Fields{"version": Version}).Info("START")

	// log_file, log_err := os.OpenFile(LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	// if log_err == nil {
	//	  log.SetOutput(log_file)
	//    defer log_file.close()
	// }

	withCtlr := flag.Bool("c", false, "Coexist controller and ranger")
	debug := flag.Bool("d", false, "Enable control path debug")
	join := flag.String("j", "", "Cluster join address")
	adv := flag.String("a", "", "Cluster advertise address")
	bind := flag.String("b", "", "Cluster bind address")
	rtSock := flag.String("u", "", "Container socket URL")
	lanPort := flag.Uint("lan_port", 0, "Cluster Serf LAN port")
	grpcPort := flag.Uint("grpc_port", 0, "Cluster GRPC port")
	pipeType := flag.String("p", "", "Pipe driver")
	cnet_type := flag.String("n", "", "Container Network type")
	skip_nvProtect := flag.Bool("s", false, "Skip NV Protect")
	show_monitor_trace := flag.Bool("m", false, "Show process/file monitor traces")
	disable_kv_congest_ctl := flag.Bool("no_kvc", false, "disable kv congestion control")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
		gInfo.agentConfig.Debug = []string{"ctrl"}
	}

	agentEnv.kvCongestCtrl = true
	if *disable_kv_congest_ctl {
		log.Info("KV congestion control is disabled")
		agentEnv.kvCongestCtrl = false
	}

	if *join != "" {
		// Join addresses might not be all ready. Accept whatever input is, resolve them
		// when starting the cluster.
		/*
			addrs := utils.ResolveJoinAddr(*join)
			if addrs == "" {
				log.WithFields(log.Fields{"join": *join}).Error("Invalid join address. Exit!")
				os.Exit(-2)
			}
		*/
		joinAddr = *join
	}
	if *adv != "" {
		ips, err := utils.ResolveIP(*adv)
		if err != nil || len(ips) == 0 {
			log.WithFields(log.Fields{"advertise": *adv}).Error("Invalid join address. Exit!")
			os.Exit(-2)
		}

		advAddr = ips[0].String()
	}
	if *bind != "" {
		bindAddr = *bind
		log.WithFields(log.Fields{"bind": bindAddr}).Info()
	}

	// Set global objects at the very first//example:
	//	//2022-02-09T06:10:35.544|INFO|AGT|container.Connect: - endpoint=
	//	//2022-02-09T06:10:35.544|INFO|AGT|container._connect: Connecting to docker - endpoint=unix:///var/run/docker.sock
	//	//2022-02-09T06:10:35.557|INFO|AGT|container._connect: docker connected - endpoint=unix:///var/run/docker.sock version=&{ApiVersion:1.41 Arch:amd64 GitCommit:459d0df GoVersion:go1.16.12 KernelVersion:3.10.0-1160.49.1.el7.x86_64 Os:linux Version:20.10.12}
	//	//2022-02-09T06:10:35.58 |INFO|AGT|container._connect: - version=&{ApiVersion:1.41 Arch:amd64 GitCommit:459d0df GoVersion:go1.16.12 KernelVersion:3.10.0-1160.49.1.el7.x86_64 Os:linux Version:20.10.12}
	platform, flavor, network, containers, err := global.SetGlobalObjects(*rtSock, nil)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to initialize")
		os.Exit(-2)
	}

	walkerTask = workerlet.NewWalkerTask(false, global.SYS)

	log.WithFields(log.Fields{"endpoint": *rtSock, "runtime": global.RT.String()}).Info("Container socket connected")
	if platform == share.PlatformKubernetes {
		k8sVer, ocVer := global.ORCH.GetVersion()
		log.WithFields(log.Fields{"k8s": k8sVer, "oc": ocVer}).Info()
	}

	var selfID string
	agentEnv.runWithController = *withCtlr
	agentEnv.runInContainer = global.SYS.IsRunningInContainer()
	if agentEnv.runInContainer {
		selfID, agentEnv.containerInContainer, err = global.SYS.GetSelfContainerID()
		if selfID == "" { // it is a POD ID in the k8s cgroup v2; otherwise, a real container ID
			log.WithFields(log.Fields{"error": err}).Error("Unsupported system. Exit!")
			os.Exit(-2)
		}
		//容器保护模式
		agentEnv.containerShieldMode = (!*skip_nvProtect)
		//2022-02-09T06:10:36.235|INFO|AGT|main.main: PROC: - shield=true
		log.WithFields(log.Fields{"shield": agentEnv.containerShieldMode}).Info("PROC:")
	} else {
		log.Info("Not running in container.")
	}

	if platform == share.PlatformKubernetes {
		selfID = adjustContainerPod(selfID, containers)
	}
	//当容器up后，可以注入容器端口。至少等待一次。
	// Container port can be injected after container is up. Wait for at least one.
	pid2ID := make(map[int]string)
	for _, meta := range containers {
		if meta.Pid != 0 {
			pid2ID[meta.Pid] = meta.ID
		}
	}

	for {
		// Get local host and agent info
		//获取本地主机和代理信息
		// example:
		//|INFO|AGT|main.parseHostAddrs: link - flags=up|broadcast|multicast link=docker0 mtu=1500 type=bridge
		//2022-02-09T06:10:36.244|INFO|AGT|main.parseHostAddrs: Switch - ipnet={IP:172.17.0.1 Mask:ffff0000} link=docker0
		//2022-02-09T06:10:36.244|INFO|AGT|main.parseHostAddrs: link - flags=up|broadcast|multicast link=cali4129a0581dd mtu=1440 type=veth
		//2022-02-09T06:10:36.244|INFO|AGT|main.parseHostAddrs: link - flags=up|broadcast|multicast link=cali563a06a87c3 mtu=1440 type=veth
		//2022-02-09T06:10:36.244|INFO|AGT|main.parseHostAddrs: link - flags=up|broadcast|multicast link=cali886242786f6 mtu=1440 type=veth
		//2022-02-09T06:10:36.244|INFO|AGT|main.parseHostAddrs: link - flags=up|broadcast|multicast link=eth0 mtu=1500 type=device
		//2022-02-09T06:10:36.244|INFO|AGT|main.parseHostAddrs: Global - ipnet={IP:192.168.0.114 Mask:ffffff00} link=eth0
		//2022-02-09T06:10:36.244|INFO|AGT|main.parseHostAddrs: link - flags=up|loopback link=lo mtu=65536 type=device
		//2022-02-09T06:10:36.244|INFO|AGT|main.parseHostAddrs: - maxMTU=1500
		if err = getLocalInfo(selfID, pid2ID); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to get local device information")
			os.Exit(-2)
		}

		if len(Agent.Ifaces) > 0 {
			break
		}

		log.Info("Wait for local interface ...")
		time.Sleep(time.Second * 4)
	}

	// Check anti-affinity
	// 反亲和性检查
	var retry int
	retryDuration := time.Duration(time.Second * 2)
	for {
		err = checkAntiAffinity(containers, Agent.ID, parentAgent.ID)
		if err != nil {
			// Anti affinity check failure might be because the old enforcer is not stopped yet.
			// This can happen when user switches from an enforcer to an allinone on the same host.
			// Will wait and retry instead of quit to tolerate the timing issue.
			// Also if this enforcer is inside an allinone, the controller can still work correctly.
			//反亲和性检查失败可能是因为旧的enforcer还没有停止。
			//当用户在同一主机上从enforcer切换到allinone时，会发生这种情况。
			//将等待和重试而不是退出，以容忍时间问题。
			//如果这个强制执行器在allinone中，控制器仍然可以正常工作。
			retry++
			if retry == 10 {
				retryDuration = time.Duration(time.Second * 30)
				log.Info("Will retry affinity check every 30 seconds")
			}
			time.Sleep(retryDuration)

			// List only running containers
			containers, err = global.RT.ListContainers(true)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to list containers")
				os.Exit(-2)
			}
		} else {
			break
		}
	}

	Host.Platform = platform
	Host.Flavor = flavor
	Host.Network = network
	Host.CapDockerBench = (global.RT.String() == container.RuntimeDocker)
	Host.CapKubeBench = global.ORCH.SupportKubeCISBench()

	Agent.Domain = global.ORCH.GetDomain(Agent.Labels)
	parentAgent.Domain = global.ORCH.GetDomain(parentAgent.Labels)

	policyInit()

	// Assign agent interface/IP scope
	if agentEnv.runInContainer {
		meta := container.ContainerMeta{
			ID:      Agent.ID,
			Name:    Agent.Name,
			NetMode: Agent.NetworkMode,
			Labels:  Agent.Labels,
		}
		global.ORCH.SetIPAddrScope(Agent.Ifaces, &meta, gInfo.networks)
	}

	Host.StorageDriver = global.RT.GetStorageDriver()
	log.WithFields(log.Fields{"hostIPs": gInfo.hostIPs}).Info("")
	log.WithFields(log.Fields{"host": Host}).Info("")
	log.WithFields(log.Fields{"agent": Agent}).Info("")

	// Other objects
	eventLogKey := share.CLUSAgentEventLogKey(Host.ID, Agent.ID)
	evqueue = cluster.NewObjectQueue(eventLogKey, cluster.DefaultMaxQLen)
	messenger = cluster.NewMessenger(Host.ID, Agent.ID)

	//var driver string
	if *pipeType == "ovs" {
		driver = pipe.PIPE_OVS
	} else if *pipeType == "no_tc" {
		driver = pipe.PIPE_NOTC
	} else {
		driver = pipe.PIPE_TC
	}
	log.WithFields(log.Fields{"pipeType": driver, "jumboframe": gInfo.jumboFrameMTU}).Info("")

	if nvSvcPort, nvSvcBrPort, err = pipe.Open(driver, cnet_type, Agent.Pid, gInfo.jumboFrameMTU); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open pipe driver")
		os.Exit(-2)
	}

	// Start cluster
	var clusterCfg cluster.ClusterConfig
	clusterCfg.ID = Agent.ID
	clusterCfg.Server = false
	clusterCfg.Debug = false
	clusterCfg.Ifaces = Agent.Ifaces
	clusterCfg.JoinAddr = joinAddr
	clusterCfg.AdvertiseAddr = advAddr
	clusterCfg.BindAddr = bindAddr
	clusterCfg.LANPort = *lanPort
	clusterCfg.DataCenter = cluster.DefaultDataCenter
	clusterCfg.EnableDebug = *debug

	if err = clusterStart(&clusterCfg); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to start cluster. Exit!")
		if err == errNotAdmitted || err == errCtrlNotReady {
			// This indicates controllers are up but license is not loaded.
			// => exit the process but the container doesn't need to be restarted
			//这表示控制器已打开，但未加载license。
			//退出进程，但不需要重新启动容器
			os.Exit(-1)
		} else {
			// Monitor will exit, so the container will be restarted
			// Monitor将退出，因此容器将重新启动
			os.Exit(-2)
		}
	}

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	agentTimerWheel = utils.NewTimerWheel()
	agentTimerWheel.Start()

	// Read existing containers again, cluster start can take a while.
	existing := global.RT.ListContainerIDs()
	// 已存在的容器基数是否大于任务管道的最小值256，大于则以容器基数为缓冲区大小创建管道，小于缓冲区大小则是256
	if existing.Cardinality() > containerTaskChanSizeMin {
		ContainerTaskChan = make(chan *ContainerTask, existing.Cardinality())
	} else {
		ContainerTaskChan = make(chan *ContainerTask, containerTaskChanSizeMin)
	}

	rtStorageDriver = Host.StorageDriver
	log.WithFields(log.Fields{"name": rtStorageDriver}).Info("Runtime storage driver")

	// Datapath
	dpStatusChan := make(chan bool, 2)
	dp.Open(dpTaskCallback, dpStatusChan, errRestartChan)

	// Benchmark
	bench = newBench(Host.Platform, Host.Flavor)
	go bench.BenchLoop()

	if Host.CapDockerBench {
		bench.RerunDocker()
	} else {
		// If the older version write status into the cluster, clear it.
		//如果写入状态为旧版本，则清除。
		bench.ResetDockerStatus()
	}
	if !Host.CapKubeBench {
		// If the older version write status into the cluster, clear it.
		bench.ResetKubeStatus()
	}

	bPassiveContainerDetect := global.RT.String() == container.RuntimeCriO

	// Probe 探针
	probeTaskChan := make(chan *probe.ProbeMessage, 256) // increase to avoid underflow
	//文件系统监控信息管道
	fsmonTaskChan := make(chan *fsmon.MonitorMessage, 8)
	faEndChan := make(chan bool, 1)
	fsmonEndChan := make(chan bool, 1)
	probeConfig := probe.ProbeConfig{
		Pid:                  Agent.Pid,
		PidMode:              Agent.PidMode,
		DpTaskCallback:       dpTaskCallback,
		NotifyTaskChan:       probeTaskChan,
		NotifyFsTaskChan:     fsmonTaskChan,
		PolicyLookupFunc:     hostPolicyLookup,
		ProcPolicyLookupFunc: processPolicyLookup,
		ReportLearnProc:      addLearnedProcess,
		ContainerInContainer: agentEnv.containerInContainer,
		GetContainerPid:      cbGetContainerPid,
		GetAllContainerList:  cbGetAllContainerList,
		RerunKubeBench:       cbRerunKube,
		GetEstimateProcGroup: cbEstimateDeniedProcessdByGroup,
		GetServiceGroupName:  cbGetLearnedGroupName,
		FAEndChan:            faEndChan,
		DeferContStartRpt:    bPassiveContainerDetect,
		EnableTrace:          *show_monitor_trace,
		KubePlatform:         Host.Platform == share.PlatformKubernetes,
		WalkHelper:           walkerTask,
	}

	if prober, err = probe.New(&probeConfig); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to probe. Exit!")
		os.Exit(-2)
	}

	fmonConfig := fsmon.FileMonitorConfig{
		IsAufs:         global.RT.GetStorageDriver() == "aufs",
		EnableTrace:    *show_monitor_trace,
		EndChan:        fsmonEndChan,
		WalkerTask:     walkerTask,
		PidLookup:      prober.ProcessLookup,
		SendReport:     prober.SendAggregateFsMonReport,
		SendAccessRule: sendLearnedFileAccessRule,
		EstRule:        cbEstimateFileAlertByGroup,
	}

	if fileWatcher, err = fsmon.NewFileWatcher(&fmonConfig); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open file monitor!")
		os.Exit(-2)
	}

	prober.SetFileMonitor(fileWatcher)

	scanUtil = scanUtils.NewScanUtil(global.SYS)

	// grpc need to be put after probe (grpc requests like sessionList, ProbeSummary require probe ready),
	// and it also should be before clusterLoop, sending grpc port in update agent
	// grpc需要放在probe后面(grpc请求像sessionList, ProbeSummary需要probe ready
	// 也应该在clusterLoop之前，在update agent中发送grpc端口
	global.SYS.CallNetNamespaceFunc(Agent.Pid, func(params interface{}) {
		grpcServer, Agent.RPCServerPort = startGRPCServer(uint16(*grpcPort))
	}, nil)

	// Start container task thread
	// Start monitoring container events
	eventMonitorLoop(probeTaskChan, fsmonTaskChan, dpStatusChan)

	// Update host and device info to cluster
	//更新主机和设备信息到集群
	logAgent(share.CLUSEvAgentStart)
	Agent.JoinedAt = time.Now().UTC()
	putLocalInfo()
	logAgent(share.CLUSEvAgentJoin)

	clusterLoop(existing)
	existing = nil

	go statsLoop(bPassiveContainerDetect)
	go timerLoop()
	go group_profile_loop()

	// Wait for SIGTREM
	go func() {
		<-c_sig
		done <- true
	}()

	log.Info("Ready ...")

	var rc int
	select {
	case <-done:
		rc = 0
	case <-monitorExitChan:
		rc = -2
	case <-restartChan:
		// Agent is kicked because of license limit.
		// Return -1 so that monitor will restart the agent,
		// and agent will reconnect after license update.
		rc = -1
	case <-errRestartChan:
		// Proactively restart agent to recover from error condition.
		// Return -1 so that monitor will restart the agent.
		rc = -1
		dumpGoroutineStack()
	}

	// Check shouldExit() to see the loops that will exit when the flag is set
	// 检查shouldExit()以查看设置该标志时将退出的循环
	atomic.StoreInt32(&exitingFlag, 1)

	log.Info("Exiting ...")

	if walkerTask != nil {
		walkerTask.Close()
	}

	prober.Close() // both file monitors should be released at first
	fileWatcher.Close()
	bench.Close()

	stopMonitorLoop()
	closeCluster()

	waitContainerTaskExit()

	if driver != pipe.PIPE_NOTC {
		dp.DPCtrlDelSrvcPort(nvSvcPort)
	}

	pipe.Close()

	releaseAllSniffer()

	grpcServer.Stop()

	// Close DP at the last
	dp.Close()

	global.SYS.StopToolProcesses()
	<-faEndChan
	<-fsmonEndChan
	log.Info("Exited")
	//退出导致当前程序退出给定的状态码。
	//按照惯例，代码0表示成功，非0表示错误。
	//程序立即终止;不运行延迟函数。
	//
	//对于可移植性，状态码应该在[0,125]的范围内。
	os.Exit(rc)
}
