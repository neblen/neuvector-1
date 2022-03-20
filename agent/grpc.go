package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

type ScanService struct {
	scanning  utils.Set
	scanMutex sync.Mutex
}

func newScanService() *ScanService {
	return &ScanService{
		scanning: utils.NewSet(),
	}
}

func (ss *ScanService) setScanStart(id string) bool {
	ss.scanMutex.Lock()
	defer ss.scanMutex.Unlock()

	// In case a scan takes a long time to finish, ctrl will retry the request
	// Avoid triggering the same scan for such case
	// 如果扫描需要很长时间来完成，ctrl键将重试请求
	// 避免在这种情况下触发相同的扫描
	if ss.scanning.Contains(id) {
		return true
	}

	ss.scanning.Add(id)
	return false
}

func (ss *ScanService) setScanDone(id string) {
	ss.scanMutex.Lock()
	defer ss.scanMutex.Unlock()

	ss.scanning.Remove(id)
}

// 扫描主机、容器
func (ss *ScanService) ScanGetFiles(ctx context.Context, req *share.ScanRunningRequest) (*share.ScanData, error) {
	// Use Info log level so we by default log it's scanning
	log.WithFields(log.Fields{"id": req.ID}).Info("")

	if ss.setScanStart(req.ID) {
		log.WithFields(log.Fields{"id": req.ID}).Info("scan in propress")
		return &share.ScanData{Error: share.ScanErrorCode_ScanErrInProgress}, nil
	}
	// 解锁最后删除改id
	defer ss.setScanDone(req.ID)

	var pid int
	var data share.ScanData

	gInfoRLock()
	if req.Type == share.ScanObjectType_HOST {
		pid = 1
		if gInfo.hostScanCache != nil {
			data.Buffer = gInfo.hostScanCache
			data.Error = share.ScanErrorCode_ScanErrNone
		}
	} else if c, ok := gInfo.activeContainers[req.ID]; ok {
		pid = c.pid
		if c.scanCache != nil {
			data.Buffer = c.scanCache
			data.Error = share.ScanErrorCode_ScanErrNone
		}
	}
	gInfoRUnlock()

	// Use the cached buffer if it's valid
	// 如果缓存是有效的，使用它
	if data.Buffer != nil {
		log.WithFields(log.Fields{"id": req.ID}).Info("return cached data")
		return &data, nil
	}

	if pid == 0 {
		log.WithFields(log.Fields{"id": req.ID}).Info("container not running")
		return &share.ScanData{Error: share.ScanErrorCode_ScanErrContainerExit}, nil
	}

	global.SYS.ReCalculateMemoryMetrics(memStatsEnforcerResetMark)

	taskReq := workerlet.WalkGetPackageRequest{
		Pid:     pid,
		Id:      req.ID,
		Kernel:  Host.Kernel,
		ObjType: req.Type,
	}

	bytesValue, _, err := walkerTask.Run(taskReq)
	if err == nil {
		if err = json.Unmarshal(bytesValue, &data); err != nil {
			log.WithFields(log.Fields{"id": req.ID, "error": err}).Error()
		}
	} else {
		log.WithFields(log.Fields{"id": req.ID, "error": err}).Error()
	}

	if data.Error == share.ScanErrorCode_ScanErrNone {
		gInfoLock()
		if req.Type == share.ScanObjectType_HOST {
			gInfo.hostScanCache = data.Buffer
		} else if c, ok := gInfo.activeContainers[req.ID]; ok {
			c.scanCache = data.Buffer
		}
		gInfoUnlock()
	}

	if err := ctx.Err(); err != nil {
		log.WithFields(log.Fields{"id": req.ID, "error": err}).Error("gRPC: Failed")
	}

	log.WithFields(log.Fields{"id": req.ID}).Info("return data for scanning")
	return &data, nil
}

type CapService struct {
}

func (s *CapService) IsGRPCCompressed(ctx context.Context, v *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

func startGRPCServer(port uint16) (*cluster.GRPCServer, uint16) {
	var grpc *cluster.GRPCServer
	var err error
	//默认为18401
	if port == 0 {
		port = cluster.DefaultAgentGRPCPort
	}

	log.WithFields(log.Fields{"port": port}).Info("")
	for {
		grpc, err = cluster.NewGRPCServerTCP(fmt.Sprintf(":%d", port))
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to create GRPC server")
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}
	// 判断能不能连接上?
	share.RegisterEnforcerCapServiceServer(grpc.GetServer(), new(CapService))
	// 具体实现代码在agent/service.go中,主要功能实现:获取解析回话列表头、获取探针汇总，process、RunDockerBench、RunKubernetesBench、解析和获取的DLP规则 、GetFileMonitorFile等等
	share.RegisterEnforcerServiceServer(grpc.GetServer(), new(RPCService))
	// 扫描主机、容器,在scanner/server/ScanRunning中被调用
	share.RegisterEnforcerScanServiceServer(grpc.GetServer(), newScanService())
	go grpc.Start()

	log.Info("GRPC server started")

	return grpc, port
}

func createControllerAgentServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewControllerAgentServiceClient(conn)
}

func getControllerServiceClient() (share.ControllerAgentServiceClient, error) {
	ctrlEndpoint := getLeadGRPCEndpoint()
	log.WithFields(log.Fields{"endpoint": ctrlEndpoint}).Debug("")

	if ctrlEndpoint == "" {
		log.WithFields(log.Fields{"endpoint": ctrlEndpoint}).Error("Controller endpoint is not ready")
		return nil, fmt.Errorf("Controller endpoint is not ready")
	}
	if cluster.GetGRPCClientEndpoint(ctrlEndpoint) == "" {
		cluster.CreateGRPCClient(ctrlEndpoint, ctrlEndpoint, true,
			createControllerAgentServiceWrapper)
	}
	c, err := cluster.GetGRPCClient(ctrlEndpoint, cluster.IsControllerGRPCCommpressed, nil)
	if err == nil {
		return c.(share.ControllerAgentServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

func requestAdmission(req *share.CLUSAdmissionRequest, timeout time.Duration) (*share.CLUSAdmissionResponse, error) {
	client, err := getControllerServiceClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return nil, fmt.Errorf("Fail to find controller client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return client.RequestAdmission(ctx, req)
}

// 寄送已学习的process
func sendLearnedProcess(procs []*share.CLUSProcProfileReq) error {
	log.WithFields(log.Fields{"processes": len(procs)}).Debug("")

	client, err := getControllerServiceClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return fmt.Errorf("Fail to find controller client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	procArray := &share.CLUSProcProfileArray{
		Processes: procs,
	}

	_, err = client.ReportProcProfile(ctx, procArray)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Fail to report process profile to controller")
		return fmt.Errorf("Fail to report process profile to controller")
	}
	return nil
}

func sendLearnedFileAccessRule(rules []*share.CLUSFileAccessRuleReq) error {
	log.WithFields(log.Fields{"rules": len(rules)}).Debug("")
	client, err := getControllerServiceClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return fmt.Errorf("Fail to find controller client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	ruleArray := &share.CLUSFileAccessRuleArray{
		Rules: rules,
	}

	_, err = client.ReportFileAccessRule(ctx, ruleArray)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Fail to report file rule to controller")
		return fmt.Errorf("Fail to report file rule to controller")
	}
	return nil
}

func sendConnections(conns []*share.CLUSConnection) (*share.CLUSReportResponse, error) {
	client, err := getControllerServiceClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return nil, fmt.Errorf("Fail to find controller client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	connArray := &share.CLUSConnectionArray{
		Connections: conns,
	}

	resp, err := client.ReportConnections(ctx, connArray)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Fail to report connections to controller")
		return resp, fmt.Errorf("Fail to report connections to controller")
	}
	return resp, nil
}
