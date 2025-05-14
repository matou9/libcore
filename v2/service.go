package v2

import (
	"github.com/hiddify/hiddify-core/v2/service_manager"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"io"
	"os"
	"runtime"
	"time"
)

var (
	sWorkingPath          string
	sTempPath             string
	sUserID               int
	sGroupID              int
	statusPropagationPort int64
)

func InitHiddifyService() error {
	return service_manager.StartServices()
}

func Setup(basePath string, workingPath string, tempPath string, statusPort int64, debug bool) error {
	statusPropagationPort = int64(statusPort)
	// 根据新版本 libbox.Setup 的参数结构进行修改
	libbox.Setup(&libbox.SetupOptions{
		BasePath:    basePath,
		WorkingPath: workingPath,
		TempPath:    tempPath,
		IsTVOS:      runtime.GOOS == "windows", // TODO add TVOS
	})
	sWorkingPath = workingPath
	os.Chdir(sWorkingPath)
	sTempPath = tempPath
	sUserID = os.Getuid()
	sGroupID = os.Getgid()

	var defaultWriter io.Writer
	if !debug {
		defaultWriter = io.Discard
	}
	factory, err := log.New(
		log.Options{
			DefaultWriter: defaultWriter,
			BaseTime:      time.Now(),
			Observable:    true,
			// Options: option.LogOptions{
			// 	Disabled: false,
			// 	Level:    "trace",
			// 	Output:   "stdout",
			// },
		})
	coreLogFactory = factory

	if err != nil {
		return E.Cause(err, "create logger")
	}
	return InitHiddifyService()
}

func NewService(options option.Options) (*libbox.BoxService, error) {
	return libbox.NewGuiChaoService(options)
}

func readOptions(configContent string) (option.Options, error) {
	var options option.Options
	ctx := libbox.BaseContext(nil)
	err := options.UnmarshalJSONContext(ctx, []byte(configContent))
	if err != nil {
		return option.Options{}, E.Cause(err, "readOptions decode config")
	}
	// 使用 UnmarshalJSONContext 替代 UnmarshalJSON
	// 根据新版本 sing-box 的 option 包结构进行修改
	//fmt.Print("readOptions=", string(options.RawMessage))
	return options, nil
}
