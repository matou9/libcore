# Hiddify Core 编译系统详解

本文档详细解释了 Hiddify Core 的编译系统，包括 Makefile 参数、目录结构和编译流程。

## 编译参数与目录结构

### Gomobile 导出

在 Makefile 中，gomobile 命令用于生成移动平台的绑定：

```shell
gomobile bind -v -androidapi=21 -javapkg=io.nekohasekai -libname=box -tags=$(TAGS) -trimpath -target=android -o $(BINDIR)/$(LIBNAME).aar github.com/sagernet/sing-box/experimental/libbox ./mobile
```

这个命令指定了两个目录：
1. `github.com/sagernet/sing-box/experimental/libbox` - 外部依赖包路径
2. `./mobile` - 项目本地的 mobile 目录

这两个目录中的公开内容（首字母大写的函数、类型、变量等）都会被导出到生成的 AAR 文件中，并可在 Java/Kotlin 代码中使用。

### 核心目录结构

- **v2 目录**：虽然没有被 gomobile 直接导出，但它是整个项目的核心实现层
  - 提供核心功能实现（服务管理、配置处理、隧道功能等）
  - 被 `mobile` 包调用，作为移动平台的后端支持
  - 实现了跨平台可用的功能
  - 包含 gRPC 服务实现，用于桌面应用通信

- **commands.go 文件**：实现了 gRPC 服务的一部分方法
  - 提供系统信息和出站连接相关的流式 API
  - 管理命令客户端与 sing-box 的交互
  - 实现观察者模式处理系统信息和出站信息
  - 提供出站选择和 URL 测试功能
  - 主要被桌面应用通过 gRPC 调用，而非移动应用

## Windows 编译详解

以下是 Windows 编译部分的详细解析：

```makefile
windows-amd64:
    curl http://localhost:18020/exit || echo "exited"
    env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc $(GOBUILDLIB) -o $(BINDIR)/$(LIBNAME).dll ./custom
    go install -mod=readonly github.com/akavel/rsrc@latest ||echo "rsrc error in installation"
    go run ./cli tunnel exit
    cp $(BINDIR)/$(LIBNAME).dll ./$(LIBNAME).dll 
    $$(go env GOPATH)/bin/rsrc -ico ./assets/hiddify-cli.ico -o ./cli/bydll/cli.syso ||echo "rsrc error in syso"
    env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CGO_LDFLAGS="$(LIBNAME).dll" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME).exe ./cli/bydll
    rm ./$(LIBNAME).dll
    make webui
```

### 命令解析

1. **停止运行中的服务**:
   ```
   curl http://localhost:18020/exit || echo "exited"
   ```
   - 尝试通过 HTTP 请求停止在端口 18020 上运行的服务
   - 如果服务未运行或停止失败，输出 "exited" 并继续

2. **编译 C 共享库**:
   ```
   env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc $(GOBUILDLIB) -o $(BINDIR)/$(LIBNAME).dll ./custom
   ```
   - `GOOS=windows GOARCH=amd64`: 设置目标平台为 Windows 64位
   - `CC=x86_64-w64-mingw32-gcc`: 使用 MinGW 交叉编译器
   - `$(GOBUILDLIB)`: 展开为 `CGO_ENABLED=1 go build -trimpath -tags $(TAGS) -ldflags="-w -s" -buildmode=c-shared`
   - `-o $(BINDIR)/$(LIBNAME).dll`: 输出到 `bin/libcore.dll`
   - `./custom`: 编译 `custom` 目录下的代码

3. **安装资源编译工具**:
   ```
   go install -mod=readonly github.com/akavel/rsrc@latest ||echo "rsrc error in installation"
   ```
   - 安装 `rsrc` 工具，用于将图标嵌入到 Windows 可执行文件中

4. **再次停止服务**:
   ```
   go run ./cli tunnel exit
   ```
   - 运行 `./cli` 目录下的代码，执行 `tunnel exit` 命令停止隧道服务

5. **复制 DLL 文件**:
   ```
   cp $(BINDIR)/$(LIBNAME).dll ./$(LIBNAME).dll
   ```
   - 将生成的 DLL 从 `bin` 目录复制到当前目录，供后续编译使用

6. **嵌入图标资源**:
   ```
   $$(go env GOPATH)/bin/rsrc -ico ./assets/hiddify-cli.ico -o ./cli/bydll/cli.syso ||echo "rsrc error in syso"
   ```
   - 使用 `rsrc` 工具将 `./assets/hiddify-cli.ico` 图标嵌入到 `./cli/bydll/cli.syso` 文件中
   - 这个 `.syso` 文件会在编译时自动被链接到可执行文件中

7. **编译 CLI 可执行文件**:
   ```
   env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CGO_LDFLAGS="$(LIBNAME).dll" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME).exe ./cli/bydll
   ```
   - 同样设置为 Windows 64位目标
   - `CGO_LDFLAGS="$(LIBNAME).dll"`: 链接刚才生成的 DLL
   - `$(GOBUILDSRV)`: 展开为 `CGO_ENABLED=1 go build -ldflags "-s -w" -trimpath -tags $(TAGS)`
   - `-o $(BINDIR)/$(CLINAME).exe`: 输出到 `bin/HiddifyCli.exe`
   - `./cli/bydll`: 编译 `cli/bydll` 目录下的代码

8. **清理临时文件**:
   ```
   rm ./$(LIBNAME).dll
   ```
   - 删除临时复制的 DLL 文件

9. **生成 Web UI**:
   ```
   make webui
   ```
   - 调用 `webui` 目标，下载并解压 Web UI 文件到 `bin/webui` 目录

### 相关程序目录

1. **`./custom`**: 
   - 包含 C 共享库的入口点代码
   - 实现了可以被其他语言调用的 C 导出函数
   - 文件如 `custom.go` 定义了与 Dart/Flutter 交互的接口

2. **`./cli`**:
   - 命令行界面的实现
   - 包含各种子命令如 `run`, `tunnel`, `config` 等
   - 使用 Cobra 库构建命令行界面

3. **`./cli/bydll`**:
   - 特定于 Windows 的 CLI 实现
   - 通过 CGO 链接到 `libcore.dll`
   - 使用 DLL 提供的功能实现命令行工具

4. **`./assets`**:
   - 包含资源文件，如图标 `hiddify-cli.ico`

5. **`$(BINDIR)` (即 `./bin`)**:
   - 编译输出目录
   - 存放生成的 DLL、可执行文件和 Web UI

6. **`./v2`**:
   - 核心功能实现
   - 提供服务管理、配置处理等功能

## 编译流程特点

Hiddify Core 的编译系统具有以下特点：

1. **跨平台编译**：使用 CGO 和交叉编译器实现跨平台编译
2. **两步编译流程**：先编译核心库，再编译依赖该库的应用程序
3. **资源嵌入**：将图标等资源嵌入到可执行文件中
4. **模块化设计**：核心功能与平台特定代码分离
5. **多平台支持**：同一代码库支持桌面、移动和服务器平台

这种设计使得 Hiddify Core 能够在保持核心功能一致的同时，适应不同平台的特定需求。