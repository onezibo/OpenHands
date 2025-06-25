# SecurityAgent 安全工具配置指南

## 概述

SecurityAgent 为您提供专业的安全分析能力，集成了 AFL++、GDB、KLEE 等安全工具。为了获得完整的功能，需要使用包含这些工具的 Docker 环境。

## 🔧 快速配置

### 方案1：使用预构建的安全镜像（推荐）

如果您已经构建了 `openhands-security:latest` 镜像，可以通过以下方式配置：

#### 环境变量方式
```bash
export OH_RUNTIME_CONTAINER_IMAGE=openhands-security:latest
# 然后启动 OpenHands
make run
```

#### 配置文件方式
在您的 `config.toml` 中添加：
```toml
[core]
runtime_container_image = "openhands-security:latest"
```

### 方案2：构建安全工具镜像

如果您还没有安全工具镜像，可以构建一个：

```bash
# 在 OpenHands 项目根目录下
docker build -t openhands-security:latest -f containers/security/Dockerfile.security-minimal .
```

构建完成后，按照方案1进行配置。

## 🛠️ 包含的安全工具

SecurityAgent 环境包含以下安全分析工具：

### 模糊测试工具
- **AFL++**: 高级模糊测试框架
  - `afl-fuzz`: 主要模糊测试工具
  - `afl-cmin`: 语料库最小化
  - `afl-tmin`: 测试用例最小化

### 调试分析工具
- **GDB**: GNU 调试器
  - 崩溃分析和调试
  - 内存检查和栈跟踪

### 静态分析工具
- **Clang/LLVM**: 编译器和分析工具
- **objdump**: 二进制反汇编
- **file**: 文件类型检测
- **strings**: 字符串提取

### Python 安全库
- **pwntools**: CTF 和安全分析框架

## 🚀 验证安装

启动 SecurityAgent 后，它会自动检测可用的安全工具。您可以通过以下方式验证：

1. SecurityAgent 启动时会在日志中显示检测到的工具
2. 运行 Docker 容器中的检查脚本：
   ```bash
   docker run --rm openhands-security:latest check-security-tools
   ```

## 📋 使用示例

配置完成后，您可以直接使用 SecurityAgent 进行安全分析：

```
用户: 请对这个二进制文件进行 fuzzing 测试
SecurityAgent: 我将使用 AFL++ 对您的二进制文件进行模糊测试...
[SecurityAgent 将直接开始分析，无需安装工具]
```

## 🔍 故障排除

### 问题：SecurityAgent 仍然尝试安装工具

**可能原因**：
- 未正确配置 runtime_container_image
- Docker 镜像未正确构建
- 环境变量未生效

**解决方案**：
1. 确认镜像存在：`docker images | grep openhands-security`
2. 验证配置：检查 config.toml 或环境变量
3. 重启 OpenHands 服务

### 问题：Docker 镜像构建失败

**解决方案**：
1. 检查网络连接（需要下载 AFL++ 等工具）
2. 确保有足够的磁盘空间（镜像约 8GB）
3. 使用 `Dockerfile.security-minimal` 进行快速构建

### 问题：某些工具不可用

**解决方案**：
1. 使用完整版本的 Dockerfile.security-extension
2. 手动安装缺失工具
3. 报告问题以改进默认配置

## 📚 更多资源

- [SecurityAgent 使用指南](USAGE.md)
- [Agent Skills 文档](../../runtime/plugins/agent_skills/security/)
- [OpenHands 配置文档](../../../docs/configuration.md)

## 🤝 支持

如果您在配置过程中遇到问题，请：
1. 检查 OpenHands 日志中的 SecurityAgent 相关信息
2. 验证 Docker 镜像和配置
3. 查阅故障排除部分

SecurityAgent 致力于为您提供专业的安全分析能力！🔒