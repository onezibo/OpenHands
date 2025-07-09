# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenHands是一个由AI驱动的软件开发代理平台，结合了Python后端和React前端。项目前身为OpenDevin，现在作为一个完整的代码助手生态系统运行。

## Development Commands

### Environment Setup
```bash
make build           # 完整构建：依赖检查 + 安装 + 前端构建
make setup-config    # 配置LLM API密钥和工作目录
```

### Running the Application
```bash
make run             # 启动完整应用（后端+前端）
make start-backend   # 仅启动后端服务器（端口3000）
make start-frontend  # 仅启动前端服务器（端口3001）
```

### Testing
```bash
make test                    # 运行前端测试
make test-frontend          # 明确运行前端测试
poetry run pytest tests/unit/  # 运行Python单元测试
poetry run pytest tests/runtime/  # 运行运行时测试
cd frontend && npm run test:e2e  # 运行端到端测试
```

### Code Quality
```bash
make lint            # 运行所有代码检查（前端+后端）
make lint-frontend   # 前端ESLint + Prettier检查
make lint-backend    # 后端Ruff + MyPy检查
cd frontend && npm run lint:fix  # 自动修复前端代码风格
```

### Docker Development
```bash
make docker-dev      # 在Docker容器中开发
make docker-run      # 在Docker中运行应用
```

### Dependencies
```bash
poetry add <package>  # 添加Python依赖
poetry lock --no-update  # 更新poetry.lock
cd frontend && npm install <package>  # 添加前端依赖
```

## Core Architecture

### Backend Structure (`/openhands`)
- **`agenthub/`** - AI代理实现
  - `codeact_agent/` - 主要的代码执行代理
  - `browsing_agent/` - 网页浏览代理
  - `dummy_agent/` - 测试用虚拟代理

- **`server/`** - FastAPI HTTP服务器
  - `routes/` - API路由定义
  - `session/` - 会话管理

- **`controller/`** - 代理控制器，负责执行循环
  - `agent_controller.py` - 核心控制器

- **`runtime/`** - 运行时环境管理（Docker、E2B、Modal等）

- **`llm/`** - 大语言模型接口（基于LiteLLM）

- **`events/`** - 事件系统
  - `action/` - 行动事件
  - `observation/` - 观察事件

### Frontend Structure (`/frontend`)
- **技术栈**: React 19 + TypeScript + Vite + React Router v7 + Redux + TanStack Query + Tailwind CSS
- **架构模式**: Remix SPA模式
- **开发工具**: MSW (Mock Service Worker)用于API模拟
- **国际化**: i18next多语言支持
- **测试**: Vitest + React Testing Library + Playwright

### Event-Driven Architecture
- **EventStream** 作为中央消息总线
- **Action** 和 **Observation** 作为基本消息类型
- 所有组件通过事件进行通信

## Development Guidelines

### Python Development
- **Python版本**: 3.12+
- **依赖管理**: Poetry >= 1.8
- **代码规范**: Ruff (linting) + MyPy (type checking)
- **测试框架**: pytest（配置在pytest.ini中）
- **入口点**: `openhands = "openhands.cli.main:main"`

### Frontend Development
- **Node.js版本**: 22.x+（虽然package.json显示20+，但Makefile要求22+）
- **包管理**: npm
- **开发服务器**: Vite（支持热重载）
- **环境变量**:
  - `VITE_MOCK_API=true` - 使用模拟API
  - `VITE_BACKEND_HOST` - 后端主机地址

### Runtime Environment Management
项目支持多种运行时环境：
- **Docker** - 默认运行时
- **E2B** - 远程沙箱环境
- **Modal** - 云计算平台
- **Local** - 本地运行时（设置`RUNTIME=local`）

### Testing Strategy
- **单元测试**: Python后端使用pytest，前端使用Vitest
- **集成测试**: `/evaluation/integration_tests/`
- **端到端测试**: 前端使用Playwright
- **评估基准**: 20+个基准测试（SWE-bench、WebArena、GAIA等）

## Common Development Workflows

### Adding New Agent
1. 在`/openhands/agenthub/`下创建新的代理目录
2. 实现Agent类，继承基础Agent接口
3. 在相应目录添加测试
4. 更新agent注册机制

### Adding New Runtime
1. 在`/openhands/runtime/`下实现新的Runtime类
2. 继承Runtime基类接口
3. 在`/containers/runtime/`添加对应的Docker配置
4. 更新运行时选择逻辑

### Frontend Component Development
1. 使用现有的Tailwind CSS + HeroUI组件库
2. 遵循React 19的最佳实践
3. 使用Redux进行状态管理，TanStack Query进行数据获取
4. 确保组件支持i18next国际化

### API Development
1. 在`/openhands/server/routes/`添加新路由
2. 使用FastAPI的依赖注入和类型提示
3. 更新前端的API类型定义
4. 如果是开发模式，在MSW中添加mock handler

## Special Directories

### `/microagents` - 微代理
预定义的专用代理配置，用于特定任务：
- `github.md` - GitHub相关任务
- `docker.md` - Docker相关任务
- `security.md` - 安全检查任务

### `/evaluation` - 评估框架
包含20+个基准测试套件，包括：
- `swe_bench/` - 软件工程基准
- `webarena/` - 网页操作评估
- `gaia/` - 通用AI助手评估

### `/containers` - 容器化配置
- `app/` - 应用容器配置
- `dev/` - 开发容器配置
- `runtime/` - 运行时容器配置

## Environment Requirements

### System Requirements
- **操作系统**: Linux、macOS或WSL2（Ubuntu >= 22.04）
- **Docker**: 用于沙箱环境（支持hardened installation）
- **Python**: 3.12+
- **Node.js**: 22.x+
- **Poetry**: 1.8+

### Development Dependencies
- **tmux**: 可选，用于高级终端功能
- **build-essential**: Ubuntu上需要（`sudo apt-get install build-essential python3.12-dev`）
- **netcat**: WSL上需要（`sudo apt-get install netcat`）

## Configuration Files

### Core Configuration
- **`config.toml`** - 主配置文件（LLM设置、工作目录等）
- **`pyproject.toml`** - Python项目配置（Poetry、依赖、脚本）
- **`frontend/package.json`** - 前端依赖和脚本

### Development Configuration
- **`pytest.ini`** - Python测试配置
- **`dev_config/python/.pre-commit-config.yaml`** - Pre-commit hooks
- **`frontend/eslint.config.js`** - 前端代码检查配置

## Debugging and Logging

### LLM Debugging
设置环境变量`DEBUG=1`并重启后端，将在`logs/llm/CURRENT_DATE`目录记录LLM提示和响应。

### Log Locations
- **后端日志**: `logs/` 目录
- **前端开发**: 浏览器开发者工具
- **Docker容器**: Docker logs

## Security and Best Practices

### Network Security
在公共网络上部署时，参考[Hardened Docker Installation Guide](https://docs.all-hands.dev/usage/runtimes/docker#hardened-docker-installation)。

### API Keys Management
- 使用`config.toml`或环境变量存储API密钥
- 支持多种LLM提供商（基于litellm）
- 优先级：环境变量 > config.toml > 默认值

### Docker Security
- 使用官方runtime镜像：`docker.all-hands.dev/all-hands-ai/runtime:0.44-nikolaik`
- 支持网络限制和安全措施
- 避免在多租户环境中直接部署
