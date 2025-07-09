#!/bin/bash
# SecurityAgent 配置脚本
# 用于快速配置 OpenHands 使用包含安全工具的 Docker 镜像

set -e

echo "🔒 SecurityAgent 配置工具"
echo "========================="
echo ""

# 检查 Docker 是否可用
if ! command -v docker &> /dev/null; then
    echo "❌ Docker 未安装或不可用"
    echo "请先安装 Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# 检查是否已有安全镜像
if docker images | grep -q "openhands-security"; then
    echo "✅ 发现现有的 openhands-security 镜像"
    docker images | grep openhands-security
else
    echo "📦 未找到 openhands-security 镜像，开始构建..."

    # 检查是否在 OpenHands 项目目录中
    if [ ! -f "containers/security/Dockerfile.security-minimal" ]; then
        echo "❌ 未找到 SecurityAgent Dockerfile"
        echo "请确保在 OpenHands 项目根目录中运行此脚本"
        exit 1
    fi

    echo "正在构建安全工具镜像（这可能需要几分钟）..."
    docker build -t openhands-security:latest -f containers/security/Dockerfile.security-minimal .

    if [ $? -eq 0 ]; then
        echo "✅ 安全工具镜像构建成功"
    else
        echo "❌ 镜像构建失败"
        exit 1
    fi
fi

echo ""
echo "🔧 配置 OpenHands 使用安全工具镜像"

# 方案1：环境变量配置
echo ""
echo "方案1: 使用环境变量 (临时配置)"
echo "export OH_RUNTIME_CONTAINER_IMAGE=openhands-security:latest"

# 方案2：配置文件
CONFIG_FILE="config.toml"
echo ""
echo "方案2: 更新配置文件 (持久配置)"

if [ -f "$CONFIG_FILE" ]; then
    echo "发现现有的 config.toml 文件"
    if grep -q "runtime_container_image" "$CONFIG_FILE"; then
        echo "⚠️  配置文件中已存在 runtime_container_image 设置"
        echo "请手动编辑 $CONFIG_FILE 并设置:"
        echo "runtime_container_image = \"openhands-security:latest\""
    else
        echo "正在更新配置文件..."
        # 检查是否有 [core] 节
        if grep -q "\[core\]" "$CONFIG_FILE"; then
            # 在 [core] 节后添加配置
            sed -i '/\[core\]/a runtime_container_image = "openhands-security:latest"' "$CONFIG_FILE"
        else
            # 添加新的 [core] 节
            echo "" >> "$CONFIG_FILE"
            echo "[core]" >> "$CONFIG_FILE"
            echo "runtime_container_image = \"openhands-security:latest\"" >> "$CONFIG_FILE"
        fi
        echo "✅ 配置文件已更新"
    fi
else
    echo "创建新的配置文件..."
    cat > "$CONFIG_FILE" << EOF
[core]
runtime_container_image = "openhands-security:latest"
EOF
    echo "✅ 配置文件已创建: $CONFIG_FILE"
fi

echo ""
echo "🧪 验证配置"
echo "运行以下命令测试安全工具:"
echo "docker run --rm openhands-security:latest check-security-tools"

echo ""
echo "🚀 启动 OpenHands"
echo "运行以下命令启动 OpenHands："
echo "make run"

echo ""
echo "📚 更多信息"
echo "- SecurityAgent 文档: openhands/agenthub/security_agent/SECURITY_SETUP.md"
echo "- 使用指南: openhands/agenthub/security_agent/USAGE.md"

echo ""
echo "🎉 配置完成！SecurityAgent 现在可以使用完整的安全工具集了。"
