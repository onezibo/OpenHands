#!/bin/bash
# SecurityAgent Docker运行时构建脚本

set -e

# 颜色输出
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

# 配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_IMAGE="${BASE_IMAGE:-docker.all-hands.dev/all-hands-ai/runtime:0.44-nikolaik}"
SECURITY_IMAGE_NAME="${SECURITY_IMAGE_NAME:-openhands-security}"
SECURITY_IMAGE_TAG="${SECURITY_IMAGE_TAG:-latest}"

echo -e "${GREEN}=== SecurityAgent Docker Runtime 构建脚本 ===${NC}"
echo ""

# 检查Docker是否可用
if ! command -v docker &> /dev/null; then
    echo -e "${RED}错误: Docker未安装或不可用${NC}"
    exit 1
fi

# 检查Dockerfile是否存在
DOCKERFILE_PATH="${SCRIPT_DIR}/Dockerfile.security-extension"
if [ ! -f "$DOCKERFILE_PATH" ]; then
    echo -e "${RED}错误: 找不到Dockerfile: $DOCKERFILE_PATH${NC}"
    exit 1
fi

echo -e "${YELLOW}配置信息:${NC}"
echo "  基础镜像: $BASE_IMAGE"
echo "  目标镜像: $SECURITY_IMAGE_NAME:$SECURITY_IMAGE_TAG"
echo "  Dockerfile: $DOCKERFILE_PATH"
echo ""

# 确认构建
read -p "是否继续构建? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "构建已取消"
    exit 0
fi

echo -e "${GREEN}开始构建SecurityAgent运行时镜像...${NC}"
echo ""

# 构建镜像
docker build \\
    --build-arg BASE_IMAGE="$BASE_IMAGE" \\
    -t "$SECURITY_IMAGE_NAME:$SECURITY_IMAGE_TAG" \\
    -f "$DOCKERFILE_PATH" \\
    "$SCRIPT_DIR"

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ SecurityAgent运行时镜像构建成功!${NC}"
    echo ""
    echo -e "${YELLOW}使用方法:${NC}"
    echo "1. 启动容器:"
    echo "   docker run -it --rm $SECURITY_IMAGE_NAME:$SECURITY_IMAGE_TAG"
    echo ""
    echo "2. 在OpenHands中使用:"
    echo "   export RUNTIME_IMAGE=$SECURITY_IMAGE_NAME:$SECURITY_IMAGE_TAG"
    echo "   openhands --agent SecurityAgent --runtime docker"
    echo ""
    echo "3. 检查工具安装:"
    echo "   docker run --rm $SECURITY_IMAGE_NAME:$SECURITY_IMAGE_TAG check-security-tools"
    echo ""
    echo "4. 快速安全扫描:"
    echo "   docker run --rm -v /path/to/binary:/tmp/binary $SECURITY_IMAGE_NAME:$SECURITY_IMAGE_TAG quick-security-scan /tmp/binary"
    echo ""
else
    echo -e "${RED}✗ 镜像构建失败${NC}"
    exit 1
fi

# 显示镜像信息
echo -e "${YELLOW}镜像信息:${NC}"
docker images | grep "$SECURITY_IMAGE_NAME" | head -1

echo ""
echo -e "${GREEN}SecurityAgent运行时环境已准备就绪! 🔒${NC}"
