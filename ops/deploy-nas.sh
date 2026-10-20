#!/bin/sh
# bdmvtoiso 一键部署：自动确保 ghcr 凭据 → 拉最新镜像 → 重建容器
# 凭据持久化在 /volume1/docker/.docker/config.json（随 docker 目录一起，重建容器/重启都不丢）
# 凭据一旦缺失，本脚本会用 MoviePilot 容器里的 PAT 自动重新登录，不需要人工输入密码。
set -e

DOCK=/usr/local/bin/docker
CRED_DIR=/volume1/docker/.docker
CRED=$CRED_DIR/config.json
COMPOSE_DIR=/volume1/docker/bdmvtoiso
OWNER=Desire5864

mkdir -p "$CRED_DIR"
chmod 700 "$CRED_DIR"

# 1) 迁移旧位置并指向持久卷（幂等）
mkdir -p /root/.docker
if [ ! -f "$CRED" ] && [ -f /root/.docker/config.json ] && [ ! -L /root/.docker/config.json ]; then
    cp -a /root/.docker/config.json "$CRED"
    chmod 600 "$CRED"
    echo "已把 /root/.docker/config.json 迁移到 $CRED"
fi
ln -sfn "$CRED" /root/.docker/config.json

# 2) 凭据里没有 ghcr.io 条目时自动登录（token 取自容器环境，不落日志）
if ! grep -q '"ghcr.io"' "$CRED" 2>/dev/null; then
    TOK=$($DOCK exec moviepilot-v2 printenv GITHUB_TOKEN 2>/dev/null || true)
    if [ -z "$TOK" ]; then
        echo "!! 取不到 MoviePilot 容器里的 GITHUB_TOKEN，无法自动登录 ghcr.io" >&2
        exit 1
    fi
    printf '%s' "$TOK" | DOCKER_CONFIG="$CRED_DIR" $DOCK login ghcr.io -u "$OWNER" --password-stdin >/dev/null
    echo "凭据缺失，已用 MoviePilot 容器的 PAT 重新登录 ghcr.io"
else
    echo "ghcr 凭据已就绪（$CRED）"
fi

# 3) 拉取 + 重建
cd "$COMPOSE_DIR"
DOCKER_CONFIG="$CRED_DIR" $DOCK compose pull
DOCKER_CONFIG="$CRED_DIR" $DOCK compose up -d
sleep 6
$DOCK ps --filter name=bdmvtoiso --format '{{.Status}} {{.Image}}'
