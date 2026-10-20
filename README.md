# bdmvtoiso

BDMV 目录打包成蓝光 ISO 的 Web 面板。核心能力：

- 自动识别 `BDMV/index.bdmv` + `BDMV/MovieObject.bdmv`，输出 UDF 2.50 的 ISO
- 打包引擎按 `genisoimage` -> `xorriso` -> `pycdlib` 依次兜底
- 后台任务 + 进度轮询，支持停止、清除记录
- 内置 ed2k 哈希（9500KB 分块，兼容 eMule），结果持久化缓存，改名不改哈希
- qBittorrent 下载完成 webhook：可自动排队打包、自动计算 ed2k

## 镜像

```
ghcr.io/desire5864/bdmvtoiso:latest
```

由 GitHub Actions 从本仓库源码构建，无任何授权校验，直接启动即可。

## 快速开始

```yaml
services:
  bdmvtoiso:
    image: ghcr.io/desire5864/bdmvtoiso:latest
    restart: unless-stopped
    ports: ["5173:5173"]
    volumes:
      - /path/to/原盘:/app/data
      - /path/to/ISO:/app/updata
      - /path/to/iso-lib:/app/iso
      - ./config:/app/config
```

```bash
docker compose up -d
```

打开 `http://<host>:5173`，初始账号 `admin` / `admin123`，登录后可在「改密」页修改。

## 卷说明

| 容器路径 | 用途 |
|---|---|
| `/app/data` | 源目录。每个一级子目录要么本身是 BDMV 根，要么是内含多张碟的合集目录 |
| `/app/updata` | 打包产物输出目录 |
| `/app/iso` | 外部 ISO 库，单独计算 ed2k |
| `/app/config` | `config.json`（账号密码哈希）、`list.json` / `ed2k.json`（哈希缓存） |

## 打包引擎

镜像内置 `genisoimage`、`xorriso` 以及包装器 `bdmv-genisoimage`：

```sh
#!/bin/sh
exec /usr/bin/genisoimage -iso-level 3 -allow-limited-size -input-charset utf-8 -quiet "$@"
```

`genisoimage` 支持 `-udfver` 时会强制 UDF 2.50，保证蓝光播放机兼容性；不支持则退回 `pycdlib`（UDF 2.60）。

## qBittorrent 联动

`POST /webhook/qb`，令牌通过 `X-Webhook-Token` 头或 `?token=` 传递，默认 `aiying`，
可用环境变量 `QB_WEBHOOK_SECRET` 覆盖。三个开关（启用 webhook / 自动打包 / 自动算 ed2k）
在面板「自动化」页维护，写入 `config/config.json`。

## 接口

- `GET /api/status` — 所有打包任务状态（`jobs` 字典）。
- `GET /api/resources` — 可直接打包的 BDMV 资源目录列表，供 MoviePilot 的
  「BDMV自动打包ISO」插件比对下载任务名后自动提交打包：

```json
{"ok": true, "count": 1,
 "resources": ["Some.Movie.2026.UHD.Blu-ray.HEVC-BHYS@OurBits"],
 "items": [{"name": "Some.Movie.2026...", "kind": "disc", "out_exists": false, "discs": []}]}
```

两个接口都走登录校验（`/login` 拿 session cookie 后携带）。

## 群晖部署 / 升级

镜像发布在 GHCR，**公开、免登录**，NAS 上直接拉即可：

```bash
cd /volume1/docker/bdmvtoiso
/usr/local/bin/docker compose pull
/usr/local/bin/docker compose up -d
```

群晖的 compose 是独立二进制，脚本里请写绝对路径 `/usr/local/bin/docker compose`。
`config/`（账号、会话密钥）是挂载目录，`pull` 与重建容器都不会碰它。

要钉在某个版本上，把 compose 里的 `:latest` 换成 `:vX.Y.Z`；打 `v*` 标签会同时产出
版本号标签、`latest` 和 `sha-<短哈希>`。

### 备用镜像源（Docker Hub）

每次构建会同时推到两个仓库，产物完全一致：

```
ghcr.io/desire5864/bdmvtoiso:latest            # 主链路
docker.io/zhangsan51455/bdmvtoiso:latest       # 备用（ghcr 拉不动时替换 compose 里的 image）
```

Docker Hub 的 Docker ID 无法改名，所以两边的账号名不同，属正常。备用源需要仓库 Secrets
`DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`（PAT 具备 Read & Write 即可）。

## 本地构建

```bash
docker build -t bdmvtoiso .
docker run -d -p 5173:5173 -v $PWD/config:/app/config bdmvtoiso
```
