# BDMV -> Blu-ray ISO 打包面板
# 独立构建：不依赖任何上游镜像产物，工具链全部由 Debian 官方包提供
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 蓝光 UDF 打包工具链：genisoimage 优先，xorriso 兜底
RUN apt-get update \
 && apt-get install -y --no-install-recommends genisoimage xorriso \
 && rm -rf /var/lib/apt/lists/*

# 打包引擎会优先调用这个包装器，把参数补齐成蓝光常用的组合
RUN printf '#!/bin/sh\nexec /usr/bin/genisoimage -iso-level 3 -allow-limited-size -input-charset utf-8 -quiet "$@"\n' \
      > /usr/local/bin/bdmv-genisoimage \
 && chmod +x /usr/local/bin/bdmv-genisoimage

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/ /app/
COPY templates/ /app/templates/

# 运行时目录（实际使用建议挂载到宿主机）
RUN mkdir -p /app/data /app/updata /app/iso /app/config

EXPOSE 5173

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5173/login',timeout=4).status==200 else 1)"

CMD ["python", "/app/main.py", "--host", "0.0.0.0", "--port", "5173", "--no-debug"]
