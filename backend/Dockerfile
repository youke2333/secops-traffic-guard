# ============================================================================
# 智能流量安全检测与分析系统 —— 后端镜像
# 说明：
#   * 抓包与防火墙需要内核能力，容器必须以 --cap-add=NET_RAW --cap-add=NET_ADMIN 运行，
#     若要抓到宿主机全部网卡流量（eBPF/libpcap），还需 --network=host；
#   * 默认 DRY_RUN=true，容器内不会真正修改宿主机防火墙，验证通过后再关闭。
# ============================================================================
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    PIP_NO_CACHE_DIR=1

# libpcap: scapy 抓包；nmap: 资产指纹与漏洞扫描；iptables: 防火墙联动；iproute2: 网络诊断
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpcap0.8 \
        nmap \
        iptables \
        nftables \
        iproute2 \
        iputils-ping \
        curl \
        tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY data ./data
COPY .env.example ./.env.example

RUN mkdir -p /app/data && \
    useradd -m -s /bin/bash secops && \
    chown -R secops:secops /app
USER secops

EXPOSE 8000

# 健康检查：/api/v1/health 同时反映采集模式与防火墙后端
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers"]
