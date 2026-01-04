# 网络攻击态势感知系统

基于 Snort3 入侵检测系统的实时网络攻击监控和可视化平台，集成机器学习置信度分析，提供全面的网络安全态势感知能力。

## 功能特性

### 📊 实时监控
- 实时读取 Snort alert_fast.txt 日志文件
- WebSocket 实时推送新攻击告警
- 支持攻击数据持久化存储到 SQLite 数据库

### 🤖 机器学习分析
- 实时机器学习置信度分析引擎
- 基于多维度特征的攻击风险评估
- 支持7种主要攻击类型识别：暴力破解、SQL注入、主机侦查、XSS、XML注入、WEBSHELL上传、UDP洪水

### 📈 数据可视化
- 攻击统计卡片（今日/本周/本月攻击数、高危攻击、活跃源IP等）
- 24小时攻击趋势图表
- 攻击类型分布统计
- 协议分布分析
- 攻击源TOP10排名
- 攻击目标TOP10排名
- 机器学习置信度分布
- 实时告警列表（支持分页和筛选）

### 🗄️ 数据存储
- SQLite 数据库存储攻击数据
- 完整的攻击信息记录（时间戳、签名、分类、优先级、IP、端口等）
- 支持多维度查询和统计分析
- 数据库索引优化查询性能

### 🎯 威胁情报
- 攻击模式分析
- 高危攻击源识别
- 新兴威胁检测
- 风险等级自动评估

## 项目结构

```
awareness/
├── app.py                      # Flask主应用程序
├── database.py                 # 数据库模型和操作
├── ml_analyzer.py              # 机器学习分析引擎
├── requirements.txt            # Python依赖
├── result.txt                  # ML分析结果文件
├── attack.db                   # SQLite数据库（自动创建）
├── app.log                     # 应用日志
├── Snort3 部署手册（基于 Ubuntu ）.md
└── templates/
    └── dashboard.html          # 仪表盘页面
```

## 快速开始

### 1. 环境准备

确保已安装 Python 3.8+ 和 pip：

```bash
python3 --version
pip3 --version
```

### 2. 安装依赖

```bash
# 激活或创建 conda 环境（可选）
conda create -n awareness python=3.9
conda activate awareness

# 安装项目依赖
pip install -r requirements.txt
```

### 3. 配置路径

在 `app.py` 中修改以下路径：

```python
# Snort告警文件路径
SNORT_ALERT_FILE = "/var/log/snort/alert_fast.txt"

# ML结果文件路径
ML_RESULT_FILE = "/home/httc/awareness/result.txt"
```

### 4. 启动应用

```bash
# 前台运行（开发环境）
python app.py

# 后台运行（生产环境）
nohup python app.py > app.log 2>&1 &
```

应用将在 `http://localhost:5000` 启动

### 5. 访问仪表盘

打开浏览器访问：`http://localhost:5000`

## API 接口

### 仪表盘总览
```
GET /api/dashboard/overview
```
返回今日、本周、本月攻击统计及整体风险等级

### 实时统计数据
```
GET /api/dashboard/realtime-stats
```
返回24小时内攻击趋势、类型分布、协议分布、TOP10源IP/目标IP

### 攻击地图数据
```
GET /api/dashboard/attack-map
```
返回地理位置映射的攻击数据

### 威胁情报
```
GET /api/dashboard/threat-intelligence
```
返回攻击模式、高危攻击源、新兴威胁分析

### 告警列表
```
GET /api/dashboard/alerts?page=1&per_page=20&priority=1&src_ip=192.168.1.1
```
支持分页和筛选的告警列表

### 攻击数据
```
GET /api/dashboard/attack-data
```
返回最新50条格式化的攻击记录

### 统计数据
```
GET /api/dashboard/statistics
```
返回数据库统计信息

### ML置信度分析
```
GET /api/dashboard/ml-confidence
```
返回机器学习置信度分析结果和统计

### 健康检查
```
GET /api/health
```
返回系统状态和文件访问情况

## Snort 日志格式

系统支持 Snort3 alert_fast 格式：

```
11/29-04:23:56.378950 [**] [1:108:12] "MALWARE-BACKDOOR QAZ Worm Client Login access" [**] [Classification: Misc activity] [Priority: 3] {TCP} 192.168.31.189:53968 -> 192.168.31.96:7597
```

解析字段：
- **时间戳**：精确到毫秒
- **规则ID**：gid, sid, rev
- **攻击签名**：详细的攻击描述
- **分类**：攻击类型分类
- **优先级**：1-5（1为最高优先级）
- **协议**：TCP/UDP/ICMP等
- **源/目标IP和端口**

## 数据库表结构

```sql
CREATE TABLE attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    signature TEXT NOT NULL,
    classification TEXT,
    priority INTEGER,
    proto TEXT,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    sid INTEGER,
    gid INTEGER,
    rev INTEGER,
    raw_line TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

## 风险等级评估

系统基于以下规则自动计算风险等级：

| 风险等级 | 判定条件 |
|---------|---------|
| Critical | 优先级1 或包含 malware/bot/c2/trojan 关键词 |
| High | 优先级2 |
| Medium | 优先级3 |
| Low | 其他优先级 |

## 机器学习模型

### 特征提取
模型提取以下18维特征：
- 优先级、时间（小时）、源/目标端口
- 消息长度、是否主要攻击类型
- Web攻击/DoS攻击/侦查攻击/管理攻击标记
- 内部流量标记
- 协议类型（TCP/UDP/ICMP/其他）

### 置信度分级
- **高置信度 (>0.7)**：高度确认为真实攻击
- **中等置信度 (0.4-0.7)**：可能是攻击，需关注
- **低置信度 (<0.4)**：可能是误报或低威胁

## 配置说明

### 端口配置
通过环境变量配置端口：
```bash
export PORT=5000
python app.py
```

### 调试模式
```bash
export FLASK_DEBUG=True
python app.py
```

### 日志级别
在 `app.py` 中修改日志配置：
```python
logging.basicConfig(
    level=logging.INFO,  # DEBUG/INFO/WARNING/ERROR
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

## Snort3 部署

完整的 Snort3 部署指南请参考 `Snort3 部署手册（基于 Ubuntu ）.md`

### 主要步骤：
1. 安装依赖包（build-essential, libpcap-dev 等）
2. 安装 Snort DAQ
3. 编译安装 Snort3
4. 配置网络接口（混杂模式 + 关闭 offloading）
5. 下载并配置规则集和 OpenAppID
6. 修改 `snort.lua` 配置文件
7. 部署为系统服务

## 生产部署建议

### 1. 使用 WSGI 服务器
```bash
pip install gunicorn
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
```

### 2. 配置 Nginx 反向代理
```nginx
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

### 3. 启用 HTTPS
使用 Let's Encrypt 或配置 SSL 证书

### 4. 日志轮转
配置 logrotate 管理 app.log

### 5. 监控告警
使用 Prometheus + Grafana 或其他监控工具

### 6. 防火墙配置
```bash
sudo ufw allow 5000/tcp
sudo ufw enable
```

## 故障排除

### 常见问题

1. **数据库连接失败**
   ```bash
   # 检查文件权限
   ls -la attack.db
   chmod 644 attack.db
   ```

2. **Snort日志文件无法读取**
   ```bash
   # 检查文件路径和权限
   ls -la /var/log/snort/alert_fast.txt
   sudo chmod 644 /var/log/snort/alert_fast.txt
   ```

3. **WebSocket连接失败**
   - 检查防火墙设置
   - 确认端口可访问
   - 检查 Nginx 配置是否正确代理 WebSocket

4. **ML分析器未启动**
   - 检查 `ml_analyzer.py` 是否存在
   - 查看日志中的错误信息

5. **内存占用过高**
   - 调整 `alerts_storage` 限制
   - 减少批处理队列大小

### 日志查看
```bash
# 查看应用日志
tail -f app.log

# 查看系统服务日志
journalctl -u snort3 -f
```

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端框架 | Flask |
| 实时通信 | Flask-SocketIO + WebSocket |
| 数据库 | SQLite |
| 前端框架 | Bootstrap 5 |
| 图表库 | Chart.js |
| 日志解析 | 正则表达式 |
| 机器学习 | 特征工程 + 加权模型 |

## 系统要求

- **操作系统**：Ubuntu 20.04+ / macOS / Windows
- **Python**：3.8 或更高版本
- **内存**：建议 ≥ 4GB
- **磁盘空间**：≥ 10GB（日志和数据库）

## 许可证

Apache License 2.0

## 更新日志

### v1.0.0
- 初始版本发布
- 支持 Snort3 日志实时监控
- 集成机器学习置信度分析
- 完整的Web仪表盘界面
- 威胁情报分析功能
