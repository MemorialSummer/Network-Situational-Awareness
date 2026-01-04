# Snort3 部署手册（基于 Ubuntu 22.04）

## 适用场景
- 平台：Ubuntu（桌面版）
- 环境：VMware 虚拟机 / 服务器
- 目标：完成 Snort3 的安装、网络配置、规则加载与服务部署

---

## 一、创建 Ubuntu 虚拟机

- 使用镜像：`ubuntu-22.04.5-desktop-amd64.iso`（建议从清华源下载）
- 建议配置：内存 ≥ 4GB，磁盘 ≥ 40GB
- 安装完成后进入系统，打开终端，开始后续操作

---

## 二、安装 Snort3

### 1. 更新软件源
```bash
sudo apt update
```

### 2. 安装依赖包

如果遇到apt不成功的情况，请查找是否是更新后apt包名发生了变化。

```bash
sudo apt install build-essential libpcap-dev libdumbnet-dev libpcre2-dev libdnet-dev zlib1g-dev liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake libsqlite3-dev uuid-dev libnetfilter-queue-dev libluajit-5.1-dev flex bison cpputest libcmocka-dev git libtool ethtool -y
```

### 3. 安装 Snort DAQ

如果git失败，请检查是否安装了git。没安装的话请使用'sudo apt install git'，并且检查网络是否能够访问到github。

```bash
mkdir ~/Snort && cd ~/Snort
git clone https://github.com/snort3/libdaq.git

cd libdaq
./bootstrap
./configure --prefix=/usr/local
make
sudo make install
sudo ldconfig
```

### 4. 安装 Snort3
```bash
cd ~/Snort
git clone https://github.com/snort3/snort3.git

cd snort3
./configure_cmake.sh --prefix=/usr/local
cd build
make
sudo make install
sudo ldconfig
```

### ✅ 验证安装
```bash
snort -V
```
输出版本信息即表示安装成功。

---

## 三、配置网络（混杂模式 + 关闭 offloading）

### 1. 查看网络接口名称
```bash
ip addr
```
一般为 `ens***`

### 2. 检查接收卸载状态

请把***换成你自己服务器使用的网口。

```bash
sudo ethtool -k ens*** | grep receive-offload
```
确保以下两项中有一项为 `on`（后续将关闭）：
- `generic-receive-offload`
- `large-receive-offload`

### 3. 创建服务文件设置网络
```bash
sudo nano /lib/systemd/system/ethtool.service
```

填入以下内容（将 `ens33` 替换为你的接口名）：
```ini
[Unit]
Description=Ethtool Configuration for Network Interface

[Service]
Requires=network.target
Type=oneshot
ExecStart=/sbin/ethtool -K ens*** gro off
ExecStart=/sbin/ethtool -K ens*** lro off
ExecStart=/sbin/ip link set ens*** promisc on

[Install]
WantedBy=multi-user.target
```

保存并退出：
```bash
ctrl+x --> y --> Enter
```

### 4. 启用服务
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ethtool.service
```

### ✅ 验证网络配置
```bash
ip addr show ens***
ethtool -k ens*** | grep receive-offload
```
- 应看到 `PROMISC` 模式已开启
- `generic-receive-offload` 和 `large-receive-offload` 为 `off`

---

## 四、配置 Snort3 功能

### 1. 获取规则集与 OpenAppID

请注意存放路径不能为/home/用户名 的目录，存放会导致后续snort应用以snort用户权限访问的时候被AppArmor阻止。即使你给了snort用户访问的权限也无法绕过AppArmor的阻止不同用户互相访问。

- 下载地址：
  - 社区规则集：https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
  - OpenAppID：https://www.snort.org/downloads/openappid/33380
- 假设存放路径为：
  - `/etc/snort/rules/snort3-community-rules.tar.gz`
  - `/etc/snort/OpenAppID/snort-openappid.tar.gz`

解压，如果下载下来的是.tar文件请记得把-后面的z参数去掉：
```bash
cd /etc/snort/rules
tar -xzvf snort3-community-rules.tar.gz

cd /etc/snort/OpenAppID
tar -xzvf snort-openappid.tar.gz
```

### 2. 修改配置文件 `snort.lua`
```bash
sudo nano /usr/local/etc/snort/snort.lua
```

修改以下字段：

#### ✅ 设置 HOME_NET
```lua
HOME_NET = '192.168.***.***'  -- 替换为你的主机 IP 或网段,或者是需要被监测的网段。
EXTERNAL_NET = '!$HOME_NET'
```

#### ✅ 添加规则集路径
```lua
ips = {
  include = '/etc/snort/rules/snort3-community-rules/snort3-community.rules',
  variables = default_variables
}
```

#### ✅ 添加 OpenAppID 路径
```lua
appid = {
  app_detector_dir = '/etc/snort/OpenAppID',
  log_stats = true
}
```

#### ✅ 添加输出log

```lua
alert_fast = { file = true }
alert_json = { file = true }
```

请将对应的修改添加到模版的对应位置，模版中都有这些参数，其中alert_fast是被默认注释的。alert_json源模版没有请放在alert_fast的下一行。

保存并退出。

---

## 五、检查配置是否有效
```bash
snort -c /usr/local/etc/snort/snort.lua
```
输出中包含 `successfully` 表示配置无误。

---

## 六、部署为系统服务

### 1. 创建日志目录
```bash
mkdir -p /var/log/snort
```

### 2. 创建 snort 用户
```bash
sudo useradd -r -s /usr/sbin/nologin -M -c SNORT_IDS snort
```

### 3. 创建服务文件
```bash
sudo nano /etc/systemd/system/snort3.service
```

填入以下内容（路径、接口名按需修改）：
```ini
[Unit]
Description=Snort 3 NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -s 65535 -k none -l /var/log/snort -D -i ens33 -m 0x1b -u snort -g snort

[Install]
WantedBy=multi-user.target
```

### 4. 设置权限
```bash
sudo chown -R snort:snort /var/log/snort
sudo chmod -R 750 /var/log/snort
sudo find /var/log/snort -type f -exec chmod 640 {} \;
sudo systemctl daemon-reload
```

### 5. 启动服务并设置开机自启
```bash
sudo systemctl enable --now snort3.service
```

### ✅ 检查服务状态
```bash
sudo systemctl status snort3.service
```
看到 `active (running)` 表示部署成功。如果需要后续修改前面的配置或者规则集后请使用sudo systemctl restart snort3.service重新启动应用，并用sudo systemctl status snort3.service重新查看启动状态状态，配置和规则集并非热加载的。

---

## ✅ 部署完成

你现在拥有了一个运行在 Ubuntu 上的 Snort3 入侵检测系统，具备以下功能：

添加

- ✅ 网络接口已配置为混杂模式
- ✅ 规则集已加载
- ✅ OpenAppID 应用识别已启用
- ✅ Snort3 已作为系统服务运行
- ✅ 日志目录权限已正确设置，可以在/var/log/snort/alert_fast.txt中查看记录的警告。

如果需要添加规则集，可以直接在/etc/snort/rules/snort3-community-rules/snort3-community.rules中修改并添加，如若添加后发现项目应用无法运行。

## ✅ 后续运行awareness

将awareness放置于～目录下

```bash
cd ~/awareness
sudo apt install python3-pip
sudo pip install -r requirements.txt
sudo nohup python3 app.py > app.log 2>&1 &
```
