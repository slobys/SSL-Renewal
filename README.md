# SSL一键申请
## 脚本功能
* 一键申请SSL证书  
* 关闭防火墙/放行端口  
* 选择SSL证书颁发机构（增加申请成功率）  
* 证书自动续期（正在优化）  

## 安装git
```bash
apt install git -y
```
## 一键脚本
```bash
git clone https://github.com/slobys/SSL-Renewal.git /tmp/acme && mv /tmp/acme/* /root
bash acme_2.0.sh
```
