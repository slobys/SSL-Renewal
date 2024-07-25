# SSL一键申请
## 脚本功能
* 一键申请SSL证书  
* 关闭防火墙/放行端口  
* 选择SSL证书颁发机构（增加申请成功率）  
* 证书自动续期  

## 安装git
```bash
sudo apt install git -y
```
* 如果执行后出错，请先更新系统
```bash
sudo apt update -y
```
## 一键脚本
```bash
git clone https://github.com/slobys/SSL-Renewal.git /tmp/acme && mv /tmp/acme/* /root
bash acme_2.0.sh
```
## 注意事项  
* 请不要用同一个域名频繁申请，这样容易出错
* 如果遇到出错可以参考以下解决办法  
  1、换个域名申请  
  2、换个时间再申请  
  
