# Detect

## 功能简介  
本检测工具可检测网页内容，流量包内容的某些特征  

## 环境配置
python 2.7，从requirements.txt安装相应模块  


## 资源及文本文件说明

由于windows和linux的换行不同，windows是CRLF，linux是LF，所以如果更换系统，配置文件的换行需要自行处理  

资源文件在resource文件夹  

**pcap_domain_ips.txt**  
用于检测流量包中是否有黑名单ip  
正则特征库，'# '为注释符(#后要加一个空格)，空行程序自行忽略  
域名-ip对，每行格式如：'hello.com:1.2.3.4'  
可自行添加域名，添加格式为：'world.com:'  
可使用程序命令更新域名对应的ip，命令为：`python Detect.py --update`  

**webpage_regex_signatures.txt**  
用于检测网页中是否有某些特征  
正则特征库，'# '为注释符，空行程序自行忽略  
需手动更新  

**pcap_regex_signatures.txt**  
正则特征库，'# '为注释符，空行程序自行忽略  
需手动更新  

**log**  
日志文件  
存储上一次扫描的部分信息  


## 使用说明
```
Usage:    python Detect.py [options]
Example:
  Detect single webpage: python Detect.py -a webpage -u https://www.baidu.com
  Detect whole website: python Detect.py -a webpage -u https://www.baidu.com -w
  Detect pcap file: python Detect.py -a pcap -f hello.pcapng
  Detect sniffed 50 packages: python Detect.py -a pcap -c 50
  Update some files: python Detect.py --update


Options:
  -h, --help            show this help message and exit
  -a ACTION, --action=ACTION
                        what to do, could be one of them: webpage | pcap
  -f PCAP_FILE, --file=PCAP_FILE
                        the pcap file to scan, if action is pcap, this option
                        is valid
  -u URL, --url=URL     the url or website to scan, if action is webpage, this
                        option is valid
  -w, --whole_site      need to scan whole website, if action is webpage, this
                        option is valid
  -i INTERFACE, --interface=INTERFACE
                        the interface to sniff, if action is pcap and have not
                        -f, this option is valid, can only be used under linux
  -c SNIFF_CAPS_COUNT, --count=SNIFF_CAPS_COUNT
                        the count of  caps to sniff, if action is pcap and
                        have not -f, this option is valid
  -t SNIFF_TIME, --time=SNIFF_TIME
                        the time(seconds) to sniff, if action is pcap and have
                        not -f, this option is valid, only -c or -t
  -s, --save            save the packages sniffed, if action is pcap and have
                        not -f, this option is valid
  --update              update resource file "domain_ip"
```


一些测试文件在test_file文件夹中  
以windows系统举例，测试例子：  
网页检测：  
```
python Detect.py -a webpage -u http://www.masterputi.com/test1
```
网站检测：  
```
python Detect.py -a webpage -u http://www.masterputi.com -w
```
流量包检测：  
```
python Detect.py -a pcap -f test_file\5minutes.pcapng
```
半实时流量检测(指定时间10秒，捕获流量包保存为result.pcapng)：  
```
python Detect.py -a pcap -t 10
```
半实时流量检测(指定捕获包数50，捕获流量包保存为result.pcapng)：  
```
python Detect.py -a pcap -c 50
```