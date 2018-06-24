# coding:utf8

from scapy.all import *

from utils import get_regex_signatures,get_domain_ips, log_p
from py.conf import home_dir


class Pcap():
    '''
    扫描pcap文件
    '''
    def __init__(self):
        # 流量包中可能有网页内容，所以添加webpage_regex_signatures.txt中的特征
        self.regex_signatures = get_regex_signatures(home_dir + '/resource/webpage_regex_signatures.txt')
        self.regex_signatures.extend(get_regex_signatures(home_dir + '/resource/pcap_regex_signatures.txt'))


    def get_ip_domains(self):
        '''
        获取ip_domains字典
        这样的顺序是因为是一对多的关系
        :return: dict形式的ip_domain
        '''
        domain_ips = get_domain_ips()

        ip_domain_dict = {}
        for domain_ip in domain_ips:
            domain,ip = domain_ip.split(':')
            if ip in ip_domain_dict.keys():
                ip_domain_dict[ip] = ip_domain_dict[ip] + ',' + domain
            else:
                ip_domain_dict[ip] = domain
        return ip_domain_dict


    def content_detect(self, content):
        '''
        根据正则串检测是否有挖矿特征存在，需要增强，&&&&&&&
        :param content: 要检测的内容
        :return: list形式的可疑内容
        '''
        all_finds = []
        for regex_signature in self.regex_signatures:
            finds = re.findall(regex_signature, content)
            if finds:
                all_finds.extend(finds)
        return all_finds


    def scan(self, file_name=None, iface=None, count=0, timeout=None, save_pcap=False):
        '''
        扫描pcap文件或者监听到的流量，判断是否有挖矿流量特征
        :param file_name: 要扫描的pcap文件
        :param iface: 要监听的网卡接口
        :param count: 监听的package数量
        :param timeout: 监听的时间
        :param save_pcap: 是否保存监听的packages
        :return: None
        '''
        if file_name:
            caps = rdpcap(file_name)
        else:
            log_p('[*] Start to sniff packages...')
            caps = sniff(iface=iface, count=count, timeout=timeout)
            log_p('[*] Sniff packages finish')
            if save_pcap:
                wrpcap(home_dir + '/result.pcapng', caps)
        ip_domains = self.get_ip_domains()

        bad_ip = []
        exist_finds = []
        for i in xrange(len(caps)):
            try:
                caps[i]['IP']
                src = caps[i]['IP'].src
                dst = caps[i]['IP'].src
                if src in ip_domains.keys() and src not in bad_ip:
                    bad_ip.append(src)
                    log_p('[*] Find bad ip_domain:\n%s:%s'%(src, ip_domains[src]))
                if dst in ip_domains.keys() and dst not in bad_ip:
                    bad_ip.append(dst)
                    log_p('[*] Find bad ip_domain:\n%s:%s'%(dst, ip_domains[dst]))
            except:
                pass

            try:
                caps[i]['Raw']
                all_finds = self.content_detect(caps[i]['Raw'].load)
                if all_finds and all_finds[0] not in exist_finds:
                    exist_finds.append(all_finds[0])
                    log_p('[*] Find Something in No.%d package'%(i+1)) # i从0开始计数
                    log_p(all_finds[0]) # 全部输出太多，只输出匹配类型的第一个
            except:
                pass

        if not bad_ip and not exist_finds:
            print '[*] Nothing'
        log_p('[*] Scan Finish, count %d packages'%len(caps))