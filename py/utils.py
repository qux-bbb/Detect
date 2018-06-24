# coding:utf8

import os
import re
import time
import socket
import subprocess

from py.conf import home_dir, now_plat


def get_regex_signatures(filename):
    '''
    读取正则形式的特征，处理成list格式
    :return: list形式的特征串
    '''
    regex_signatures_file = open(filename, 'r')
    origin_regex_signatures = regex_signatures_file.read().strip()
    regex_signatures_file.close()
    if now_plat == 'Windows':
        regex_signatures = re.sub('# .*\n', '', origin_regex_signatures).strip()
        regex_signatures = re.sub('\n{2,}', '\n', regex_signatures).split('\n')
    else:
        regex_signatures = re.sub('# .*\r\n', '', origin_regex_signatures).strip()
        regex_signatures = re.sub('(?:\r\n){2,}', '\r\n', regex_signatures).split('\r\n')

    return regex_signatures


def turn_domain_to_ip(domain):
    '''
    把域名解析成ip
    :param domain: 要解析的域名
    :return: 解析结果
    '''
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = None
    return ip


def update_domain_ips():
    '''
    重新解析域名到ip
    :return: None
    '''
    domain_ips_file = open(home_dir + '/resource/pcap_domain_ips.txt', 'r')

    domain_ips_content = domain_ips_file.read().strip()
    domain_ips_file.close()

    if now_plat == 'Windows':
        domain_ips = re.sub('#.*\n', '', domain_ips_content).strip()
        domain_ips = re.sub('\n{2,}', '\n', domain_ips).split('\n')
    else:
        domain_ips = re.sub('#.*\r\n', '', domain_ips_content).strip()
        domain_ips = re.sub('(?:\r\n){2,}', '\r\n', domain_ips).split('\r\n')

    fail_domains = []
    for domain_ip in domain_ips:
        domain = domain_ip.split(':')[0]
        ip = turn_domain_to_ip(domain)
        if not ip:
            fail_domains.append(domain)
            new_domain_ip = domain + ':'
        else:
            new_domain_ip = domain + ':' + ip
        domain_ips_content = re.sub(domain_ip, new_domain_ip, domain_ips_content)

    domain_ips_file = open(home_dir + '/resource/pcap_domain_ips.txt', 'w')
    domain_ips_file.write(domain_ips_content)
    domain_ips_file.close()

    if fail_domains:
        print '[!] The following domains updating failed:'
        print '\n'.join(fail_domains)
    else:
        print '[*] Domain_ip update Success'


def get_domain_ips():
    '''
    从文件读取domain_ips
    :return: list形式的domain_ip对
    '''
    domain_ips_file = open(home_dir + '/resource/pcap_domain_ips.txt', 'r')
    domain_ips_content = domain_ips_file.read().strip()
    domain_ips_file.close()

    if now_plat == 'Windows':
        domain_ips = re.sub('# .*\n', '', domain_ips_content).strip()
        domain_ips = re.sub('\n{2,}', '\n', domain_ips).split('\n')
    else:
        domain_ips = re.sub('# .*\r\n', '', domain_ips_content).strip()
        domain_ips = re.sub('(?:\r\n){2,}', '\r\n', domain_ips).split('\r\n')

    return domain_ips


def log(content):
    '''
    保存内容到log文件
    :param content: 要保存的内容
    :return: None
    '''
    log_file = open(home_dir + '/log', 'a')
    log_file.write(content + '\n')
    log_file.close()


def log_p(content):
    '''
    输出内容到终端并保存到log文件
    :param content: 要保存的内容
    :return: None
    '''
    print content
    log_file = open(home_dir + '/log', 'a')
    log_file.write(content + '\n')
    log_file.close()


def clear_log():
    '''
    删除log文件
    :return: None
    '''
    if os.path.exists(home_dir + '/log'):
        os.remove(home_dir + '/log')
