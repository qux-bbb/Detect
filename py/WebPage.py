# coding:utf8

import requests
import re
import urlparse

from py.utils import get_regex_signatures, log_p
from py.conf import home_dir

import sys
reload(sys)
sys.setdefaultencoding('utf8')


class WebPage():
    '''
    扫描指定网页
    '''


    def __init__(self):
        # 一些文件 如 图片，css文件，不分析，直接跳过
        self.ignore_tails = ['.jpg', '.JPG', '.png', '.gif', '.ico', '.css', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
                '.ppt', 'pptx', '.apk', '.wav', '.WAV', '.zip', '.rar', '.7z']
        self.regex_signatures = get_regex_signatures(home_dir + '/resource/webpage_regex_signatures.txt')
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0',
            'Referer': 'http://www.google.com',
        }


    def ignore_it(self, url):
        url_path = urlparse.urlparse(url).path
        for tail in self.ignore_tails:
            if url_path.endswith(tail):
                return True
        return False


    def content_detect(self, content):
        '''
        根据正则串检测是否有挖矿特征存在，需要增强，&&&&&&&
        :param content: 要检测的页面内容
        :return: list形式的页面可疑内容
        '''
        all_finds = []
        for regex_signature in self.regex_signatures:
            finds = re.findall(regex_signature, content)
            if finds:
                all_finds.extend(finds)
        unique_all_finds = list(set(all_finds))
        unique_all_finds.sort(key=all_finds.index)
        return unique_all_finds


    def del_url_para(self, url):
        '''
        删除url参数
        类似这样的形式 http://a.com?b=c 或者 http://a.com/b/c?d=e
        处理为 http://a.com 或者 http://a.com/b/c
        :param url: 要处理的url
        :return: 去除参数的url
        '''
        if '?' in url:
            url = url.split('?')[0]
        return url

    def already_have_the_url(self, url, urls):
        '''
        判断url是否早已存在于urls中，不同参数算作同一url
        :param url: 单个url
        :param urls: list形式的url
        :return: 是否存在
        '''
        exist_already = False
        tmp_url = self.del_url_para(url)
        for u in urls:
            u = self.del_url_para(u)
            if tmp_url == u:
                exist_already = True
                break
        return exist_already


    def site_scan(self, main_url):
        '''
        寻找该url所在网站的所有url并检测
        (为简化，忽略所有参数，因为挖矿木马的部署不会太过动态，应该会尽可能容易让用户加载到
         如果不忽略参数，扫描体量会很大)
        :param url: 传入的一个url，可能是域名，也可能比域名多一些东西
        :return: None
        '''
        find_flag = False # 是否发现挖矿特征的标志

        main_url = main_url.strip()

        # 包含所有url，不确定url是否有效
        urls = []
        # 包含所有请求有效且页面类型为text/html的url
        valid_urls = []


        # 种子url的添加
        try:
            res = requests.get(main_url, headers=self.headers, timeout=20)
        except Exception as e:
            print '[!] ' + str(e.__class__) + main_url
            return
        urls.append(res.url)

        urlparse_res_url = urlparse.urlparse(res.url)
        domain_url = urlparse_res_url.scheme + '://' + urlparse_res_url.netloc
        if domain_url != res.url and domain_url + '/' != res.url:
            urls.append(domain_url)

        for url in urls:
            if len(url) == 0:  # href=''
                continue

            if self.ignore_it(url):
                continue

            try:
                res = requests.get(url, headers=self.headers, timeout=20)
            except Exception as e:
                log_p('[!] ' + str(e.__class__)) + url
                continue

            code_str = str(res.status_code)
            if code_str.startswith('2') or code_str.startswith('3'):
                # ignore没有忽略掉，但是不需要分析的类型  只分析text/html、application/javascript类型的页面
                if 'text/html' in res.headers['Content-Type'] or 'application/javascript' in res.headers['Content-Type']:
                    valid_urls.append(res.url)
                    all_finds = self.content_detect(res.content)
                    if all_finds:
                        find_flag = True
                        log_p('[*] Find Something in %s'%res.url)
                        log_p('\n'.join(all_finds))
                else:
                    continue
                if 'application/javascript' in res.headers['Content-Type']: # js文件只检测内容，不分析url
                    continue

            half_urls = re.findall(r'(?:href|src|action)\s?=\s?\"(.*?)\"', res.content)
            half_urls.extend(re.findall(r'(?:href|src|action)\s?=\s?\'(.*?)\'', res.content))
            for half_url in half_urls:
                join_url = urlparse.urljoin(res.url, half_url)
                if self.del_url_para(join_url).endswith('.js'): # js文件就算不在本站，也需要检测一下内容
                    if not self.already_have_the_url(join_url, urls):
                        urls.append(join_url)
                elif domain_url in join_url:  # 在本域名下
                    if join_url != res.url and not self.already_have_the_url(join_url, urls):
                        urls.append(join_url)

        if not find_flag:
            print '[*] Nothing'
        log_p('[*] Scan Finish, count %d urls'%len(valid_urls))


    def page_scan(self, main_url):
        '''
        扫描单个网页内容，包括网页中包含的js文件
        :param main_url: 要检测的页面
        :return: None
        '''
        find_flag = False # 是否发现挖矿特征的标志
        main_url = main_url.strip()
        try:
            res = requests.get(main_url, headers=self.headers, timeout=20)
        except Exception as e:
            log_p('[!] ' + str(e.__class__) + main_url)
            return
        all_finds = self.content_detect(res.content)
        if all_finds:
            find_flag = True
            log_p('[*] Find Something in %s' % res.url)
            log_p('\n'.join(all_finds))

        half_urls = re.findall(r'(?:href|src|action)\s?=\s?\"(.*?)\"', res.content)
        half_urls.extend(re.findall(r'(?:href|src|action)\s?=\s?\'(.*?)\'', res.content))
        half_urls = list(set(half_urls)) # 去重
        for half_url in half_urls:
            join_url = urlparse.urljoin(res.url, half_url)
            if self.del_url_para(join_url).endswith('.js'):  # 检测js文件
                try:
                    res = requests.get(join_url, headers=self.headers, timeout=20)
                except Exception as e:
                    log_p('[!] ' + str(e.__class__) + main_url)
                    continue
                all_finds = self.content_detect(res.content)
                if all_finds:
                    find_flag = True
                    log_p('[*] Find Something in %s' % res.url)
                    log_p('\n'.join(all_finds))
        if not find_flag:
            print '[*] Nothing'


    def scan(self, url, whole_site):
        '''
        网页扫描入口
        :param url: 要扫描的页面或网站
        :param whole_site: 值为True则扫描整个网站
        :return: None
        '''
        if whole_site:
            self.site_scan(url)
        else:
            self.page_scan(url)