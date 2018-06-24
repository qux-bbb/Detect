# coding:utf8

import os
from optparse import OptionParser

from py.WebPage import WebPage
from py.Pcap import Pcap
from py.utils import clear_log


if __name__ == '__main__':

    parser = OptionParser(
        'Usage:    python Detect.py [options]\n'
        'Example:\n'
        '  Detect single webpage: python Detect.py -a webpage -u https://www.baidu.com\n'
        '  Detect whole website: python Detect.py -a webpage -u https://www.baidu.com -w\n'
        '  Detect pcap file: python Detect.py -a pcap -f hello.pcapng\n'
        '  Detect sniffed 50 packages: python Detect.py -a pcap -c 50\n'
        '  Update some files: python Detect.py --update\n')

    parser.add_option('-a', '--action', dest='action', help='what to do, could be one of them: webpage | pcap')
    parser.add_option('-f', '--file', dest='pcap_file', help='the pcap file to scan, if action is pcap, this option is valid')
    parser.add_option('-u', '--url', dest='url', help='the url or website to scan, if action is webpage, this option is valid')
    parser.add_option('-w', '--whole_site', action='store_true', dest='whole_site', default=False, help='need to scan whole website, if action is webpage, this option is valid')
    parser.add_option('-i', '--interface', dest='interface', help='the interface to sniff, if action is pcap and have not -f, this option is valid, can only be used under linux')
    parser.add_option('-c', '--count', type='int', dest='sniff_caps_count', help='the count of  caps to sniff, if action is pcap and have not -f, this option is valid')
    parser.add_option('-t', '--time', type='int', dest='sniff_time', help='the time(seconds) to sniff, if action is pcap and have not -f, this option is valid, only -c or -t')
    parser.add_option('-s', '--save', action='store_true', dest='save_pcap', default=False, help='save the packages sniffed, if action is pcap and have not -f, this option is valid')
    parser.add_option('--update', action='store_true', dest='update_ip',
                      default=False, help='update resource file "domain_ip"')

    (options, args) = parser.parse_args()

    action = options.action
    pcap_file = options.pcap_file
    url = options.url
    whole_site = options.whole_site
    net_interface = options.interface
    sniff_caps_count = options.sniff_caps_count
    sniff_time = options.sniff_time
    save_pcap = options.save_pcap
    update_ip = options.update_ip

    try:

        clear_log()

        if update_ip:
            from py.utils import update_domain_ips
            update_domain_ips()
            exit(0)

        if action not in ['webpage', 'pcap']:
            parser.print_help()
            exit(0)

        if action == 'webpage':
            if not url:
                print '[!] Need -u option'
            elif not url.startswith('http://') and not url.startswith('https://'):
                print '[!] -u Url need to start with "http://" or "https://"'
            else:
                webpage = WebPage()
                webpage.scan(url, whole_site)
        else:
            if pcap_file:
                if not os.path.exists(pcap_file):
                    print '[!] -f File does not exist'
                elif not os.path.isfile(pcap_file):
                    print '[!] -f This is not a file'
                else:
                    pcap = Pcap()
                    pcap.scan(file_name=pcap_file)
            elif not sniff_caps_count and not sniff_time:
                print '[!] Need -c or -t option'
            else:
                pcap = Pcap()
                if sniff_caps_count:
                    pcap.scan(iface=net_interface, count=sniff_caps_count, save_pcap=save_pcap)
                else:
                    pcap.scan(iface=net_interface, timeout=sniff_time, save_pcap=save_pcap)

    except KeyboardInterrupt:
        print('Interrupted by user')
        exit()
