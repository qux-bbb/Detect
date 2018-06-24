# coding:utf8

# 主目录，在读取文件，资源文件时用
import os
import platform
home_dir = os.path.dirname(__file__)[:-3]
now_plat = platform.system()