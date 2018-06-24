# Detect

FROM python:2.7

WORKDIR /home/

# 添加程序代码及样本
COPY / /home/detect/

# 安装所需软件和依赖
RUN pip install -r /home/detect/requirements.txt

# 开一个bash
ENTRYPOINT [ "/bin/bash" ]