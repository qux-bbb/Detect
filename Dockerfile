# Detect

FROM python:2.7

WORKDIR /home/

# 添加程序代码
COPY / /home/detect/

# 安装模块
RUN pip install -r /home/detect/requirements.txt

# 开一个bash
ENTRYPOINT [ "/bin/bash" ]