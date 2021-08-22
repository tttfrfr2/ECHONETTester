# FROM <イメージ名>:<バージョンタグ>
# このイメージを元に使って
FROM ubuntu:16.04

# イメージの中にアプリ用ディレクトリを作成
RUN apt -y update
RUN apt -y install vim lsof iproute2 
RUN apt -y install git
RUN apt -y install curl make gcc zlib1g-dev libffi-dev libssl-dev
RUN apt -y install wget

# pip pipenv INSTALL
WORKDIR /root
#RUN curl -kL https://bootstrap.pypa.io/pip/3.5/get-pip.py | python3
RUN bash
RUN wget https://bootstrap.pypa.io/pip/3.5/get-pip.py 
WORKDIR /
RUN echo "export LC_ALL=C.UTF-8" >> /root/.bashrc
RUN echo "export LANG=C.UTF-8" >> /root/.bashrc
RUN echo "export PATH="/root/.pyenv/bin:$PATH"" >> /root/.bashrc
RUN echo 'eval "$(pyenv init -)"' >> /root/.bashrc
RUN echo 'eval "$(pyenv virtualenv-init -)"' >> /root/.bashrc
RUN curl https://pyenv.run | bash

# SSH config
RUN mkdir ~/.ssh
RUN chmod 700 ~/.ssh
RUN touch ~/.ssh/authorized_keys
RUN chmod 600 ~/.ssh/authorized_keys
RUN apt -y install openssh-server
RUN rm /etc/ssh/ssh_host_*key*
RUN dpkg-reconfigure openssh-server
# イメージの中の"cd"
# WORKDIR /opt/myapp

#ENTRYPOINT python3 get-pip.py && pip install pipenv && pipenv install numpy && pipenv install cryptography && pipenv install cryptography==3.0.0
ENTRYPOINT /etc/init.d/ssh restart && /bin/bash

