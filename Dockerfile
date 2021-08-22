# FROM <イメージ名>:<バージョンタグ>
# このイメージを元に使って
FROM ubuntu:16.04

# pip pipenv INSTALL
WORKDIR /root
#RUN curl -kL https://bootstrap.pypa.io/pip/3.5/get-pip.py | python3
RUN bash

# SSH config
RUN mkdir ~/.ssh
RUN chmod 700 ~/.ssh
RUN touch ~/.ssh/authorized_keys
RUN chmod 600 ~/.ssh/authorized_keys
RUN rm /etc/ssh/ssh_host_*key*

CMD ["/bin/bash"]

