# FROM <イメージ名>:<バージョンタグ>
# このイメージを元に使って
FROM ubuntu:16.04

# イメージの中にアプリ用ディレクトリを作成
RUN apt -y update
RUN apt -y git
RUN apt -y install curl make gcc zlib1g-dev libffi-dev libssl-dev

ENTRYPOINT /etc/init.d/ssh restart && /bin/bash

