FROM ubuntu:16.04

ADD . /home/ubuntu/magicicada-server
COPY . /home/ubuntu/magicicada-server
WORKDIR /home/ubuntu/magicicada-server

RUN apt-get update && apt-get install make -y
RUN make docker-bootstrap

RUN useradd -ms /bin/bash ubuntu
RUN chown -R ubuntu:ubuntu /home/ubuntu

USER ubuntu
ENV HOME /home/ubuntu
ENV PG_HOST /home/ubuntu/pg_data
