FROM ubuntu:16.04

ADD . /home/ubuntu/magicicada
COPY . /home/ubuntu/magicicada
WORKDIR /home/ubuntu/magicicada

RUN apt-get update && apt-get install make -y
RUN make docker-bootstrap

RUN useradd -ms /bin/bash ubuntu
RUN chown -R ubuntu:ubuntu /home/ubuntu

USER ubuntu
ENV HOME /home/ubuntu
ENV PG_HOST /home/ubuntu/pg_data
