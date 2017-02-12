FROM ubuntu:16.04
MAINTAINER toolbox@cloudpassage.com

RUN apt-get update && apt-get install -y curl apt-transport-https wget

RUN echo 'deb https://production.packages.cloudpassage.com/debian debian main' > /etc/apt/sources.list.d/cloudpassage.list
RUN curl https://production.packages.cloudpassage.com/cloudpassage.packages.key | apt-key add -

RUN apt-get update && apt-get install -y apache2 cphalo

WORKDIR /src

RUN wget https://wordpress.org/wordpress-4.7.tar.gz

RUN tar -zxvf wordpress-4.7.tar.gz -C /var/www/html

CMD /opt/cloudpassage/bin/configure --agent-key=${AGENT_KEY}; /opt/cloudpassage/bin/cphalo
