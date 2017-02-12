FROM ubuntu:16.04
MAINTAINER toolbox@cloudpassage.com

RUN apt-get update && apt-get install -y curl apt-transport-https

RUN echo 'deb https://production.packages.cloudpassage.com/debian debian main' > /etc/apt/sources.list.d/cloudpassage.list
RUN curl https://production.packages.cloudpassage.com/cloudpassage.packages.key | apt-key add -

RUN apt-get update && apt-get install -y wordpress cphalo

CMD /opt/cloudpassage/bin/configure --agent-key=${AGENT_KEY}; /opt/cloudpassage/bin/cphalo
