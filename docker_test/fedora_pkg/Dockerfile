FROM fedora:latest
MAINTAINER toolbox@cloudpassage.com

RUN echo "[cloudpassage]" > /etc/yum.repos.d/cloudpassage.repo
RUN echo "name=CloudPassage" >> /etc/yum.repos.d/cloudpassage.repo
RUN echo "baseurl=https://production.packages.cloudpassage.com/redhat/x86_64" >> /etc/yum.repos.d/cloudpassage.repo
RUN echo "gpgcheck=1" >> /etc/yum.repos.d/cloudpassage.repo

RUN rpm --import https://production.packages.cloudpassage.com/cloudpassage.packages.key

RUN yum install -y wordpress

RUN yum install -y cphalo

CMD /opt/cloudpassage/bin/configure --agent-key=${AGENT_KEY}; /opt/cloudpassage/bin/cphalo
