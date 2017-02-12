FROM centos:7
MAINTAINER toolbox@cloudpassage.com

RUN echo "[cloudpassage]" > /etc/yum.repos.d/cloudpassage.repo
RUN echo "name=CloudPassage" >> /etc/yum.repos.d/cloudpassage.repo
RUN echo "baseurl=https://production.packages.cloudpassage.com/redhat/x86_64" >> /etc/yum.repos.d/cloudpassage.repo
RUN echo "gpgcheck=1" >> /etc/yum.repos.d/cloudpassage.repo

RUN rpm --import https://production.packages.cloudpassage.com/cloudpassage.packages.key

RUN yum install -y cphalo httpd wget

WORKDIR /src

RUN wget https://wordpress.org/wordpress-4.7.1.tar.gz

RUN tar -zxvf wordpress-4.7.1.tar.gz -C /var/www/html

CMD /opt/cloudpassage/bin/configure --agent-key=${AGENT_KEY}; /opt/cloudpassage/bin/cphalo
