FROM agl

WORKDIR /tmp
RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/zypper-1.14.92-1.1.x86_64.rpm
RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/libzypp-17.37.11-1.1.x86_64.rpm
RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/libsolv-tools-0.7.34-1.2.x86_64.rpm
RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/rpm-4.20.1-5.1.x86_64.rpm
RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/curl-8.14.1-6.1.x86_64.rpm
RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/libcurl4-8.14.1-6.1.x86_64.rpm

# Is this correct?
RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/libopenssl3-3.5.1-1.1.x86_64.rpm
# RUN wget https://ftp.lysator.liu.se/pub/opensuse/distribution/leap/15.6/repo/oss/x86_64/libopenssl1_1-1.1.1w-150600.3.10.x86_64.rpm

RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/libxml2-2-2.13.8-2.1.x86_64.rpm
RUN wget https://download.opensuse.org/tumbleweed/repo/oss/x86_64/libsqlite3-0-3.50.2-1.1.x86_64.rpm

RUN rpm -Uvh --nodeps *.rpm

CMD ["/bin/bash"]