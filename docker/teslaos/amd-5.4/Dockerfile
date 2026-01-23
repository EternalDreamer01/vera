FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get clean && apt update && apt install -y \
	wget git make cmake fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison

# WORKDIR /
# ARG KERNEL_VERSION=5.4.295
# RUN wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${KERNEL_VERSION}.tar.xz
# RUN xz -cd linux-${KERNEL_VERSION}.tar.xz | tar xvf -
# WORKDIR /linux-${KERNEL_VERSION}

WORKDIR /teslaos
RUN git clone --progress --depth 1 --single-branch https://github.com/teslamotors/linux.git .

ENV TERM=xterm
ENV KCONFIG_NONINTERACTIVE=1
RUN yes "" | make oldconfig
RUN make -j8 -Oline
RUN make modules_install install
RUN make V=2 all

RUN apt install -y --install-recommends linux-generic
RUN apt upgrade -y

RUN git clone https://github.com/landley/toybox.git
WORKDIR /teslaos/toybox
RUN make defconfig
RUN make
RUN make install

RUN apt install -y --fix-broken \
    systemd \
    dbus-x11 \
    x11-apps
RUN apt install -y --fix-broken \
	bluetooth \
	flatpak
	# kdeconnect \
	# cheese \
	# powerdevil \
	# korganizer \
	# kodi
	# retroarch \
	# chromium-browser
# RUN flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
# RUN flatpak update
# RUN flatpak install flathub com.tidal.music

RUN apt autoremove && apt clean

CMD ["/bin/bash"]
