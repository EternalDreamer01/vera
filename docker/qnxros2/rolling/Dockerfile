# Download base image ubuntu 18.04
FROM ubuntu:20.04

# LABEL about the custom image
LABEL maintainer="asobhy@blackberry.com"
LABEL version="0.2.4"
LABEL description="Docker image for building ROS2 for QNX."

# Disable Prompt During Packages Installation
ARG DEBIAN_FRONTEND=noninteractive

# set to the distribution being used by passing it as an argument eg: docker build --build-arg ROS2DIST=foxy -t qnxros2_foxy .
ARG ROS2DIST=$ROS2DIST
ENV ROS2DIST=$ROS2DIST

# Set locale
RUN apt-get clean && apt update && apt install -y locales software-properties-common
RUN locale-gen en_US en_US.UTF-8 && \
	update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 && \
	export LANG=en_US.UTF-8

# Add ROS2 apt repository
RUN apt update && apt install -y curl gnupg2 lsb-release && \
	curl -s https://raw.githubusercontent.com/ros/rosdistro/master/ros.asc | apt-key add - && \
	sh -c 'echo "deb [arch=$(dpkg --print-architecture)] http://packages.ros.org/ros2/ubuntu $(lsb_release -cs) main" > /etc/apt/sources.list.d/ros2-latest.list'

# Build tools needed for building dependencies
RUN apt update && apt install -y \
	build-essential \
  	git \
  	libbullet-dev \
  	python3-colcon-common-extensions \
  	python3-flake8 \
	python3-pip \
	python3-pytest-cov \
	python3-rosdep \
	python3-setuptools \
	python3-vcstool \
	wget \
	bc \
	subversion \
	autoconf \
	libtool-bin \
	libssl-dev \
	zlib1g-dev \
	rsync \
	rename

ENV PY_VER=3.9
# Install python 3.11
RUN add-apt-repository ppa:deadsnakes/ppa -y && \
	apt-get update && apt-get upgrade -y
RUN apt-get install -y \
	python$PY_VER-dev \
	python$PY_VER-venv \
	python$PY_VER-distutils \
	rename

WORKDIR /usr/bin
RUN rm python3 && ln -s python$PY_VER python3

# Install CMake 3.18
RUN cd /opt && sudo wget https://cmake.org/files/v3.18/cmake-3.18.0-Linux-x86_64.sh && \
	sudo mkdir /opt/cmake-3.18.0-Linux-x86_64 && \
	yes | sudo sh cmake-3.18.0-Linux-x86_64.sh --prefix=/opt/cmake-3.18.0-Linux-x86_64 --skip-license && \
	sudo ln -s /opt/cmake-3.18.0-Linux-x86_64/bin/cmake /usr/local/bin/cmake

RUN apt autoremove && apt clean

# Adding user
ARG USER_NAME
ARG GROUP_NAME
ARG USER_ID
ARG GROUP_ID

RUN groupadd --gid ${GROUP_ID} ${GROUP_NAME} && \
	useradd --uid ${USER_ID} --gid ${GROUP_ID} --groups sudo --no-log-init --create-home ${USER_NAME} && \
	echo "${USER_NAME}:password" | chpasswd
WORKDIR /home/${USER_NAME}
USER ${USER_NAME}

# Install standard ROS 2 development tools
# Install pip packages needed for testing
# Needed to build numpy from source
RUN cd /home/${USER_NAME} && \
	python$PY_VER -m venv env && \
	. ./env/bin/activate && \
	python3 -m pip install -U \
	argcomplete \
	flake8-blind-except \
	flake8-builtins \
	flake8-class-newline \
	flake8-comprehensions \
	flake8-deprecated \
	flake8-docstrings \
	flake8-import-order \
	flake8-quotes \
	pytest-repeat \
	pytest-rerunfailures \
	pytest \
	setuptools \
	importlib-metadata \
	importlib-resources \
	Cython==0.29.35 \
	numpy \
	catkin_pkg \
	empy==3.3.4 \
	lark-parser

# Get ROS 2 code
RUN	mkdir -p ros2_${ROS2DIST}/src && \
	cd ros2_${ROS2DIST} && \
	if [ "${ROS2DIST}" = "rolling" ] ; then BRANCH=master ; else BRANCH=${ROS2DIST} ; fi && \
	wget https://raw.githubusercontent.com/ros2/ros2/${BRANCH}/ros2.repos && \
	vcs import src < ros2.repos

# QNX SDP8.0 should be installed on system before creating an image
# QNX SDP8.0 directory should be named qnx800
# ~/qnx800 directory will have to be copied over to the build context directory
ENV QNX_DIR=qnx800
COPY --chown=${USER_NAME}:${GROUP_NAME} ${QNX_DIR} /home/${USER_NAME}/${QNX_DIR}

# Setup host for Cross-compiling for QNX
RUN cd ros2_${ROS2DIST} && \
        if [ "${ROS2DIST}" = "rolling" ] ; then BRANCH=master ; else BRANCH=${ROS2DIST} ; fi && \
	git clone -b ${BRANCH} https://gitlab.com/qnx/frameworks/ros2/ros2_qnx.git /tmp/ros2 && \
	rsync -haz /tmp/ros2/* . && \
	rm -rf /tmp/ros2

# Import QNX dependency repositories
RUN cd ros2_${ROS2DIST} && \
	mkdir -p src/qnx_deps && \
	vcs import src/qnx_deps < qnx_deps.repos

# RUN cd ros2_${ROS2DIST} && \
# 	./patch-pkgxml.py --path=src && \
# 	./colcon-ignore.sh && \
# 	touch ./src/eclipse-cyclonedds/COLCON_IGNORE && \
# 	touch ./src/qnx_deps/cyclonedds_vendor/COLCON_IGNORE

# Clone empty ROS2 package workspace
RUN git clone https://gitlab.com/qnx/frameworks/ros2/dev_ws

# Welcome Message
COPY --chown=${USER_NAME}:${GROUP_NAME} ".welcome.bash" "/home/${USER_NAME}"
RUN echo "source /home/${USER_NAME}/.welcome.bash\n" >> "/home/${USER_NAME}/.bashrc"

ENV CPU=x86_64
ENV QNX_HOST=/home/${USER_NAME}/${QNX_DIR}/host/linux/${CPU}
ENV QNX_TARGET=/home/${USER_NAME}/${QNX_DIR}/target/qnx
ENV MAKEFLAGS=-I/home/${USER_NAME}/${QNX_DIR}/target/qnx/usr/include

# WORKDIR /home/${USER_NAME}/ros2_${ROS2DIST}
# # RUN sed -Ei 's/(python-{0,1})3(.){0,1}8/\13\211/g' ./platform/qnx.nto.toolchain.cmake
# RUN find * -type f \( -iname "*.sh" -o -iname "*.py" \) -exec sed -Ei 's/(python-{0,1})3(.){0,1}8/\13\211/gi' {} \;
# RUN ./build-ros2.sh

CMD ["/bin/bash"]
