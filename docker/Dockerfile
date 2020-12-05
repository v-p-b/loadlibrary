FROM  ubuntu@sha256:8dcc8cd61c36a338d35662307ae2f23e00f407bae2281caf95e25550504eb001 
WORKDIR /root
RUN apt-get update
RUN apt install -y git vim wget apt-transport-https build-essential libc6-dev gcc-multilib libreadline-dev cabextract binutils-dev bsdmainutils libunwind-dev liblzma-dev nasm cmake
RUN bash -c "wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -"
RUN bash -c "echo 'deb http://apt.llvm.org/xenial/   llvm-toolchain-xenial-7  main' >> /etc/apt/sources.list"
RUN apt-get update
RUN apt install -y clang-7
RUN git clone https://github.com/intel/libipt
RUN bash -c "cd libipt;mkdir build;cd build; cmake ..;make;make install;cd ../.."
RUN git clone https://github.com/google/honggfuzz
RUN bash -c "cd honggfuzz;make;cd .."
RUN git clone https://github.com/v-p-b/loadlibrary
RUN bash -c "cd loadlibrary;git checkout intelpt;make;make mpscript;cd .."
