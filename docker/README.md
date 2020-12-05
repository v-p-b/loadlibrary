mpscript container
==================

This is a container to play with (fuzz) [Windows Defender's JavaScript engine](https://github.com/0xAlexei/Publications/tree/master/Reverse%20Engineering%20Windows%20Defender). The image contains a 32-bit userland so you don't have to clobber your system with libeverything:i686. Tavis Ormandy's [loadlibrary](https://github.com/taviso/loadlibrary) is pulled from a fork that includes the original `mpscript` wrapper. A separate branch (intelpt) contains code for persistent fuzzing. 

Build the conainer:

    docker build -t mpengine .

Run the container:

    docker run --privileged -v /path/to/your/corpus:/mnt -v /path/to/mpengine/files:/root/loadlibrary/engine -it mpengine

Test case minimization with [honggfuzz](https://github.com/google/honggfuzz):

    cd loadlibrary
    git checkout intelpt
    ../honggfuzz/honggfuzz --linux_perf_ipt_block -Q -P -i /mnt/ --minimize --timeout 10 -- ./mpscript
