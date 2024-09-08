#!/bin/bash

gcc -mno-sse -mno-sse2 -mno-avx -fno-tree-vectorize -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -fPIC -mrdrnd \
	 -c stream_hash.c  
gcc -mno-sse -mno-sse2 -mno-avx -fno-tree-vectorize -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_Hash_SHA3.c

ar rcs libstream_hash.a Hacl_Hash_SHA3.o stream_hash.o 
mkdir -p ../../../libstream_hash/
cp libstream_hash.a ../../../libstream_hash/libstream_hash.a 
cp stream_hash.h ../../../../module/include/
cp libstream_hash.a ../../../../module/include/
