#!/bin/sh

mkdir -p build
cd build
cmake ../
make
./server &
./client
