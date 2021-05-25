# homenc_and_SIEM_data

First clone both repositories

```
git clone https://github.com/kapiekarz/homenc_and_SIEM_data.git
git clone https://github.com/homenc/HElib.git
```

Then build the HElib library

```
cd HElib
mkdir buid
cd build
cmake -DPACKAGE_BUILD=ON ..
make -j16
```

If the build won't work, you may need to install additional packages

```
sudo apt-get install build-essential pthreads libpthread-stubs0-dev cmake m4 patchelf
```

Build and run the main script (adjust path accordingly)

```
cd ../../homenc_and_SIEM_data/projects/base_operations/
cmake -Dhelib_DIR=/home/kpiekarz/repos/HElib/build/helib_pack/share/cmake/helib .
cmake .
make
./build_operations
```

For further build and run just use these two commands

```
make
./build_operations
```