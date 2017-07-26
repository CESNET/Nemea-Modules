#Installation script for sysrepo and it's dependencies. First version, so far used only for testing.

yum install git cmake gcc gcc-c++ openssl-devel make bison flex pcre-devel libev-devel protobuf-c-devel valgrind swig python-devel

#install swig - repo version is too low
git clone https://github.com/swig/swig.git
cd swig
./autogen.sh
./configure
make
sudo make install
cd ..

#install CMOCKA - tool for unit testing
git clone git://git.cryptomilk.org/projects/cmocka.git
cd cmocka/
mkdir build; cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
sudo make install
cd ../..

#install libyang
git clone -b devel https://github.com/CESNET/libyang.git
cd libyang
mkdir build; cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
make
sudo make install
cd ../..

#install google proto buffers
apt-get install autoconf libtool
git clone -b https://github.com/google/protobuf.git
cd protobuf
./autogen.sh
./configure
make
sudo make install
cd ..

#installing libredblack
git clone https://github.com/sysrepo/libredblack.git
cd libredblack
./configure
make
sudo make install
cd ..

#installing sysrepo
git clone https://github.com/sysrepo/sysrepo.git
cd sysrepo
git checkout devel
mkdir build; cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX:PATH=/usr -DREPOSITORY_LOC:PATH=/etc/sysrepo -DPLUGINS_DIR:PATH=/opt/sysrepo/plugins -DBUILD_EXAMPLES:BOOL=FALSE ..
make
sudo make install
cd ../..
