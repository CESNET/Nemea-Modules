`Flow_meter` was moved to https://github.com/CESNET/ipfixprobe

To build it as a NEMEA module, configure it using `--with-nemea`, e.g.:
```
git clone https://github.com/CESNET/ipfixprobe
cd ipfixprobe
autoreconf -i
./configure --with-nemea
make
sudo make install
```

Note: because of backward compatibility, we install a symlink `flow_meter`
into $bindir, i.e., `/usr/bin/nemea/flow_meter` by default; it points to
`/usr/bin/ipfixprobe` (default path of installed ipfixprobe).

