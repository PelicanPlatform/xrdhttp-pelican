
An XrdHttp plugin for the Pelican Platform
==========================================

This repository contains a small plugin for the [XrdHttp](https://xrootd.github.io/) server
which implements specific behaviors needed by the [Pelican platform](https://pelicanplatform.org/).

To build:

```
mkdir build
cd build
cmake ..
make
```

To use the plugin, add the following line to your XRootD configuration:

```
http.exthandler xrdpelican libXrdHttpPelican.so
```
