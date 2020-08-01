# tdmux

# About

tdmux is a tcp layer demultiplexer. It allows you to access mutiple tcp services through a single port. It currently supports HTTP, HTTPS, SSH protocols.

# Build

```
git clone https://github.com/Ahiknsr/tdmux
cd tdmux
mkdir -p _build && cd _build
cmake ../src 
make
./server
```

# Credits
* https://docs.libuv.org/en/v1.x/
* https://tls.ulfheim.net/
* https://gist.github.com/darrenjs/4645f115d10aa4b5cebf57483ec82eca
* https://www.openssl.org/docs/manmaster/man7/
