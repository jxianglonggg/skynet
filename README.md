Skynet is a lightweight online game framework which can be used in many other fields.

## Build

For Linux, install autoconf first for jemalloc:

```
git clone https://github.com/cloudwu/skynet.git
cd skynet
make 'PLATFORM'  # PLATFORM can be linux, macosx, freebsd linux_nojemalloc now
```

## About Lua version

Skynet now uses a modified version of lua 5.4.2 ( https://github.com/ejoy/lua/tree/skynet54 ) for multiple lua states.

Official Lua versions can also be used as long as the Makefile is edited.

## How To Use

* Read Wiki for documents https://github.com/cloudwu/skynet/wiki
* The FAQ in wiki https://github.com/cloudwu/skynet/wiki/FAQ
