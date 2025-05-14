# Windows

Windows users must install npcap and get the sdk to put into the thirdparty folder and name it `npcap-sdk`.

https://npcap.com/#download

# linux

`apt install libpcap-dev`

# Linting
```find . \( -path './build' -o -path './thirdparty' \) -prune -o -name '*.cpp' -print0 | xargs -0 -I{} clang-tidy --warnings-as-errors='*' -p build {}```

