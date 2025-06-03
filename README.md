# Windows

Windows users must install npcap and get the sdk to put into the thirdparty folder and name it `npcap-sdk`.
https://npcap.com/#download

They should also install boost under the thirdparty folder and rename the root folder of the zip folder to `boost-sdk`
https://www.boost.org/releases/latest/

To make boost work with SSL capabilities, install `OpenSSL` too:
https://slproweb.com/products/Win32OpenSSL.html

# linux

`sudo apt install libpcap-dev`
and
`sudo apt install libboost-all-dev`
you might also have to do 
`sudo apt install libssl-dev`

# Linting
```find . \( -path './build' -o -path './thirdparty' \) -prune -o -name '*.cpp' -print0 | xargs -0 -I{} clang-tidy --warnings-as-errors='*' -p build {}```
add the fix flag if you want to apply automated fixes, don't do this unsupervised.
