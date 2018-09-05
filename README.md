# pintos project for POSTECH OS Class

## VM environment
```
gcc version : 7.3.0
qemu version : 2.11.1(Debian 1:2.11+dfsg-1ubuntu7.4)
```

## Pre-install
* modify `$pintos_path` in `/src/utils/pintos` and `/src/utils/Pintos.pm` to path of your pintos folder.

* modify `pintos_path` in `/src/utils/pintos-gdb` to path of your pintos folder as well.

* add `$INSTALLATION_PATH/pintos/src/utils` to your path (recommend to edit bashrc)

#### Don't commit pintos, pintos-gdb, Pintos.pm!!!

## Installation
```
cd $INSTALLATION_PATH/pintos/src/utils
make 
cd ../threads
make
```

## How to Test
```
make check
or
pintos -q run <test_name>
```

#### By Physicube
