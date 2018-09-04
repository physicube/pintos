pintos project for POSTECH OS Class

Pre-install
* modify `$pintos_path` in `/src/utils/pintos` and `/src/utils/Pintos.pm` to path of your pintos folder.

* modify `pintos_path` in `/src/utils/pintos-gdb` to path of your pintos folder as well.

* add `$INSTALLATION_PATH/pintos/src/utils` to your path (recommend to edit bashrc)

Installation
```
cd $INSTALLATION_PATH/pintos/src/utils
make 
cd ../threads
make
```

How to Test
```
make check
or
pintos -q run <test_name>
```

By Physicube
