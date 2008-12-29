#!/bin/bash
find -name '*.c' -o -name '*.cpp' -o -name '*.h' > cscope.files
cscope -bkq -i cscope.files
#ctags -R
