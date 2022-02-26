#!/bin/bash

afl-fuzz -m none -i ./corpus -o ./output -s 123 -x ./dict/xml.dict -D -M master -- ./libxml/bin/xmllint --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@
