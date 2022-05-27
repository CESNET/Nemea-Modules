#!/bin/bash

cd ./detector/src
python3 setup.py build_ext --inplace
cd ./pyds
python3 setup.py build_ext --inplace
