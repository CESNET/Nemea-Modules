bin_PROGRAMS=svm-predict svm-train svm-scale
#lib_LTLIBRARIES=libsvm.la
AM_LDFLAGS=-lm

EXTRA_DIST=svm.h
#libsvm_la_SOURCES=svm.cpp svm.h
svm_predict_SOURCES=svm.cpp svm-predict.c

svm_train_SOURCES=svm-train.c svm.cpp
svm_scale_SOURCES=svm-scale.c

