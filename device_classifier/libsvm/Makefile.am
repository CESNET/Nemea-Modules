svmbindir=${bindir}/svm-tools
svmbin_PROGRAMS=svm-predict svm-train svm-scale
AM_LDFLAGS=-lm
SUBDIRS=data tools


EXTRA_DIST=svm.h
svm_predict_SOURCES=svm.cpp svm-predict.c

svm_train_SOURCES=svm-train.c svm.cpp
svm_scale_SOURCES=svm-scale.c

