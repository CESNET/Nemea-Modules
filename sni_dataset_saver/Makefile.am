bin_PROGRAMS=sni_dataset_saver
sni_dataset_saver_SOURCES=main.cpp fields.c fields.h sampler.cpp sampler.h sni.cpp sni.h rapidcsv.h \
                          json.hpp htrie_map.h htrie_hash.h array-hash/array_set.h \
                          array-hash/array_map.h array-hash/array_hash.h array-hash/array_growth_policy.h
sni_dataset_saver_LDADD=-lunirec -ltrap
sni_dataset_saver_CXXFLAGS=-pthread -g -Wall -Wextra
include ../aminclude.am
