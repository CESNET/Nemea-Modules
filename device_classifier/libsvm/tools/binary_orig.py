#!/usr/bin/env python

import sys, os.path
from sys import argv
from os import system, remove
from string import *
from subr import *
import grid

global train, test, pass_through_options
global labels, features, test_labels

svmtrain_exe = '../svm-train'
svmpredict_exe = '../svm-predict'

# process command line options, set global parameters
def process_options(argv = sys.argv):
	global train, test, pass_through_options

	if len(argv) < 3:
		print "Usage: %s [parameters for svm-train] training_file testing_file" % argv[0]
		sys.exit(1)

	train = argv[-2]
	test = argv[-1]

	assert os.path.exists(train), "training_file not found."
	assert os.path.exists(test), "testing_file not found."

	pass_through_options = join(argv[1:len(argv)-2], " ")

def read_problem(file):
	assert os.path.exists(file), "%s not found." % (file)

	_labels = []
	_features = []

	in_file = open(file, "r")
	for line in in_file:
		spline = split(line)
		if spline[0].find(':') == -1:
			_labels.append(split(spline[0], ','))
			_features.append(join(spline[1:]))
		else:
			_labels.append([])
			_features.append(join(spline))
	in_file.close()

	return (_labels, _features)

def count_labels(labels):
	_labels = []

	for i in range(len(labels)):
		for lab in labels[i]:
			if (lab not in _labels):
				_labels.append(lab)

	return _labels

# Give me a label
def build_problem(lab):
	# build binary classification problem for label lab
	problem = open("tmp_binary", "w")

	for t in range(len(labels)):
		if lab in labels[t]:
			problem.write("+1 %s\n" % features[t])
		else:
			problem.write("-1 %s\n" % features[t])

	problem.close()

def train_problem(lab):
	global pass_through_options
	print "Training problem for label %s..." % lab

	rate, param = grid.find_parameters("tmp_binary", "")

	pass_through_options = "-c %f -g %f" % (param['c'], param['g'])
	print pass_through_options
	cmd = "%s %s %s %s" % (svmtrain_exe, pass_through_options, "tmp_binary", "models/tmp_model_%s" % lab)
	os.system(cmd)

def test_problem(lab):
	print "Testing problem for label %s..." % lab

	cmd = "%s %s %s %s" % (svmpredict_exe, "tmp_test", "models/tmp_model_%s" % lab, "tmp_output")
	os.system(cmd)

def build_test(testset):
	global test_labels

	(test_labels, x) = read_problem(testset)
	out_test = open("tmp_test", "w")
	for i in range(len(test_labels)):
		out_test.write("+1 %s\n" % x[i])
	out_test.close()

def get_output(lab):
	index = []

	output = open("tmp_output", "r");

	t = 0
	for line in output:
		if split(line, '\n')[0] == "1":
			index.append(t)
		t = t + 1

	output.close()

	return index

def main():
	global train, test
	global labels, features, test_labels

	process_options()

	# read problem and get all labels
	(labels, features) = read_problem(train)
	all_labels = count_labels(labels)

	print "Labels:", len(all_labels)

	build_test(test)

	predict = []
	for i in range(len(test_labels)):
		predict.append([])

	for i in range(len(all_labels)):
		# train binary problem for the label all_labels[i]
		lab = all_labels[i] 

		build_problem(lab)
		train_problem(lab)
		test_problem(lab)
		index = get_output(lab)
		for idx in index:
			predict[idx].append("%s" % lab)

	out_predict = open("tmp_predict", "w")
	for i in range(len(predict)):
		out_predict.write("%s\n" % join(predict[i], ","))
	out_predict.close()



	result = measure(test_labels, predict, all_labels)
	
	print "Exact match ratio: %s" % result[0]
	print "Microaverage F-measure: %s" % result[1]
	print "Macroaverage F-measure: %s" % result[2]

	sys.stdout.flush()

main()
