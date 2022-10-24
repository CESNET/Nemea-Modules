/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Config parsing from command line args
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.hpp"

#include <iostream>
#include <stdexcept>

namespace aggregator {

Config::Config()
{
	SetDefaultValues();
}

void Config::Parse(int argc, char **argv)
{
	SetDefaultValues();

	const option *longOptions = GetLongOptions();
	const char *shortOptions = GetShortOptions();

	char c;
	while ((c = getopt_long(argc, argv, shortOptions, longOptions, nullptr)) != -1) {
		switch (c) {
		case 'c':
			_configParserSpecification = optarg;
			break;
		case 'h':
			_help = true;
			break;
		}
	}
	Validate();
}

void Config::SetDefaultValues()
{
	_configParserSpecification.clear();
	_help = false;
}

const option *Config::GetLongOptions()
{
	static struct option long_options[] = {
		{"config", required_argument, nullptr, 'c'},
		{"help", no_argument, nullptr, 'h'},
		{nullptr, 0, nullptr, 0}
	};
	return long_options;
}

const char *Config::GetShortOptions()
{
	return "c:h";
}

void Config::Validate()
{
	if (_help) {
		return;
	}
	if (_configParserSpecification.empty()) {
		throw std::invalid_argument("Missing config parser specification (-c)");
	}
}

const std::string& Config::GetConfigParserSpecification() const
{
	return _configParserSpecification;
}

bool Config::IsHelp() const
{
	return _help;
}

void Config::PrintUsage() const
{
	std::cerr << "Usage: ./ft-replay [options] -c <config parser specification>\n";
	std::cerr << "  --config, -c  ... The config parser specification\n";
	std::cerr << "  --help, -h    ... Show this help message\n";
}

} // namespace aggregator
