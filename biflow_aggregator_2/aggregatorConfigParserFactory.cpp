/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Config parser factory implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "aggregatorConfigParserFactory.hpp"

#include <stdexcept>

namespace aggregator {

std::unique_ptr<AggConfigParser>
AggConfigParserFactory::Create(const std::string& ConfigParserSpecification)
{
	auto [parserFileFormat, parserArguments] = SplitArguments(ConfigParserSpecification);

	auto it = _registeredFormats.find(parserFileFormat);
	if (it == _registeredFormats.end()) {
		throw std::runtime_error("Config parser file format: '" + parserFileFormat
			+ "' is not registered.");
	}

	return it->second(parserArguments);
}

std::pair<std::string, std::string>
AggConfigParserFactory::SplitArguments(const std::string& ConfigParserSpecification)
{
	std::size_t position = ConfigParserSpecification.find_first_of(":");
	if (position == std::string::npos) {
		throw std::runtime_error("Invalid format of Config Parser specification");
	}

	return std::make_pair(
		std::string(ConfigParserSpecification, 0, position),
		std::string(ConfigParserSpecification, position + 1));
}


bool AggConfigParserFactory::RegisterParser(
	const std::string& fileFormat,
	const AggConfigParserGenerator& funcCreate)
{
	return _registeredFormats.insert(std::make_pair(fileFormat, funcCreate)).second;
}

AggConfigParserFactory& AggConfigParserFactory::instance()
{
	static AggConfigParserFactory instance;
	return instance;
}

} // namespace aggregator
