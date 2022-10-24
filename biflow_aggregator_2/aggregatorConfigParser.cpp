/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Config parser implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "aggregatorConfigParser.hpp"

#include <algorithm>
#include <stdexcept>

namespace aggregator {

const std::vector<AggFieldConfig>& 
AggConfigParser::GetAggFieldsConfig() const
{
	return _aggFieldsConfig;
}

std::map<std::string, std::string>
AggConfigParser::SplitUserArguments(const std::string &configParserArguments)
{
	std::map<std::string, std::string> argMap;
	std::string argString = configParserArguments;
	size_t start = 0;
	size_t end = 0;

	auto noSpaceEnd = std::remove(argString.begin(), argString.end(), ' ');
	argString.erase(noSpaceEnd, argString.end());

	while (end != std::string::npos) {
		end = argString.find(',', start);
		std::string tmp = argString.substr(start, end - start);

		size_t mid = tmp.find('=');
		if (mid == std::string::npos || mid + 1 >= tmp.size() || tmp.substr(0, mid).size() == 0) {
			throw std::invalid_argument("AggConfigParser::SplitUserArguments() has failed");
		}

		auto ret = argMap.emplace(tmp.substr(0, mid), tmp.substr(mid + 1));
		if (!ret.second) {
			throw std::invalid_argument("AggConfigParser::SplitUserArguments() has failed");
		}
		start = end + 1;
	}

	return argMap;
}

void AggConfigParser::ParseFieldOption(
	AggFieldConfig& aggFieldConfig,
	const std::string& optionName,
	const std::string& optionValue)
{
	if (!optionName.compare(_fieldNameIdentifier)) {
		aggFieldConfig._fieldName = optionValue;
	} else if (!optionName.compare(_fieldNameReverseIdentifier)) {
		aggFieldConfig._fieldNameReverse = optionValue;
	} else if (!optionName.compare(_fieldTypeIdentifier)) {
		aggFieldConfig._fieldType = optionValue;
	} else {
		aggFieldConfig._optionalParameters.emplace(optionName, optionValue);
	}
}

void AggConfigParser::AddAggFieldConfig(const AggFieldConfig& aggFieldConfig)
{
	_aggFieldsConfig.emplace_back(aggFieldConfig);
}

} // namespace aggregator
