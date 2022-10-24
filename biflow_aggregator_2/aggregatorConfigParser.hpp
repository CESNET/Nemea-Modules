/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Config parser interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>
#include <vector>
#include <map>

namespace aggregator {

struct AggFieldConfig {
	std::string _fieldName;
	std::string _fieldNameReverse;
	std::string _fieldType;
	std::map<std::string, std::string> _optionalParameters;
};

class AggConfigParser {
public:
	/**
	 * @brief Parse config file
	 *
	 */
	virtual void Parse() = 0;

	const std::vector<AggFieldConfig>& GetAggFieldsConfig() const;

protected:
	std::map<std::string, std::string> SplitUserArguments(const std::string& configParserArguments);

	void ParseFieldOption(AggFieldConfig& aggFieldConfig, const std::string& optionName,
		const std::string& optionValue);
	void AddAggFieldConfig(const AggFieldConfig& aggFieldConfig);

	const std::string _fieldNameIdentifier = "name";
	const std::string _fieldNameReverseIdentifier = "reverse_name";
	const std::string _fieldTypeIdentifier = "type";

private:

	std::vector<AggFieldConfig> _aggFieldsConfig;
};

} // namespace aggregator