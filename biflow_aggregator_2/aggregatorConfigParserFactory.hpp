/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Config parser factory interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "aggregatorConfigParser.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>

namespace aggregator {

/**
 * @brief Pointer to function which generate new Config parser instance
 */
using AggConfigParserGenerator = std::unique_ptr<AggConfigParser> (*)(const std::string&);

/**
 * @brief Config parser factory pattern.
 *
 */
class AggConfigParserFactory {
public:
	/**
	 * @brief Get factory instance - Singleton pattern
	 *
	 * @return AggConfigParserFactory&  Reference to the factory singleton
	 */
	static AggConfigParserFactory& instance();

	/**
	 * @brief Create new config parser
	 *
	 * @p ConfigParserSpecification format:
	 * "fileFormmat;firstParam=value,otherParam=value"
	 *
	 * fileFormmat = Registered file format name
	 *
	 * @param ConfigParserSpecification configuration string
	 * @return Config parser context.
	 */
	std::unique_ptr<AggConfigParser> Create(const std::string& ConfigParserSpecification);

	/**
	 * @brief Register parser file format
	 *
	 * @param fileFormat Unique file format
	 * @param funcCreate Config parser instance generator
	 * @return true - if successfully registered, false otherwise
	 */
	bool RegisterParser(const std::string& fileFormat, const AggConfigParserGenerator& funcCreate);

private:
	std::pair<std::string, std::string> SplitArguments(const std::string& ConfigParserSpecification);
	std::map<const std::string, AggConfigParserGenerator> _registeredFormats;
};

} // namespace aggregator
