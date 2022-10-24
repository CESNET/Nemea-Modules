/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Config parser factory registrator
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "aggregatorConfigParserFactory.hpp"

#include <memory>
#include <stdexcept>
#include <string>

namespace aggregator {

/**
 * @brief Aggregator config parser registrator.
 *
 * @tparam T Type of class to register
 */
template <typename T>
struct AggConfigParserFactoryRegistrator {
	/**
	 * @brief Register aggregator config parser to the factory.
	 *
	 * @param fileFormat  Config file format name
	 */
	AggConfigParserFactoryRegistrator(const std::string& fileFormat)
	{
		bool inserted;
		inserted = AggConfigParserFactory::instance().RegisterParser(
			fileFormat,
			[](const std::string& configParserParams) -> std::unique_ptr<AggConfigParser> {
				return std::make_unique<T>(configParserParams);
			}
		);
		if (!inserted) {
			throw std::runtime_error(
				"Multiple registration of Config parser file format: " + fileFormat);
		}
	}
};

} // namespace aggregator
