/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Config parsing from command line args
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <cstdint>
#include <string>

#include <getopt.h>

namespace aggregator {

/**
 * @brief Command line arguments parser.
 *
 * Parse and validate user-specified command line arguments.
 */
class Config {
public:
	/**
	 * @brief Construct a Config object with the default values.
	 *
	 */
	Config();

	/**
	 * @brief Parse command line arguments.
	 * @param[in] argc Number of arguments
	 * @param[in] argv Array of arguments
	 *
	 * @throws std::invalid_argument  When invalid command line arguments are provided
	 */
	void Parse(int argc, char **argv);

	/** @brief Get Config Parser specification. */
	const std::string& GetConfigParserSpecification() const;
	/** @brief Whether help should be printer */
	bool IsHelp() const;
	/** @brief Print the usage message */
	void PrintUsage() const;

private:
	void SetDefaultValues();
	void Validate();

	const option *GetLongOptions();
	const char *GetShortOptions();

	std::string _configParserSpecification;

	bool _help;
};

} // namespace aggregator
