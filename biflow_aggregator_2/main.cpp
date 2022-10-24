/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Bidirectional flow (bi-flow) aggregator 
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstdlib>
#include <memory>
#include <iostream>
#include <stdexcept>

#include "aggregatorConfigParser.hpp"
#include "aggregatorConfigParserFactory.hpp"

#include "config.hpp"
#include "libtrapAdapter.hpp"
#include "unirecAdapter.hpp"

#include "flowKeyUnirecDescription.hpp"

using namespace aggregator;

/**
 * @brief Build TrapModuleInfo class
 */
TrapModuleInfo BuildTrapModuleInfo()
{
	TrapModuleInfo trapModuleInfo;
	trapModuleInfo.SetModuleName("aggregator");
	trapModuleInfo.SetModuleDescription("TODO WiP");
	trapModuleInfo.SetIfcCount(1, 1);
	return trapModuleInfo;
}

int main(int argc, char** argv)
{
	Config config;
	TrapModuleInfo trapModuleInfo = BuildTrapModuleInfo();

	Libtrap libtrap(trapModuleInfo.GetModuleInfo());
	Unirec unirec;

	try {
		libtrap.Init(argc, argv);
		const char* requiredInputTemplate = "TIME_FIRST,TIME_LAST";
		unirec.CreateInputTemplate(requiredInputTemplate);
	} catch (const std::exception& ex) {
		std::cerr << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	try {
		config.Parse(argc, argv);
	} catch (const std::invalid_argument& ex) {
		std::cerr << ex.what() << std::endl;
		config.PrintUsage();
		return EXIT_FAILURE;
	}

	if (config.IsHelp()) {
		config.PrintUsage();
		return EXIT_SUCCESS;
	}

	std::unique_ptr<AggConfigParser> configParser;

	try {
		configParser = AggConfigParserFactory::instance().Create(
			config.GetConfigParserSpecification());
		configParser->Parse();
	} catch (const std::exception& ex) {
		std::cerr << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}