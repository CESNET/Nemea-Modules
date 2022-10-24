/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief C++ libtrap adapter interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>

#include <libtrap/trap.h>

namespace aggregator {

/**
 * trap_module_info c++ adapter
 */
class TrapModuleInfo {
public:

	TrapModuleInfo();
	~TrapModuleInfo();

	/**
	 * @brief Set input and output interface count
	 */
	void SetIfcCount(size_t inputIfcCount, size_t outputIfcCount);
	/**
	 * @brief Set trap module name
	 */
	void SetModuleName(const std::string& moduleName);
	/**
	 * @brief Set trap module description
	 */
	void SetModuleDescription(const std::string& moduleDescription);
	/**
	 * @brief Get trap module info structure
	 */
	trap_module_info_t* GetModuleInfo();

private:
	trap_module_info_t _moduleInfo;
};

/**
 * Libtrap c++ adapter
 */
class Libtrap {
public:

	Libtrap(trap_module_info_t* trapModuleInfo);
	~Libtrap();

	/**
	 * @brief Initialize libtrap, load cmd line arguments
	 */
	void Init(int& argc, char** argv);

private:

	int ParseCommandLine(int& argc, char** argv);

	size_t _inputIfcCount;
	size_t _outputIfcCount;

	trap_ifc_spec_t _ifcSpec;
	trap_module_info_t* _trapModuleInfo;
};

} // namespace aggregator