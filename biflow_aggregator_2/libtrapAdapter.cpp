/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief C++ libtrap adapter implementation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libtrapAdapter.hpp"

#include <cstring>
#include <stdexcept>

namespace aggregator {

void TrapModuleInfo::SetIfcCount(size_t inputIfcCount, size_t outputIfcCount)
{
	_moduleInfo.num_ifc_in = inputIfcCount;
	_moduleInfo.num_ifc_out = outputIfcCount;
}

void TrapModuleInfo::SetModuleName(const std::string& moduleName)
{
	_moduleInfo.name  = strdup(moduleName.c_str());
}

void TrapModuleInfo::SetModuleDescription(const std::string& moduleDescription)
{
	free(_moduleInfo.description);
	_moduleInfo.description = strdup(moduleDescription.c_str());
}

trap_module_info_t* TrapModuleInfo::GetModuleInfo()
{
	return &_moduleInfo;
}

TrapModuleInfo::TrapModuleInfo()
{
	_moduleInfo.name = NULL;
	_moduleInfo.description = strdup("");
	_moduleInfo.num_ifc_in = 0;
	_moduleInfo.num_ifc_out = 0;
	_moduleInfo.params = NULL;
}

TrapModuleInfo::~TrapModuleInfo()
{
	free(_moduleInfo.name);
	free(_moduleInfo.description);
}


Libtrap::Libtrap(trap_module_info_t* trapModuleInfo)
	: _trapModuleInfo(trapModuleInfo)
{
} 

void Libtrap::Init(int& argc, char** argv)
{
	if (ParseCommandLine(argc, argv)) {
		return;
	}
	
	if (trap_init(_trapModuleInfo, _ifcSpec) != TRAP_E_OK) {
		throw std::runtime_error("Libtrap::Init() has failed. "
		"Error message: " + std::string(trap_last_error_msg));
	}
}

Libtrap::~Libtrap()
{
	trap_terminate();
	trap_free_ifc_spec(_ifcSpec);
	trap_finalize();
}

int Libtrap::ParseCommandLine(int& argc, char** argv)
{
	int ret = trap_parse_params(&argc, argv, &_ifcSpec);
	if (ret == TRAP_E_OK) {
		return 0;
	} else if (ret == TRAP_E_HELP) {
		trap_print_help(_trapModuleInfo);
		return 1;
	} else {
		throw std::runtime_error("Libtrap::ParseCommandLine() has failed. "
			"Problem in parsing of parameters for TRAP: " + std::string(trap_last_error_msg));
	}
}

} // namespace aggregator