/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief implementation of C++ unirec adapter
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "unirecAdapter.hpp"

#include <stdexcept>

namespace aggregator {

Unirec::Unirec()
{
	_inputTemplate = NULL;
	_outputTemplate = NULL;
}

Unirec::~Unirec()
{
	ur_free_template(_inputTemplate);
	ur_free_template(_outputTemplate);
}

void Unirec::ChangeTrapFormat()
{
	const char *spec = NULL;
	uint8_t dataFormat;
	if (trap_ctx_get_data_fmt(trap_get_global_ctx(), TRAPIFC_INPUT, 0, &dataFormat, &spec) != TRAP_E_OK) {
		throw std::runtime_error("Unirec::ChangeTrapFormat() has failed. Data format was not loaded.n");
	} 
	_inputTemplate = ur_define_fields_and_update_template(spec, _inputTemplate);
	if (_inputTemplate == NULL) {
		throw std::runtime_error("Unirec::ChangeTrapFormat() has failed. Template could not be edited.n");
	} else {
		if (_inputTemplate->direction == UR_TMPLT_DIRECTION_BI) {
			char* spec_cpy = ur_cpy_string(spec);
			if (spec_cpy == NULL) {
				throw std::runtime_error("Unirec::ChangeTrapFormat() has failed. Memory allocation problem.n");
			} else {
				trap_ctx_set_data_fmt(trap_get_global_ctx(), _inputTemplate->ifc_out, TRAP_FMT_UNIREC, spec_cpy);
			}
		} 
	}
}

std::tuple<const void*, uint16_t, int> Unirec::Receive()
{
	const void *receivedData;
	uint16_t dataSize = 0;

	int returnCode = trap_recv(0, &receivedData, &dataSize);
	return std::make_tuple(receivedData, dataSize, returnCode);
}

bool Unirec::IsEOFReceived(uint16_t dataSize) const noexcept
{
	return dataSize <= 1;
}

bool Unirec::IsUnirecFieldPresent(ur_field_id_t fieldId) const
{
	return ur_is_present(_inputTemplate, fieldId);
}

void Unirec::CreateOutputTemplate(const std::string& templateFields)
{
	_outputTemplate = ur_create_output_template(0, templateFields.c_str(), NULL);
	if (!_outputTemplate) {
       	throw std::runtime_error("Unirec::CreateOutputTemplate() has failed.");
	}
}

void Unirec::CreateInputTemplate(const std::string& templateFields)
{
	_inputTemplate = ur_create_input_template(0, templateFields.c_str(), NULL);
	if (!_inputTemplate) {
       	throw std::runtime_error("Unirec::CreateInputTemplate() has failed.");
	}
   }

void Unirec::Send(const void* dataToSend)
{
	trap_send(0, dataToSend, ur_rec_size(_outputTemplate, dataToSend));
}

ur_template_t* Unirec::GetInputTemplate() const noexcept
{
	return _inputTemplate;
}

ur_template_t* Unirec::GetOutputTemplate() const noexcept
{
	return _outputTemplate;
}

} // namespace aggregator
