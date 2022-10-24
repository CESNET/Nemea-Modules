/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Flow key unirec description interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdexcept>

#include "flowKeyUnirecDescription.hpp"

namespace aggregator {
	
void FlowKeyUnirecDescription::AddKey(
	const std::string& fieldNameForward, 
	const std::string& fieldNameReverse)
{
	ur_field_id_t fieldIdForward = ur_get_id_by_name(fieldNameForward.c_str());
	ur_field_id_t fieldIdReverse = ur_get_id_by_name(fieldNameReverse.c_str());

	size_t fieldSizeForward = GetFieldSize(fieldIdForward);
	size_t fieldSizeReverse = GetFieldSize(fieldIdReverse);

	if (fieldSizeForward != fieldSizeReverse) {
		throw std::runtime_error("AddKey() has failed. "
			"Forward and reverse unirec field size is not equal.");
	}

	AddKeyPartSize(fieldSizeForward);
	_keyPartsTemplateForward.emplace_back(fieldIdForward, fieldSizeForward);
	_keyPartsTemplateReverse.emplace_back(fieldIdReverse, fieldSizeReverse);
}

size_t FlowKeyUnirecDescription::GetFieldSize(ur_field_id_t fieldId)
{
	if (IsFieldIdStringType(fieldId)) {
		return sizeof(uint32_t);
	} else if (IsVariableLengthField(fieldId)) {
		throw std::runtime_error("GetFieldSize() has failed. "
			"Non string variable-lenght key size is not allowed.");
	} else {
		return ur_get_size(fieldId);
	}
}

const FlowKeyUnirecDescription::KeyPartsTemplate& 
FlowKeyUnirecDescription::GetKeyPartsTemplate(bool getReverseDirection = false) const
{
	if (getReverseDirection) {
		return _keyPartsTemplateReverse;	
	} else {
		return _keyPartsTemplateForward;
	}
}

size_t FlowKeyUnirecDescription::GetKeyPartsTemplateSize() const noexcept
{
	return _totalKeyPartsTemplateSize;
}

void FlowKeyUnirecDescription::AddKeyPartSize(size_t keyPartSize) noexcept
{
	_totalKeyPartsTemplateSize += keyPartSize;
}

bool FlowKeyUnirecDescription::IsFieldIdStringType(ur_field_id_t urFieldId) const noexcept
{
	return ur_get_type(urFieldId) == UR_TYPE_STRING;
}

bool FlowKeyUnirecDescription::IsVariableLengthField(ur_field_id_t urFieldId) const noexcept
{
	return ur_get_size(urFieldId) < 0;
}

} // namespace aggregator
