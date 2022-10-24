/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief Flow key unirec description interface
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <unirec/unirec.h>

namespace aggregator {

class FlowKeyUnirecDescription {
public:
	using KeyPartsTemplate = std::vector<std::pair<ur_field_id_t, size_t>>;

	void AddKey(const std::string& fieldNameForward, const std::string& fieldNameReverse);

	const KeyPartsTemplate& GetKeyPartsTemplate(bool getReverseDirection) const;
	size_t GetKeyPartsTemplateSize() const noexcept;
	 
private:
	std::vector<std::pair<ur_field_id_t, size_t>> _keyPartsTemplateForward;
	std::vector<std::pair<ur_field_id_t, size_t>> _keyPartsTemplateReverse;
	
	size_t GetFieldSize(ur_field_id_t fieldId);
	bool IsFieldIdStringType(ur_field_id_t urFieldId) const noexcept;
	bool IsVariableLengthField(ur_field_id_t urFieldId) const noexcept;
	void AddKeyPartSize(size_t keyPartSize) noexcept;

	size_t _totalKeyPartsTemplateSize = 0;
};

} // namespace aggregator
