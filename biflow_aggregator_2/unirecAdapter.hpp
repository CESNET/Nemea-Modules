/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief interface of C++ unirec adapter
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>
#include <tuple>

#include <unirec/unirec.h>

namespace aggregator {

/**
 * Unirec c++ adapter
 */
class Unirec {
public:

	Unirec();
	~Unirec();

	std::tuple<const void*, uint16_t, int> Receive();
	void Send(const void* dataToSend);

	bool IsEOFReceived(uint16_t dataSize) const noexcept;
	void ChangeTrapFormat();

	bool IsUnirecFieldPresent(ur_field_id_t fieldId) const;

	void CreateOutputTemplate(const std::string& templateFields);
	void CreateInputTemplate(const std::string& templateFields);

	ur_template_t* GetInputTemplate() const noexcept;
	ur_template_t* GetOutputTemplate() const noexcept;

private:
	ur_template_t *_inputTemplate;
	ur_template_t *_outputTemplate;
};

} // namespace aggregator
