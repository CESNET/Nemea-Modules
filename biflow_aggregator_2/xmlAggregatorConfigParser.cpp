/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief XML config file parser
 *
 * @copyright Copyright (c) 2022 CESNET
 */

#include "xmlAggregatorConfigParser.hpp"

#include <stdexcept>

namespace aggregator {

XmlAggConfigParser::XmlAggConfigParser(const std::string& configParserArguments)
{
	ParseUserArguments(configParserArguments);
	ValidateUserArguments();
	LoadFileAsXmlDocument();
}

void XmlAggConfigParser::ParseUserArguments(const std::string& userArguments)
{
	const std::string _configFileOption = "file";
	const std::string _configSectionOption = "section";

	auto keyValueMap = SplitUserArguments(userArguments);
	for (const auto& [key, value]: keyValueMap) {
		if (key == _configFileOption) {
			_configFilename = value;
		} else if (key == _configSectionOption) {
			_sectionAttributeValue = value;
		} else {
			throw std::runtime_error("XmlAggConfigParser::ParseUserArguments() has failed. "
				"Unknown argument: " + key + "=" + value);
		}
	}
}

void XmlAggConfigParser::ValidateUserArguments()
{
	if (_configFilename.empty()) {
		throw std::runtime_error("XmlAggConfigParser::ValidateUserArguments() has failed. "
			"Specification of 'file=filename' is missing.");
	}
	if (_sectionAttributeValue.empty()) {
		throw std::runtime_error("XmlAggConfigParser::ValidateUserArguments() has failed. "
			"Specification of 'section=name' is missing.");
	}
}

void XmlAggConfigParser::LoadFileAsXmlDocument()
{
	if (!_xmlDocument.load_file(_configFilename.c_str())) {
		throw std::runtime_error("XmlAggConfigParser::LoadFileAsXmlDocument() has failed. "
			"Unable to load XML file: " + _configFilename);
	}
}

void XmlAggConfigParser::Parse()
{
	xmlNode sectionNode = GetSectionNode();
	if (!sectionNode) {
		throw std::runtime_error(CreateMissingSectionErrorMessage());
	}
	ParseSectionNode(sectionNode);
}

XmlAggConfigParser::xmlNode XmlAggConfigParser::GetSectionNode() const
{
	return _xmlDocument.child(_rootNodeName.c_str()).find_child_by_attribute(
		_sectionNodeName.c_str(), _sectionAttributeName.c_str(), _sectionAttributeValue.c_str());
}

std::string XmlAggConfigParser::CreateMissingSectionErrorMessage() const
{
	return std::string("XmlAggConfigParser::Parse() has failed. "
		"XML node [" + _rootNodeName + "->" + _sectionNodeName + " "
		+ _sectionAttributeName + " = " + _sectionAttributeValue + "] not found.");
}

void XmlAggConfigParser::ParseSectionNode(xmlNode sectionNode)
{
	for (xmlNode fieldNode : sectionNode) {
		CheckNodeName(fieldNode, _fieldNodeName);
		ParseFieldNode(fieldNode);
	}
}

void XmlAggConfigParser::CheckNodeName(xmlNode node, const std::string& validName)
{
	if (validName.compare(node.name())) {
		throw std::runtime_error("XmlAggConfigParser::CheckNodeName() has failed. "
			"Invalid node name: " + std::string(node.name()));
	}
}

void XmlAggConfigParser::ParseFieldNode(xmlNode fieldNode)
{
	AggFieldConfig aggFieldConfig;
	for (xmlNode node : fieldNode) {
		ParseFieldOption(aggFieldConfig, node.name(), node.child_value());
	}
	AddAggFieldConfig(aggFieldConfig);
}

} // namespace aggregator
