/**
 * @file
 * @author Pavel Siska <siska@cesnet.cz>
 * @brief XML config file parser
 *
 * @copyright Copyright (c) 2022 CESNET
 */

#pragma once

#include "aggregatorConfigParser.hpp"
#include "aggregatorConfigParserFactoryRegistrator.hpp"

#include <string>

#include <pugixml.hpp>

namespace aggregator {

/**
 * @brief Parse aggregator config file in XML format
 * 
 */
class XmlAggConfigParser : public AggConfigParser {
public:
	/**
	 * @brief Parse config parser arguments and load config file
	 * 
	 * @param configParserArguments config parser arguments
	 */
	XmlAggConfigParser(const std::string& configParserArguments);

	/**
	 * @brief Parse config file
	 * 
	 */
	void Parse() override;

private:
	using xmlNode = pugi::xml_node;

	void ParseUserArguments(const std::string& userArguments);
	void ValidateUserArguments();

	void LoadFileAsXmlDocument();

	xmlNode GetSectionNode() const;
	void ParseSectionNode(xmlNode sectionNode);
	void CheckNodeName(xmlNode node, const std::string& validName);
	void ParseFieldNode(xmlNode fieldNode);

	std::string CreateMissingSectionErrorMessage() const;

	const std::string _rootNodeName = "aggregator";
	const std::string _sectionNodeName = "section";
	const std::string _sectionAttributeName = "name";
	const std::string _fieldNodeName = "field";

	std::string _sectionAttributeValue;
	std::string _configFilename;
	pugi::xml_document _xmlDocument;
};

AggConfigParserFactoryRegistrator<XmlAggConfigParser> _xmlConfigParserExtension("xml");

} // namespace aggregator