/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <libsolidity/interface/StorageLayout.h>

using namespace std;
using namespace dev;
using namespace dev::solidity;

Json::Value StorageLayout::generate(ContractDefinition const& _contractDef)
{
	solAssert(!m_contract, "");
	m_contract = &_contractDef;
	m_types.clear();

	auto typeType = dynamic_cast<TypeType const*>(_contractDef.type());
	solAssert(typeType, "");
	auto contractType = dynamic_cast<ContractType const*>(typeType->actualType());
	solAssert(contractType, "");

	Json::Value variables(Json::arrayValue);
	for (auto const& var: contractType->stateVariables())
		variables.append(generate(*get<0>(var), get<1>(var), get<2>(var)));

	Json::Value layout;
	layout["storage"] = move(variables);
	layout["types"] = move(m_types);
	return layout;
}

Json::Value StorageLayout::generate(VariableDeclaration const& _var, u256 const& _slot, unsigned _offset)
{
	Json::Value varEntry;
	TypePointer varType = _var.type();

	varEntry["label"] = _var.name();
	varEntry["ast_id"] = to_string(_var.id());
	varEntry["contract"] = m_contract->name();
	varEntry["slot"] = _slot.str();
	varEntry["offset"] = to_string(_offset);
	varEntry["type"] = varType->richIdentifier();

	generate(varType);

	return varEntry;
}

void StorageLayout::generate(TypePointer _type)
{
	if (m_types.isMember(_type->richIdentifier()))
		return;

	// Register it now to cut recursive visits.
	m_types[_type->richIdentifier()] = {};
	Json::Value& typeInfo = m_types[_type->richIdentifier()];
	typeInfo["label"] = _type->toString(true);
	typeInfo["numberOfSlots"] = _type->storageSize().str();
	typeInfo["numberOfBytes"] = to_string(_type->storageBytes());

	if (auto structType = dynamic_cast<StructType const*>(_type))
	{
		Json::Value members(Json::arrayValue);
		auto const& structDef = structType->structDefinition();
		for (auto const& member: structDef.members())
		{
			auto const& offsets = structType->storageOffsetsOfMember(member->name());
			members.append(generate(*member, offsets.first, offsets.second));
		}
		typeInfo["members"] = move(members);
		typeInfo["encoding"] = "inplace";
	}
	else if (auto mappingType = dynamic_cast<MappingType const*>(_type))
	{
		typeInfo["key"] = mappingType->keyType()->richIdentifier();
		typeInfo["value"] = mappingType->valueType()->richIdentifier();
		generate(mappingType->keyType());
		generate(mappingType->valueType());
		typeInfo["encoding"] = "mapping";
	}
	else if (auto arrayType = dynamic_cast<ArrayType const*>(_type))
	{
		typeInfo["base"] = arrayType->baseType()->richIdentifier();
		generate(arrayType->baseType());
		typeInfo["encoding"] = arrayType->isDynamicallySized() ? "dynamic_array" : "inplace";
	}
	else
	{
		solAssert(_type->isValueType(), "");
		typeInfo["encoding"] = "inplace";
	}

	solAssert(typeInfo.isMember("encoding"), "");
}
