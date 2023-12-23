/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2011-2015  Regents of the University of California.
 *
 * This file is part of ndnSIM. See AUTHORS for complete list of ndnSIM authors and
 * contributors.
 *
 * ndnSIM is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndnSIM is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndnSIM, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include "ndn-producer.hpp"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"

#include "helper/ndn-fib-helper.hpp"
#include "model/ndn-l3-protocol.hpp"

#include <memory>

#include </home/couto/Desktop/ndnSIM/ns-3/src/ndnSIM/examples/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream> // For error handling

NS_LOG_COMPONENT_DEFINE("ndn.Producer");

namespace ns3 {
namespace ndn {

std::string
urlDecode(const std::string& input)
{
  std::string decoded;
  for (size_t i = 0; i < input.size(); ++i) {
    if (input[i] == '%' && i + 2 < input.size()) {
      int hex1 = input[i + 1];
      int hex2 = input[i + 2];
      if (isxdigit(hex1) && isxdigit(hex2)) {
        char decodedChar = static_cast<char>((hex1 % 32 + 9) % 25 * 16 + (hex2 % 32 + 9) % 25);
        decoded += decodedChar;
        i += 2;
      }
      else {
        // Invalid URL encoding, keep '%' as is
        decoded += input[i];
      }
    }
    else {
      decoded += input[i];
    }
  }
  return decoded;
}

NS_OBJECT_ENSURE_REGISTERED(Producer);

TypeId
Producer::GetTypeId(void)
{
  static TypeId tid =
    TypeId("ns3::ndn::Producer")
      .SetGroupName("Ndn")
      .SetParent<App>()
      .AddConstructor<Producer>()
      .AddAttribute("Prefix", "Prefix, for which producer has the data", StringValue("/"),
                    MakeNameAccessor(&Producer::m_prefix), MakeNameChecker())
      .AddAttribute("ChunkNumber", "Number of chunks to produce (0 - unlimited)", UintegerValue(0),
                    MakeUintegerAccessor(&Producer::m_chunkNumber), MakeUintegerChecker<uint32_t>())
      .AddAttribute(
        "Postfix",
        "Postfix that is added to the output data (e.g., for adding producer-uniqueness)",
        StringValue("/"), MakeNameAccessor(&Producer::m_postfix), MakeNameChecker())
      .AddAttribute("PayloadSize", "Virtual payload size for Content packets", UintegerValue(1024),
                    MakeUintegerAccessor(&Producer::m_virtualPayloadSize),
                    MakeUintegerChecker<uint32_t>())
      .AddAttribute("Freshness", "Freshness of data packets, if 0, then unlimited freshness",
                    TimeValue(Seconds(0)), MakeTimeAccessor(&Producer::m_freshness),
                    MakeTimeChecker())
      .AddAttribute(
        "Signature",
        "Fake signature, 0 valid signature (default), other values application-specific",
        UintegerValue(0), MakeUintegerAccessor(&Producer::m_signature),
        MakeUintegerChecker<uint32_t>())
      .AddAttribute("KeyLocator",
                    "Name to be used for key locator.  If root, then key locator is not used",
                    NameValue(), MakeNameAccessor(&Producer::m_keyLocator), MakeNameChecker());
  return tid;
}

Producer::Producer()
{
  NS_LOG_FUNCTION_NOARGS();
}

// inherited from Application base class.
void
Producer::StartApplication()
{

  // print producer started
  std::cout << "Producer started" << std::endl;
  NS_LOG_FUNCTION_NOARGS();
  App::StartApplication();

  std::string prefix = m_prefix.toUri();
  FibHelper::AddRoute(GetNode(), prefix, m_face, 0);

  // for (int i = 1; i <= m_chunkNumber; i++) {
  //   size_t dotPos = m_prefix.toUri().rfind('.');

  //   std::string extension = (dotPos != std::string::npos) ? m_prefix.toUri().substr(dotPos) : "";

  //   std::string m_prefixWithoutExtension = m_prefix.toUri();
  //   // Remove the extension from the m_prefix
  //   if (!extension.empty()) {
  //     m_prefixWithoutExtension = m_prefix.toUri().substr(0, dotPos);
  //   }
  //   std::string prefix = m_prefixWithoutExtension + "#" + std::to_string(i) + extension;
  //   //std::string prefix = m_prefix.toUri();
  //   //print prefix
  //   std::cout << "Prefix: " << prefix << std::endl;
  //   FibHelper::AddRoute(GetNode(), prefix, m_face, 0);
  // }
}

void
Producer::StopApplication()
{
  NS_LOG_FUNCTION_NOARGS();

  App::StopApplication();
}

void
Producer::OnInterest(shared_ptr<const Interest> interest)
{
  App::OnInterest(interest); // tracing inside

  std::cout << "OnInterest" << std::endl;

  NS_LOG_FUNCTION(this << interest);

  Name dataName(interest->getName());
  //print dataNAme
  std::cout << "DataName: " << dataName << std::endl;
  std::string dataNameDecoded = urlDecode(dataName.getPrefix(1).toUri());

  //print getPrefix2
  std::cout << "DataName.getPrefix(2): " << dataName.getPrefix(2) << std::endl;

  std::string result = dataNameDecoded.substr(1);

  std::string manifest_name = "manifest_" + result;
  std::string manifest_path = std::filesystem::current_path().string()
                              + std::filesystem::path::preferred_separator + "manifests"
                              + std::filesystem::path::preferred_separator + manifest_name;

  // print manifest_path
  std::cout << "Manifest path: " << manifest_path << std::endl;

  std::ifstream manifest_file(manifest_path);
  if (!manifest_file) {
    throw std::runtime_error("Error opening manifest file for reading.");
  }

  nlohmann::json manifest_data;
  manifest_file >> manifest_data;

  int numberOfChunks = manifest_data["numero_de_chunks"].get<int>();

  if (!m_active)
    return;

  if (interest->isPush() == false && true == false) {

    dataName.append(dataNameDecoded);

    dataNameDecoded = urlDecode(dataNameDecoded);

    auto data = make_shared<Data>();
    data->setName(dataName);
    data->setPush(true);
    data->setFreshnessPeriod(::ndn::time::milliseconds(m_freshness.GetMilliSeconds()));
    data->setIsLast(true);

    // data->setContent(make_shared< ::ndn::Buffer>(m_virtualPayloadSize));

    std::filesystem::path cwd = std::filesystem::current_path() / "producer_files";

    // Define the full path to the file.
    std::string filePath = cwd.string() + dataNameDecoded;

    // Read the content of the file and set it as the Data packet's content.
    std::ifstream inputFile(filePath, std::ios::binary); // Open the file in binary mode.
    if (inputFile) {

      // print filepath

      std::cout << "Filepath: " << filePath << std::endl;
      // Determine the file's size.
      inputFile.seekg(0, std::ios::end);
      size_t fileSize = inputFile.tellg();
      inputFile.seekg(0, std::ios::beg);

      // Create a buffer to hold the file's content.
      ::ndn::Buffer contentBuffer(fileSize);

      // Read the file into the buffer.
      inputFile.read(reinterpret_cast<char*>(contentBuffer.data()), fileSize);

      // Set the buffer as the Data packet's content.
      data->setContent(contentBuffer);

      // Close the file.
      inputFile.close();
    }
    else {
      // Handle the case where the file couldn't be opened.
      NS_LOG_ERROR("Failed to open file");
      // Optionally, you can set an error response in the Data packet.
      // data->setNackReason(::ndn::lp::NackReason::NETWORK_ERROR);
    }

    SignatureInfo signatureInfo(static_cast<::ndn::tlv::SignatureTypeValue>(255));

    if (m_keyLocator.size() > 0) {
      signatureInfo.setKeyLocator(m_keyLocator);
    }

    data->setSignatureInfo(signatureInfo);

    ::ndn::EncodingEstimator estimator;
    ::ndn::EncodingBuffer encoder(estimator.appendVarNumber(m_signature), 0);
    encoder.appendVarNumber(m_signature);
    data->setSignatureValue(encoder.getBuffer());

    //NS_LOG_INFO("node(" << GetNode()->GetId() << ") responding with Data: " << data->getName());

    // to create real wire encoding
    data->wireEncode();

    m_transmittedDatas(data, this, m_face);
    m_appLink->onReceiveData(*data);
  }
  //before  chunksNumbersMap[urlDecode(dataName.getPrefix(2).toUri())] = 1; check if it as already a value assigned

  //chunksNumbersMap[urlDecode(dataName.getPrefix(2).toUri())] = 1;

      // Check if the key exists
    auto it = chunksNumbersMap.find(urlDecode(dataName.getPrefix(2).toUri()));

    if (it != chunksNumbersMap.end()) {
        // Key already exists, you can handle it accordingly
        std::cout << "Key " << urlDecode(dataName.getPrefix(2).toUri()) << " already exists with value " << it->second << std::endl;
    } else {
        // Key doesn't exist, assign a new value
        chunksNumbersMap[urlDecode(dataName.getPrefix(2).toUri())] = 1;
        std::cout << "Key " << urlDecode(dataName.getPrefix(2).toUri()) << " assigned with value 1" << std::endl;
    }

  if (chunksNumbersMap[urlDecode(dataName.getPrefix(2).toUri())] <= numberOfChunks) {

    size_t dotPos = dataNameDecoded.rfind('.');
    std::string extension = (dotPos != std::string::npos) ? dataNameDecoded.substr(dotPos) : "";
    std::string filenameWithoutExtension = dataNameDecoded;

    // Remove the extension from the filename
    if (!extension.empty()) {
      filenameWithoutExtension =
        dataNameDecoded.substr(0, dataNameDecoded.size() - extension.size());
    }
    std::string chunkName = filenameWithoutExtension + "#"
                            + std::to_string(chunksNumbersMap[urlDecode(dataName.getPrefix(2).toUri())]) + extension;

    dataName = dataName.getPrefix(2);

    //prin dataName.getPrefix

    dataName.append(chunkName);

    // print chunkName
    std::cout << "ChunkName: " << chunkName << std::endl;

    chunkName = urlDecode(chunkName);

    shared_ptr<Name> dataaaa = make_shared<Name>(dataName);

    auto data = make_shared<Data>();
    data->setName(*dataaaa);
    data->setPush(true);
    data->setFreshnessPeriod(::ndn::time::milliseconds(m_freshness.GetMilliSeconds()));
    //if (chunksNumbersMap[urlDecode(dataName.getPrefix(2).toUri())] == numberOfChunks) {
    //  data->setIsLast(true);
    //}

    // data->setContent(make_shared< ::ndn::Buffer>(m_virtualPayloadSize));

    std::filesystem::path cwd = std::filesystem::current_path() / "producer_files";

    // Define the full path to the file.
    std::string filePath = cwd.string() + chunkName;

    // Read the content of the file and set it as the Data packet's content.
    std::ifstream inputFile(filePath, std::ios::binary); // Open the file in binary mode.
    if (inputFile) {
      // Determine the file's size.
      inputFile.seekg(0, std::ios::end);
      size_t fileSize = inputFile.tellg();
      inputFile.seekg(0, std::ios::beg);

      // Create a buffer to hold the file's content.
      ::ndn::Buffer contentBuffer(fileSize);

      // Read the file into the buffer.
      inputFile.read(reinterpret_cast<char*>(contentBuffer.data()), fileSize);

      // Set the buffer as the Data packet's content.
      data->setContent(contentBuffer);

      // Close the file.
      inputFile.close();
    }
    else {
      // Handle the case where the file couldn't be opened.
      NS_LOG_ERROR("Failed to open file");
      // Optionally, you can set an error response in the Data packet.
      // data->setNackReason(::ndn::lp::NackReason::NETWORK_ERROR);
    }

    SignatureInfo signatureInfo(static_cast<::ndn::tlv::SignatureTypeValue>(255));

    if (m_keyLocator.size() > 0) {
      signatureInfo.setKeyLocator(m_keyLocator);
    }

    data->setSignatureInfo(signatureInfo);

    ::ndn::EncodingEstimator estimator;
    ::ndn::EncodingBuffer encoder(estimator.appendVarNumber(m_signature), 0);
    encoder.appendVarNumber(m_signature);
    data->setSignatureValue(encoder.getBuffer());

    NS_LOG_INFO("node(" << GetNode()->GetId() << ") responding with Data: " << data->getName());

    // to create real wire encoding
    data->wireEncode();

    m_transmittedDatas(data, this, m_face);
    m_appLink->onReceiveData(*data);
    chunksNumbersMap[urlDecode(dataName.getPrefix(2).toUri())]++;
    Simulator::Schedule(Seconds(1.0 / 1000.0), &Producer::OnInterest, this, interest); 
  }
  
}


} // namespace ndn
} // namespace ns3
