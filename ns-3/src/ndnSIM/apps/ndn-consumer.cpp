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

#include "ndn-consumer.hpp"
#include "ns3/boolean.h"
#include "ns3/callback.h"
#include "ns3/double.h"
#include "ns3/integer.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"

#include "utils/ndn-ns3-packet-tag.hpp"
#include "utils/ndn-rtt-mean-deviation.hpp"

#include <ndn-cxx/lp/tags.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/ref.hpp>

#include "/home/couto/Desktop/ndnSIM/ns-3/src/ndnSIM/examples/httplib.h" // Include the cpp-httplib header
#include </home/couto/Desktop/ndnSIM/ns-3/src/ndnSIM/examples/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <openssl/evp.h> // For hashing using EVP
#include <openssl/sha.h> // Requires OpenSSL for SHA-256 hashing
#include <stdexcept>

NS_LOG_COMPONENT_DEFINE("ndn.Consumer");

// Open the log file in append mode
std::ofstream logFile("log.txt", std::ios::app);

// Custom logging function
void
logToTxt(const std::string& message)
{
  logFile << message << std::endl; // Write the message to the log file
}

namespace ns3 {
namespace ndn {
std::string
nameDecode(const std::string& input)
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
std::string
sha256(const std::string& str)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, str.c_str(), str.size());
  SHA256_Final(hash, &sha256);

  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  }

  return ss.str();
}

class MerkleTree {
private:
  std::vector<std::string> leaves;
  size_t num_levels;

  std::string
  computeParentHash(const std::string& left_child, const std::string& right_child)
  {
    std::string combined = left_child + right_child;
    return sha256(combined);
  }

  std::vector<std::string>
  computeNextLevel(const std::vector<std::string>& level)
  {
    std::vector<std::string> next_level;
    for (size_t i = 0; i < level.size(); i += 2) {
      std::string left_child = level[i];
      std::string right_child = (i + 1 < level.size()) ? level[i + 1] : level[i];
      std::string parent = computeParentHash(left_child, right_child);
      next_level.push_back(parent);
    }
    return next_level;
  }

public:
  MerkleTree()
    : num_levels(0)
  {
  }

  void
  add(const std::string& data)
  {
    std::string leaf = sha256(data);
    leaves.push_back(leaf);
  }

  std::string
  root()
  {
    if (leaves.empty()) {
      return "";
    }
    if (leaves.size() == 1) {
      return leaves[0];
    }

    std::vector<std::string> tree = leaves;
    num_levels = 0; // Reset the number of levels
    while (tree.size() > 1) {
      tree = computeNextLevel(tree);
      num_levels++;
    }
    return tree[0];
  }

  // Getter method to access the num_levels property
  size_t
  getNumLevels() const
  {
    return num_levels;
  }

  // Function to calculate the SHA-256 hash of a given string
  std::string
  sha256(const std::string& input)
  {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);

    char hex[2 * SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
      sprintf(hex + 2 * i, "%02x", hash[i]);

    return std::string(hex);
  }
};

// Define a map to store Merkle trees for each m_receivedGeralName
std::map<std::string, MerkleTree> merkleTrees;

std::string
calculateChunkHash(const std::string& filePath)
{
  std::ifstream file(filePath, std::ios::binary);
  if (!file) {

    throw std::runtime_error("Error opening chunk file for reading1.");
  }

  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string chunkContent = buffer.str();

  return chunkContent; // Simply return the content of the chunk
}

NS_OBJECT_ENSURE_REGISTERED(Consumer);

TypeId
Consumer::GetTypeId(void)
{
  static TypeId tid =
    TypeId("ns3::ndn::Consumer")
      .SetGroupName("Ndn")
      .SetParent<App>()
      .AddAttribute("StartSeq", "Initial sequence number", IntegerValue(0),
                    MakeIntegerAccessor(&Consumer::m_seq), MakeIntegerChecker<int32_t>())

      .AddAttribute("Prefix", "Name of the Interest", StringValue("/"),
                    MakeNameAccessor(&Consumer::m_interestName), MakeNameChecker())
      .AddAttribute("LifeTime", "LifeTime for interest packet", StringValue("120s"),
                    MakeTimeAccessor(&Consumer::m_interestLifeTime), MakeTimeChecker())

      .AddAttribute("RetxTimer",
                    "Timeout defining how frequent retransmission timeouts should be checked",
                    StringValue("99999999999999ms"),
                    MakeTimeAccessor(&Consumer::GetRetxTimer, &Consumer::SetRetxTimer),
                    MakeTimeChecker())
      .AddAttribute("ConsumerId", "Consumer ID", StringValue(""),
                    MakeStringAccessor(&Consumer::m_consumerId), MakeStringChecker())
      .AddAttribute("FileName", "Name of the file to request", StringValue(""),
                    MakeStringAccessor(&Consumer::m_fileName), MakeStringChecker())
      .AddAttribute("ChunkNumber", "Number of the chunk to request", IntegerValue(0),
                    MakeIntegerAccessor(&Consumer::m_chunkNumber), MakeIntegerChecker<int32_t>())
      .AddTraceSource("LastRetransmittedInterestDataDelay",
                      "Delay between last retransmitted Interest and received Data",
                      MakeTraceSourceAccessor(&Consumer::m_lastRetransmittedInterestDataDelay),
                      "ns3::ndn::Consumer::LastRetransmittedInterestDataDelayCallback")

      .AddTraceSource("FirstInterestDataDelay",
                      "Delay between first transmitted Interest and received Data",
                      MakeTraceSourceAccessor(&Consumer::m_firstInterestDataDelay),
                      "ns3::ndn::Consumer::FirstInterestDataDelayCallback");

  return tid;
}

Consumer::Consumer()
  : m_rand(CreateObject<UniformRandomVariable>())
  , m_seq(0)
  , m_seqMax(0) // don't request anything
{
  NS_LOG_FUNCTION_NOARGS();

  m_rtt = CreateObject<RttMeanDeviation>();
}
std::string
Consumer::handle_save_manifest(const std::string& filename, const std::string& buffer)
{
  if (filename.empty() || buffer.empty()) {
    return "{'error': 'Filename or buffer is missing'}";
  }

  try {
    std::filesystem::path output_dir = std::filesystem::current_path() / "manifests";
    std::filesystem::path file_path = output_dir / ("manifest_" + filename);

    // print file_path
    // std::cout << "File Path: " << file_path << std::endl;

    std::ofstream file(file_path, std::ios::binary);
    if (file.is_open()) {
      file.write(buffer.c_str(), buffer.size());
      file.close();

      // print manifest
      std::cout << "Manifest: " << buffer << std::endl;

      std::cout << "Tamanho em bytes Manifest: " << buffer.size() << std::endl;
      logToTxt("MANIFEST BYTES: " + std::to_string(buffer.size()) + "\n");

      return "{'message': 'Manifest file saved successfully'}";
    }
    else {
      throw std::runtime_error("Failed to open file for writing.");
    }
  }
  catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
    return "{'error': 'Failed to save manifest file'}";
  }
}
std::string
url_encode(const std::string& value)
{
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (char c : value) {
    // Encode special characters
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    }
    else {
      escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
    }
  }

  return escaped.str();
}

std::string
Consumer::handle_manifest_request()
{
  auto start_time = std::chrono::high_resolution_clock::now();
  if (m_fileName.empty()) {
    return "{'error': 'Filename parameter is missing'}";
  }

  // print file
  std::cout << "File: " << m_fileName << std::endl;

  try {
    // Create the URL for the GET request
    std::string url = "http://localhost:5000/api/manifest?file=" + url_encode(m_fileName);

    // Create an httplib client and send the GET request
    httplib::Client cli("localhost", 5000);
    auto res = cli.Get(url.c_str());

    if (res && res->status == 200) {
      // Retrieve the buffer from the response content
      std::string buffer = res->body;

      // Call a function to handle saving the manifest
      handle_save_manifest(m_fileName, buffer);

      auto end_time = std::chrono::high_resolution_clock::now();

      // Calcule a duração (tempo decorrido)
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

      // Exiba o tempo decorrido em milissegundos
      std::cout << "Processing Time:(get manif) " << duration.count() << " milissegundos"
                << std::endl;

      logToTxt("GET MANIFEST time: " + std::to_string(duration.count()) + "\n");

      return buffer;
    }
    else {
      throw std::runtime_error("Error: " + std::to_string(res ? res->status : -1));
    }
  }
  catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
    return "{'error': 'Failed to retrieve manifest'}";
  }
}

void
Consumer::searchData()
{
  const std::string url = "http://localhost:8080/execute";

  // Get the search filter from the user
  std::cout << "Filter Data in the Blockchain: ";
  std::string search = m_fileName;
  auto start_time = std::chrono::high_resolution_clock::now();
  std::cout << "The search name is: " << search << std::endl;

  // Prepare the request text
  std::string text = "cityinfo showdata " + search;

  std::size_t tamanho_em_bytes = text.size();

  std::cout << "A mensagem para a BC tem: " << tamanho_em_bytes << " bytes." << std::endl;

  logToTxt("Msg to BC bytes: " + std::to_string(tamanho_em_bytes) + "\n");

  try {
    // Prepare the request body
    std::string jsonBody = "{\"text\":\"" + text + "\"}";

    // Create an httplib client and send the POST request
    httplib::Client cli("localhost", 8080);

    auto res = cli.Post(url.c_str(), jsonBody, "application/json");

    if (res && res->status == 200) {
      std::cout << "Response: " << res->body << std::endl;
    }
    else {
      std::cerr << "HTTP request failed with code: " << (res ? res->status : -1) << std::endl;
    }
  }
  catch (const std::exception& error) {
    std::cerr << "Error: " << error.what() << std::endl;
  }
  auto end_time = std::chrono::high_resolution_clock::now();

  // Calcule a duração (tempo decorrido)
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

  // Exiba o tempo decorrido em milissegundos
  std::cout << "Processing Time:(Search BC) " << duration.count() << " milissegundos" << std::endl;
  logToTxt("SEARCH BC time: " + std::to_string(duration.count()) + "\n");
}
void
Consumer::PrintReceivedFileContent()
{
  // print consumer number
  // std::cout << "Consumer number is " << m_fileName << '\n';
  // Check if we have received any content
  if (m_receivedFileContent.empty()) {
    NS_LOG_ERROR("Received empty content.");
    return;
  }

  // m_receivedFileContent name
  // std::cout << "Received content name: " << m_receivedFileName << std::endl;

  // Define a filename to save the received content
  std::string m_receivedFileNamePath = std::filesystem::current_path().string()
                                       + std::filesystem::path::preferred_separator + "downloads"
                                       + m_receivedFileName; // You can use any filename you prefer
  std::string m_receivedGeralNamePath = std::filesystem::current_path().string()
                                        + std::filesystem::path::preferred_separator + "downloads"
                                        + std::filesystem::path::preferred_separator
                                        + m_fileName; // You can use any filename you prefer
  // Open a local file for writing the received content
  std::ofstream outputFile(m_receivedFileNamePath, std::ios::binary);
  if (!outputFile) {
    NS_LOG_ERROR("Failed to open file for writing: " << m_receivedFileNamePath);
    return;
  }

  // Write the received content to the local file
  outputFile.write(reinterpret_cast<const char*>(m_receivedFileContent.data()),
                   m_receivedFileContent.size());
  outputFile.close();

  receivedChunks++;

  auto start_time = std::chrono::high_resolution_clock::now();

  // Calculate Merkle tree root while downloading chunks
  MerkleTree merkle_tree;

  // Retrieve the manifest file
  std::string manifest_name = "manifest_" + m_fileName;
  std::string manifest_path = std::filesystem::current_path().string()
                              + std::filesystem::path::preferred_separator + "manifests"
                              + std::filesystem::path::preferred_separator + manifest_name;

  std::ifstream manifest_file(manifest_path);
  if (!manifest_file) {
    throw std::runtime_error("Error opening manifest file for reading.");
  }

  nlohmann::json manifest_data;
  manifest_file >> manifest_data;

  std::string merkle_tree_rootManifest = manifest_data["merkle_tree"].get<std::string>();
  int merkle_tree_number_of_chunks = manifest_data["numero_de_chunks"].get<int>();

  // isto agora tem que se mudar
  int chunk_number = m_receivedNumberOfChunk;

  std::string chunk_hash =
    calculateChunkHash(m_receivedFileNamePath); // Use the MerkleTree class to calculate the hash

  chunk_hash = sha256(chunk_hash);

  std::string chunk_hash_manif =
    manifest_data["chunks_hashs"]["chunk_" + std::to_string(chunk_number - 1)].get<std::string>();

  // print chunk_hash
  // std::cout << "Chunk hash is " << chunk_hash << '\n';
  // print chunk_hash_manif
  // std::cout << "Chunk hash from manifest is " << chunk_hash_manif << '\n';
  if (chunk_hash == chunk_hash_manif) {
    std::cout << "Hash matches. The chunk " << chunk_number << " is unaltered." << std::endl;

    // guardar chunk_hashs[chunk_number] = chunk_hash
    chunk_hashs[chunk_number] = chunk_hash;
    chunk_names[chunk_number] = m_receivedFileName;

  }
  else {
    std::cout << "Hash doesn't match. The chunk " << chunk_number
              << " has been modified or corrupted." << std::endl;
  }

  // Store or update the Merkle tree for the specific m_receivedGeralName
  merkleTrees[m_fileName] = merkle_tree;

  if (merkle_tree_number_of_chunks == receivedChunks || retrans == true) {

    // verify if all chunks were received chunk_hashs.size() == merkle_tree_number_of_chunks
    if (chunk_hashs.size() != merkle_tree_number_of_chunks) {
      std::cout << "Not all chunks were received" << std::endl;
      // check which chunk was not recevied can be in the middle
      for (int i = 1; i <= m_chunkNumber; i++) {
        if (chunk_hashs.count(i) > 0) {
        }
        else {
          std::cout << "Chunk " << i << " was not received" << std::endl;
          misschunks = true;
          retrans = true;
          size_t dotPos = m_fileName.rfind('.');
          std::string extension = (dotPos != std::string::npos) ? m_fileName.substr(dotPos) : "";
          std::string filenameWithoutExtension = m_fileName;

          // Remove the extension from the filename
          if (!extension.empty()) {
            filenameWithoutExtension = m_fileName.substr(0, m_fileName.size() - extension.size());
          }
          missChunk = filenameWithoutExtension + "#" + std::to_string(i) + extension;
          std::cout << "Miss chunk is " << missChunk << std::endl;
          nRetrans++;
          if (nRetrans == 6) {
            std::cout << "Retransmissions Limit Exceed!" << std::endl;
            return;
          }
          ScheduleNextPacket();
          return;
        }
      }
    }

    // Retrieve the corresponding Merkle tree for this m_receivedGeralName
    MerkleTree& currentMerkleTree = merkleTrees[m_fileName];

    for (int i = 0; i < merkle_tree_number_of_chunks; i++) {
      currentMerkleTree.add(chunk_hashs[i + 1]);
    }
    // Now you can call the root() function on the instance of MerkleTree
    std::string merkle_tree_rootTree = currentMerkleTree.root();

    // Compare the Merkle tree root with the one from the manifest

    // std::cout << merkle_tree_rootTree << std::endl;
    // std::cout << merkle_tree_rootManifest << std::endl;
    if (merkle_tree_rootTree == merkle_tree_rootManifest) {
      std::cout << "Merkle tree validation successful. The chunks are unaltered." << std::endl;
      // std::cout << "Merkle Tree with " << currentMerkleTree.getNumLevels() << " levels" <<
      // std::endl;
    }
    else {
      std::cout << "Merkle tree validation failed. The chunks have been modified or corrupted."
                << std::endl;
    }

    auto end_time = std::chrono::high_resolution_clock::now();

    // Calcule a duração (tempo decorrido)
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Exiba o tempo decorrido em milissegundos
    std::cout << "Processing Time:(SECURITY) " << duration.count() << " milissegundos" << std::endl;
    logToTxt("Security Time: " + std::to_string(duration.count()) + "\n");

    // ------------------------------ CRIAR FILE com os chunks------------------------------
    // Create the output file by concatenating the downloaded chunks
    std::ofstream output_file(m_receivedGeralNamePath, std::ios::binary);

    if (!output_file) {
      throw std::runtime_error("Error opening output file for writing.");
    }
    for (int i = 1; i <= m_chunkNumber; i++) {

      std::string chunk_path = std::filesystem::current_path().string()
                               + std::filesystem::path::preferred_separator + "downloads"
                               + chunk_names[i];

      std::ifstream chunk_file(chunk_path, std::ios::binary);

      if (!chunk_file) {
        // print chunk_path
        std::cout << "Chunk path is " << chunk_path << '\n';
        throw std::runtime_error("Error opening chunk file for reading2.");
      }

      output_file << chunk_file.rdbuf();

      // std::remove(chunk_path.c_str());
    }
    std::cout << "\nFile \"" << m_fileName << "\" created successfully\n" << std::endl;

    auto end_timeGLOBAL = std::chrono::high_resolution_clock::now();

    // Calcule a duração (tempo decorrido)
    auto durationGLOBAL =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_timeGLOBAL - start_timeGLOBAL);

    // Exiba o tempo decorrido em milissegundos
    std::cout << "Processing Time:(end2end Consumer) " << durationGLOBAL.count() << " milissegundos"
              << std::endl;
    logToTxt("consumer end2end time: " + std::to_string(durationGLOBAL.count()) + "\n");
    logToTxt(
      "--------------------------------------------------------------------------------------\n");
    finish = true;
  }
}

void
Consumer::SetRetxTimer(Time retxTimer)
{
  m_retxTimer = retxTimer;
  if (m_retxEvent.IsRunning()) {
    // m_retxEvent.Cancel (); // cancel any scheduled cleanup events
    Simulator::Remove(m_retxEvent); // slower, but better for memory
  }

  // schedule even with new timeout
  m_retxEvent = Simulator::Schedule(m_retxTimer, &Consumer::CheckRetxTimeout, this);
}

Time
Consumer::GetRetxTimer() const
{
  return m_retxTimer;
}

void
Consumer::CheckRetxTimeout()
{
  Time now = Simulator::Now();

  Time rto = m_rtt->RetransmitTimeout();
  // NS_LOG_DEBUG ("Current RTO: " << rto.ToDouble (Time::S) << "s");

  while (!m_seqTimeouts.empty()) {
    SeqTimeoutsContainer::index<i_timestamp>::type::iterator entry =
      m_seqTimeouts.get<i_timestamp>().begin();
    if (entry->time + rto <= now) // timeout expired?
    {
      uint32_t seqNo = entry->seq;
      m_seqTimeouts.get<i_timestamp>().erase(entry);
      OnTimeout(seqNo);
    }
    else
      break; // nothing else to do. All later packets need not be retransmitted
  }

  m_retxEvent = Simulator::Schedule(m_retxTimer, &Consumer::CheckRetxTimeout, this);
}

// Application Methods
void
Consumer::StartApplication() // Called at time specified by Start
{
  NS_LOG_FUNCTION_NOARGS();

  // do base stuff
  App::StartApplication();

  // initiliaze a global timer to check processing time
  start_timeGLOBAL = std::chrono::high_resolution_clock::now();

  searchData();

  handle_manifest_request();

  ScheduleNextPacket();
}

void
Consumer::StopApplication() // Called at time specified by Stop
{
  NS_LOG_FUNCTION_NOARGS();

  logFile.close();

  // cancel periodic packet generation
  Simulator::Cancel(m_sendEvent);

  // cleanup base stuff
  App::StopApplication();
}

void
Consumer::SendPacket()
{
  if (!m_active || finish) // Check the flag before sending
    return;

  NS_LOG_FUNCTION_NOARGS();

  // atenção a isto
  if (misschunks) {

    uint32_t seq = std::numeric_limits<uint32_t>::max(); // invalid

    while (m_retxSeqs.size()) {
      seq = *m_retxSeqs.begin();
      m_retxSeqs.erase(m_retxSeqs.begin());
      break;
    }

    if (seq == std::numeric_limits<uint32_t>::max()) {
      if (m_seqMax != std::numeric_limits<uint32_t>::max()) {
        if (m_seq >= m_seqMax) {
          return; // we are totally done
        }
      }

      seq = m_seq++;
    }

    shared_ptr<Name> nameWithSequence;  // Declare outside the if-else blocks

    filename_and_id = m_fileName+"/"+m_consumerId  ;

    if (retrans == false) {
        nameWithSequence = make_shared<Name>(filename_and_id);  
    }
    else {
        nameWithSequence = make_shared<Name>(missChunk);
    }

    // print nameWithSequence
    std::cout << "Name with sequence is " << nameWithSequence->toUri() << '\n';
    //nameWithSequence->appendSequenceNumber(seq);

    shared_ptr<Interest> interest = make_shared<Interest>();
    //interest->setNonce(m_rand->GetValue(0, std::numeric_limits<uint32_t>::max()));
    interest->setName(*nameWithSequence);
    interest->setCanBePrefix(true);
    interest->setNumberChunks(m_chunkNumber);
    if(retrans == false)
    {
      interest->setPush(true); // I am a pull based consumer
    }
    else{
      interest->setPush(false);
    }
    time::milliseconds interestLifeTime(9999999999999999);
    interest->setInterestLifetime(interestLifeTime);

    WillSendOutInterest(seq);
    m_transmittedInterests(interest, this, m_face);
    m_appLink->onReceiveInterest(*interest);

    misschunks = false;
  }
}

///////////////////////////////////////////////////
//          Process incoming packets             //
///////////////////////////////////////////////////

void
Consumer::OnData(shared_ptr<const Data> data)
{
  if (!m_active )//|| finish) // Check the flag before sending
    return;

  App::OnData(data); // Tracing inside

  bool alreadyExists = false;

  NS_LOG_FUNCTION(this << data);

  // Retrieve the content from the Data packet
  const ::ndn::Block& contentBlock = data->getContent();
  const uint8_t* contentPtr = contentBlock.value();
  size_t contentSize = contentBlock.value_size();

  // Extract and store the real file name from the Data packet's Name
  const Name& dataName = data->getName();

  std::string result = "";

  std::string dataNameStr = nameDecode(dataName.toUri()); // Decode the URI
  //print datanamestr
  std::cout << "Data name is " << dataNameStr << '\n';
  size_t pos = dataNameStr.rfind('/');                    // Find the last '/' from the end
  if (pos != std::string::npos) {
    result = dataNameStr.substr(pos + 1); // Extract the substring after the last '/'
    std::cout << "Result: " << result << std::endl;
  }
  else {
    std::cout << "No '/' found in the string." << std::endl;
  }

  dataNameStr = result;

  if (dataName.size() > 0) {
    size_t hashPos = dataNameStr.find("#");
    if (hashPos != std::string::npos) {
      // This is a chunk; handle it (e.g., store or process the chunk).
      // You can use dataNameStr to identify the chunk number.

      // Find the position of the first non-digit character after the '#'
      size_t endPos = dataNameStr.find_first_not_of("0123456789", hashPos + 1);

      // Extract the chunk number as a substring
      std::string chunkNumberStr = dataNameStr.substr(hashPos + 1, endPos - (hashPos + 1));

      int chunkNumber = std::stoi(chunkNumberStr);
      m_receivedNumberOfChunk = chunkNumber;

      // For example, you can store the chunk in a vector:
      // m_receivedFileContent.insert(m_receivedFileContent.end(), contentPtr, contentPtr +
      // contentSize);
      m_receivedFileContent.assign(contentPtr, contentPtr + contentSize);

      // Process the chunk further if needed.
      NS_LOG_INFO("Received chunk " << chunkNumber);
    }
    m_receivedFileName = "/" + dataNameStr; // nameDecode(dataName.getPrefix().toUri()); // Assuming
                                            // the real file name is the last component of the Name
  }
  else {
    m_receivedFileName =
      "unknown_file"; // Set a default name if the Name doesn't contain a valid file name component.
  }
  
  // Print or process the received content as needed
  PrintReceivedFileContent();

  if (actualChunk > m_chunkNumber) {

    // This could be a problem......
    uint32_t seq = data->getName().at(-2).toSequenceNumber();
    NS_LOG_INFO("< DATA for " << seq);

    int hopCount = 0;
    auto hopCountTag = data->getTag<lp::HopCountTag>();
    if (hopCountTag != nullptr) { // e.g., packet came from local node's cache
      hopCount = *hopCountTag;
    }
    NS_LOG_DEBUG("Hop count: " << hopCount);

    SeqTimeoutsContainer::iterator entry = m_seqLastDelay.find(seq);
    if (entry != m_seqLastDelay.end()) {
      m_lastRetransmittedInterestDataDelay(this, seq, Simulator::Now() - entry->time, hopCount);
    }

    entry = m_seqFullDelay.find(seq);
    if (entry != m_seqFullDelay.end()) {
      m_firstInterestDataDelay(this, seq, Simulator::Now() - entry->time, m_seqRetxCounts[seq],
                               hopCount);
    }

    m_seqRetxCounts.erase(seq);
    m_seqFullDelay.erase(seq);
    m_seqLastDelay.erase(seq);

    m_seqTimeouts.erase(seq);
    m_retxSeqs.erase(seq);

    m_rtt->AckSeq(SequenceNumber32(seq));
  }
  else {
    actualChunk++;
  }
}

void
Consumer::OnNack(shared_ptr<const lp::Nack> nack)
{
  /// tracing inside
  App::OnNack(nack);

  NS_LOG_INFO("NACK received for: " << nack->getInterest().getName()
                                    << ", reason: " << nack->getReason());
}

void
Consumer::OnTimeout(uint32_t sequenceNumber)
{
  NS_LOG_FUNCTION(sequenceNumber);
  // std::cout << Simulator::Now () << ", TO: " << sequenceNumber << ", current RTO: " <<
  // m_rtt->RetransmitTimeout ().ToDouble (Time::S) << "s\n";

  m_rtt->IncreaseMultiplier(); // Double the next RTO
  m_rtt->SentSeq(SequenceNumber32(sequenceNumber),
                 1); // make sure to disable RTT calculation for this sample
  m_retxSeqs.insert(sequenceNumber);
  //  ScheduleNextPacket();
}

void
Consumer::WillSendOutInterest(uint32_t sequenceNumber)
{
  NS_LOG_DEBUG("Trying to add " << sequenceNumber << " with " << Simulator::Now() << ". already "
                                << m_seqTimeouts.size() << " items");

  m_seqTimeouts.insert(SeqTimeout(sequenceNumber, Simulator::Now()));
  m_seqFullDelay.insert(SeqTimeout(sequenceNumber, Simulator::Now()));

  m_seqLastDelay.erase(sequenceNumber);
  m_seqLastDelay.insert(SeqTimeout(sequenceNumber, Simulator::Now()));

  m_seqRetxCounts[sequenceNumber]++;

  m_rtt->SentSeq(SequenceNumber32(sequenceNumber), 1);
}

} // namespace ndn
} // namespace ns3
