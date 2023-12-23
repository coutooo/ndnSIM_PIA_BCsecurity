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

// ndn-grid.cpp

#include "ns3/core-module.h"
#include "ns3/ndnSIM-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/point-to-point-module.h"

#include "httplib.h" // Include the cpp-httplib header
#include </home/couto/Desktop/ndnSIM/ns-3/src/ndnSIM/examples/json.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h> // For hashing using EVP
#include <openssl/sha.h> // Requires OpenSSL for SHA-256 hashing
#include <stdexcept>

namespace ns3 {

/**
 * This scenario simulates a grid topology (using PointToPointGrid module)
 *
 * (consumer) --------------- ( ) ----- (consumer2 )
 *     |                       |             |
 *    ( ) ------------------- ( ) --------- ( )
 *     |                       |             |
 *    (consumers[9] ) ------ (producer) -- (producer)
 *
 * All links are 1Mbps with propagation 10ms delay.
 *
 * FIB is populated using NdnGlobalRoutingHelper.
 *
 * Consumer requests data from producer with frequency 1 interests per second
 * (interests contain constantly increasing sequence number).
 *
 * For every received interest, producer replies with a data packet, containing
 * 1024 bytes of virtual payload.
 *
 * To run scenario and see what is happening, use the following command:
 *
 *     NS_LOG=ndn.Consumer:ndn.Producer ./waf --run=ndn-grid
 */

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

// Function to URL-encode a string
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

void
searchData()
{
  const std::string url = "http://localhost:8080/execute";

  // Get the search filter from the user
  std::cout << "Filter Data in the Blockchain: ";
  std::string search;
  std::cin >> search;
  auto start_time = std::chrono::high_resolution_clock::now();
  std::cout << "The search name is: " << search << std::endl;

  // Prepare the request text
  std::string text = "cityinfo showdata " + search;

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
}
std::string
handle_save_manifest(const std::string& filename, const std::string& buffer)
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
handle_manifest_request(const std::string& file)
{
  auto start_time = std::chrono::high_resolution_clock::now();
  if (file.empty()) {
    return "{'error': 'Filename parameter is missing'}";
  }

  // print file
  std::cout << "File: " << file << std::endl;

  try {
    // Create the URL for the GET request
    std::string url = "http://localhost:5000/api/manifest?file=" + url_encode(file);

    // Create an httplib client and send the GET request
    httplib::Client cli("localhost", 5000);
    auto res = cli.Get(url.c_str());

    if (res && res->status == 200) {
      // Retrieve the buffer from the response content
      std::string buffer = res->body;

      // Call a function to handle saving the manifest
      handle_save_manifest(file, buffer);

      auto end_time = std::chrono::high_resolution_clock::now();

      // Calcule a duração (tempo decorrido)
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

      // Exiba o tempo decorrido em milissegundos
      std::cout << "Processing Time:(get manif) " << duration.count() << " milissegundos"
                << std::endl;

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

int
main(int argc, char* argv[])
{
  // Setting default parameters for PointToPoint links and channels
  Config::SetDefault("ns3::PointToPointNetDevice::DataRate", StringValue("1Gbps"));
  Config::SetDefault("ns3::PointToPointChannel::Delay", StringValue("10ms"));
  Config::SetDefault("ns3::DropTailQueue<Packet>::MaxSize", StringValue("999999p"));

  // Read optional command-line parameters (e.g., enable visualizer with ./waf --run=<> --visualize
  CommandLine cmd;
  cmd.Parse(argc, argv);

  AnnotatedTopologyReader topologyReader("", 1);

  topologyReader.SetFileName("src/ndnSIM/examples/topologies/topo-20nodes.txt");

  topologyReader.Read();

  // Install NDN stack on all nodes
  ndn::StackHelper ndnHelper;
  ndnHelper.SetDefaultRoutes(true);
  ndnHelper.InstallAll();

  // Set BestRoute strategy
  ndn::StrategyChoiceHelper::InstallAll("/", "/localhost/nfd/strategy/best-route");

  // Installing global routing interface on all nodes
  ndn::GlobalRoutingHelper ndnGlobalRoutingHelper;
  ndnGlobalRoutingHelper.InstallAll();

  // Getting containers for the consumer/producer
  // Ptr<Node> producer = grid.GetNode(2, 2);
  // Ptr<Node> consumer = grid.GetNode(0, 0);

  // Getting containers for the 2 consumer/producer
  // Ptr<Node> producer = grid.GetNode(1, 2);
  // Ptr<Node> consumer2 = grid.GetNode(2, 0);

  // Ptr<Node> consumers[9] = grid.GetNode(0, 2);

  // Getting containers for the consumer/producer
  Ptr<Node> consumers[11] = {Names::Find<Node>("Node9"),  Names::Find<Node>("Node10"),
                             Names::Find<Node>("Node11"), Names::Find<Node>("Node12"),
                             Names::Find<Node>("Node13"), Names::Find<Node>("Node14"),
                             Names::Find<Node>("Node15"), Names::Find<Node>("Node16"),
                             Names::Find<Node>("Node17"), Names::Find<Node>("Node18"),
                             Names::Find<Node>("Node19")};

  Ptr<Node> producer = Names::Find<Node>("Node0");

  // --------------------------Regist producer in the blockchain -----------------------------
  const std::string url = "http://localhost:8080/execute";
  const std::string text = "sawtooth keygen forum";

  try {
    // Prepare the request body in JSON format
    std::string jsonBody = "{\"text\":\"" + text + "\"}";

    // Create an httplib client and send the POST request
    httplib::Client cli("localhost", 8080);
    auto res = cli.Post(url.c_str(), jsonBody, "application/json");

    if (res && res->status == 200) {
      std::string content_type = res->get_header_value("Content-Type");
      std::string data;

      if (content_type.find("application/json") != std::string::npos) {
        // JSON response
        data = res->body;
      }
      else {
        // Handle non-JSON response here
        data = "{'message': '" + res->body + "'}";
      }

      std::cout << data << std::endl;
      std::cout << "Producer Registered..." << std::endl;
    }
    else {
      std::cerr << "HTTP request failed with code: " << (res ? res->status : -1) << std::endl;
      std::cout << "Probably the producer is already registered..." << std::endl;
    }
  }
  catch (const std::exception& error) {
    std::cerr << "Error: " << error.what() << std::endl;
  }

  // Input to continue the script
  std::cout << "Waiting for the producer upload...(PRESS ENTER)" << std::endl;
  // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

  // --------------------------------------------------------------------------------------

  while (true) {
    std::cout << "1. Search in Blockchain" << std::endl;
    std::cout << "2. Get Manifest" << std::endl;
    std::cout << "3. Download Chunks" << std::endl;
    std::cout << "0. Exit" << std::endl;

    std::string choice;
    std::cout << "Enter your choice (1-3): ";
    // std::cin >> choice;
    choice = "3";

    auto start_time = std::chrono::high_resolution_clock::now();

    if (choice == "1") {
      searchData();
    }
    else if (choice == "2") {
      std::string file;
      std::cout << "Enter the filename: ";
      std::cin >> file;
      handle_manifest_request(file);
    }
    else if (choice == "3") {
      std::string filename, filename2, filename3;
      int start_chunk, start_chunk2, start_chunk3, end_chunk, end_chunk2, end_chunk3;
      int nConsumers;

      std::cout << "Number of Consumers (1-3): ";
      // std::cin >> nConsumers;
      nConsumers = 3;
      std::cout << "Filename Consumer 1: ";
      // std::cin >> filename;
      filename = "512KB_file";
      std::cout << "Start Chunk Consumer 1: ";
      // std::cin >> start_chunk;
      start_chunk = 1;
      std::cout << "End Chunk Consumer1: ";
      // std::cin >> end_chunk;
      end_chunk = 512;

      if (nConsumers == 2) {
        std::cout << "Filename Consumer 2: ";
        std::cin >> filename2;
        std::cout << "Start Chunk Consumer 2: ";
        std::cin >> start_chunk2;
        std::cout << "End Chunk Consumer 2: ";
        std::cin >> end_chunk2;

        start_time = std::chrono::high_resolution_clock::now();

        // Extract the file extension
        size_t dotPos = filename.rfind('.');
        size_t dotPos2 = filename2.rfind('.');

        std::string extension = (dotPos != std::string::npos) ? filename.substr(dotPos) : "";
        std::string extension2 = (dotPos2 != std::string::npos) ? filename2.substr(dotPos2) : "";

        std::string filenameWithoutExtension = filename;
        std::string filenameWithoutExtension2 = filename2;

        // Remove the extension from the filename
        if (!extension.empty()) {
          filenameWithoutExtension = filename.substr(0, dotPos);
        }

        if (!extension2.empty()) {
          filenameWithoutExtension2 = filename2.substr(0, dotPos2);
        }
        // std::cout << "Chunk Name: " << prefix << std::endl;

        ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
        consumerHelper.SetPrefix(filename);
        consumerHelper.SetAttribute("FileName", StringValue(filename));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[7]);

        ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.SetAttribute("Freshness", TimeValue(Seconds(0)));
        for (int i = start_chunk; i <= end_chunk; i++) {
          std::string prefix = "/" + filenameWithoutExtension + "#" + std::to_string(i) + extension;
          ndnGlobalRoutingHelper.AddOrigins(prefix, producer);
        }
        producerHelper.Install(producer);

        // ndn::GlobalRoutingHelper::CalculateRoutes();

        // ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
        consumerHelper.SetPrefix(filename2);
        consumerHelper.SetAttribute("FileName", StringValue(filename2));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk2));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[12]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename2);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk2));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.SetAttribute("Freshness", TimeValue(Seconds(0)));
        for (int i = start_chunk2; i <= end_chunk2; i++) {
          std::string prefix2 =
            "/" + filenameWithoutExtension2 + "#" + std::to_string(i) + extension2;
          ndnGlobalRoutingHelper.AddOrigins(prefix2, producer);
        }
        producerHelper.Install(producer);

        ndn::GlobalRoutingHelper::CalculateRoutes();

        Simulator::Stop(Seconds(5.0));

        Simulator::Run();
      }
      else if (nConsumers == 3) {
        std::cout << "Filename Consumer 2: ";
        // std::cin >> filename2;
        filename2 = "512KB_file";
        std::cout << "Start Chunk Consumer 2: ";
        // std::cin >> start_chunk2;
        start_chunk2 = 1;
        std::cout << "End Chunk Consumer 2: ";
        // std::cin >> end_chunk2;
        end_chunk2 = 512;

        std::cout << "Filename Consumer 3: ";
        // std::cin >> filename3;
        filename3 = "512KB_file";
        std::cout << "Start Chunk Consumer 3: ";
        // std::cin >> start_chunk3;
        start_chunk3 = 1;
        std::cout << "End Chunk Consumer 3: ";
        // std::cin >> end_chunk3;
        end_chunk3 = 512;

        start_time = std::chrono::high_resolution_clock::now();

        // Extract the file extension
        size_t dotPos = filename.rfind('.');
        size_t dotPos2 = filename2.rfind('.');
        size_t dotPos3 = filename3.rfind('.');

        std::string extension = (dotPos != std::string::npos) ? filename.substr(dotPos) : "";
        std::string extension2 = (dotPos2 != std::string::npos) ? filename2.substr(dotPos2) : "";
        std::string extension3 = (dotPos3 != std::string::npos) ? filename3.substr(dotPos3) : "";

        std::string filenameWithoutExtension = filename;
        std::string filenameWithoutExtension2 = filename2;
        std::string filenameWithoutExtension3 = filename3;

        // Remove the extension from the filename
        if (!extension.empty()) {
          filenameWithoutExtension = filename.substr(0, dotPos);
        }

        if (!extension2.empty()) {
          filenameWithoutExtension2 = filename2.substr(0, dotPos2);
        }

        if (!extension3.empty()) {
          filenameWithoutExtension3 = filename3.substr(0, dotPos3);
        }
        ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
        consumerHelper.SetPrefix(filename);
        consumerHelper.SetAttribute("FileName", StringValue(filename));
        consumerHelper.SetAttribute("ConsumerId", StringValue("1"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[0]);

        ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        /*for (int i = start_chunk; i <= end_chunk; i++) {
            std::string prefix = "/" + filenameWithoutExtension + "#" + std::to_string(i) +
        extension;
            //std::cout << "Chunk Name: " << prefix << std::endl;
            ndnGlobalRoutingHelper.AddOrigins(prefix, producer);
        }*/

        // ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
        consumerHelper.SetPrefix(filename2);
        consumerHelper.SetAttribute("FileName", StringValue(filename2));
        consumerHelper.SetAttribute("ConsumerId", StringValue("2"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk2));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[3]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename2);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk2));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        /*for (int i = start_chunk2; i <= end_chunk2; i++) {
            std::string prefix2 = "/" + filenameWithoutExtension2 + "#" + std::to_string(i) +
        extension2; ndnGlobalRoutingHelper.AddOrigins(prefix2, producer);
        }*/

        // ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("3"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[7]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        // // 4
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("4"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[1]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        // /* for(int i = start_chunk3; i <= end_chunk3; i++){
        //    std::string prefix3 = "/" + filenameWithoutExtension3 + "#" + std::to_string(i) +
        //    extension3; ndnGlobalRoutingHelper.AddOrigins(prefix3, producer);
        //    }*/

        // // 5
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("5"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[2]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        // // 6
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("6"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[4]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        // // 7
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("7"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[5]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        // // 8
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("8"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[6]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        // // 9
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("9"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[8]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        // 10
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("10"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[9]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        // 11
        consumerHelper.SetPrefix(filename3);
        consumerHelper.SetAttribute("FileName", StringValue(filename3));
        consumerHelper.SetAttribute("ConsumerId", StringValue("11"));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk3));
        consumerHelper.SetAttribute("Frequency", StringValue("100")); // 10 interests a second
        consumerHelper.Install(consumers[10]);

        // ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename3);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk3));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        ndn::GlobalRoutingHelper::CalculateRoutes();

        Simulator::Stop(Seconds(1000.0));

        ndn::L3RateTracer::InstallAll("rate-trace.txt", Seconds(1.0));

        Simulator::Run();
      }
      else {
        // Extract the file extension
        size_t dotPos = filename.rfind('.');
        std::string extension = (dotPos != std::string::npos) ? filename.substr(dotPos) : "";

        std::string filenameWithoutExtension = filename;

        // Remove the extension from the filename
        if (!extension.empty()) {
          filenameWithoutExtension = filename.substr(0, dotPos);
        }

        ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
        consumerHelper.SetPrefix(filename);
        consumerHelper.SetAttribute("FileName", StringValue(filename));
        consumerHelper.SetAttribute("ChunkNumber", IntegerValue(end_chunk));
        consumerHelper.SetAttribute("Frequency", StringValue("1000")); // 1 interests a second
        consumerHelper.SetAttribute("LifeTime", StringValue("999999999999999s"));
        consumerHelper.Install(consumers[7]);

        ndn::AppHelper producerHelper("ns3::ndn::Producer");
        producerHelper.SetPrefix(filename);
        producerHelper.SetAttribute("ChunkNumber", UintegerValue(end_chunk));
        producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
        producerHelper.Install(producer);

        
        ndnGlobalRoutingHelper.AddOrigins(filename, producer);

        // for (int i = start_chunk; i <= end_chunk; i++) {
        //   //std::string prefix = "/" + filenameWithoutExtension + "#" + std::to_string(i) + extension;
        //   ndnGlobalRoutingHelper.AddOrigins(filename, producer);
        //   //ndnGlobalRoutingHelper.AddOrigins(prefix, producer);
        // }
        // // ndnGlobalRoutingHelper.AddOrigins(filename, producer);

        //ndn::GlobalRoutingHelper::CalculateRoutes();
        ndn::GlobalRoutingHelper::CalculateAllPossibleRoutes();

        Simulator::Stop(Seconds(500.0));

        ndn::L3RateTracer::InstallAll("rate-trace.txt", Seconds(0.5));

        Simulator::Run();

        Simulator::Destroy();
      }

      return 0;
      // Simulator::Destroy();
    }
    else if (choice == "0") {
      break;
    }
    else {
      std::cout << "Invalid choice. Please try again." << std::endl;
    }
  }
  // Add /prefix origins to ndn::GlobalRouter
  // ndnGlobalRoutingHelper.AddOrigins(prefix, producer);

  // Calculate and install FIBs
  Simulator::Destroy();

  return 0;
}

} // namespace ns3

int
main(int argc, char* argv[])
{
  return ns3::main(argc, argv);
}