#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/ndnSIM-module.h"
#include "/home/couto/Desktop/ndnSIM/ns-3/src/ndnSIM/apps/ndn-consumer-cbr.hpp"
#include "/home/couto/Desktop/ndnSIM/ns-3/src/ndnSIM/NFD/daemon/table/fib-entry.hpp"
#include "ns3/applications-module.h"
#include "ns3/ndnSIM/ndn-cxx/data.hpp"
#include "ns3/ndnSIM/ndn-cxx/name.hpp"
#include "ns3/ndnSIM/ndn-cxx/interest.hpp"

namespace ns3 {

int main(int argc, char* argv[]) {
  CommandLine cmd;
  cmd.Parse(argc, argv);

  // Create nodes
  NodeContainer nodes;
  nodes.Create(3); // One consumer, one producer, one intermediate node

  // Install NDN stack
  ndn::StackHelper ndnHelper;
  ndnHelper.InstallAll();

  // Set up forwarding strategy on the intermediate node
  ndn::StrategyChoiceHelper::Install(nodes.Get(2), "/", "/localhost/nfd/strategy/multicast");

  // Set up applications
  ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
  consumerHelper.SetAttribute("Prefix", StringValue("/producer"));
  consumerHelper.SetAttribute("Frequency", StringValue("1")); // Request frequency in Hz
  consumerHelper.Install(nodes.Get(0));

  ndn::AppHelper producerHelper("ns3::ndn::Producer");
  producerHelper.SetAttribute("Prefix", StringValue("/producer"));
  producerHelper.Install(nodes.Get(1));

  // Set up consumer's interest
  Simulator::Schedule(Seconds(1.0), [&] {
    Ptr<Application> app = nodes.Get(0)->GetApplication(0);
    app->SetAttribute("MaxSeq", StringValue("1024")); // Set chunk size
    app->SetAttribute("Prefix", StringValue("/producer")); // Set producer's prefix
    app->SetAttribute("Frequency", StringValue("1"));     // Request frequency in Hz
  });

  // Run simulation
  Simulator::Stop(Seconds(10.0));
  Simulator::Run();
  Simulator::Destroy();

  return 0;
}
} // namespace ns3

int
main(int argc, char* argv[])
{
  return ns3::main(argc, argv);
}