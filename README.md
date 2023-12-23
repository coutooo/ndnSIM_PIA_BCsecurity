# NDN-Blockchain-PIA: Secure Named Data Networking Simulation with Blockchain Integration and PIA Transport Layer

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Overview

This repository presents an adaptation of the ndnSIM (Named Data Networking Simulation) framework enhanced with a security layer utilizing blockchain technology. Additionally, the transport layer has been augmented with the PIA (Persistent Interest Approach) protocol to enhance performance and reliability in simulated NDN environments.

## Features

- **NDN Simulation with ndnSIM**: Utilize the ndnSIM framework to simulate Named Data Networking scenarios.
- **Blockchain Integration**: Integrate a security layer based on blockchain technology to enhance data integrity and trust in the NDN environment.
- **PIA Transport Layer**: Implement the PIA transport layer to improve the efficiency and reliability of data transfer in NDN simulations, using persistent interests.

## Getting Started

### Prerequisites

- [ndnSIM](https://ndnsim.net/current/) installed on your system.
- [Blockchain using Hyperledger Sawtooth](https://github.com/coutooo/CityInfo) integrated into the ndnSIM environment.

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/coutooo/ndnSIM_PIA_BCsecurity
    cd ndnSIM_PIA_BCsecurity
    ```
2. Clone the Blockchain repository:

    ```bash
    git clone https://github.com/coutooo/CityInfo
    ```

3. Run the blockchain:

    - check CityInfo repo.

4. Build and install the simulation:

    ```bash
    ./waf configure
    ./waf
    sudo ./waf install
    ```

5. Run the simulation:

    ```bash
    ./waf --run ndn-grid
    ```

## Configuration

Adjust simulation parameters, blockchain settings, and PIA configuration in the relevant configuration files. Refer to the documentation for detailed instructions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to the contributors and maintainers of ndnSIM and Hyperledger Sawtooth.

## Contact

For any inquiries, feel free to contact.

