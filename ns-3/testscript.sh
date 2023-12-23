#!/bin/bash

# Set the desired umask value to control file permissions
umask 0022

# Defina o número de iterações desejadas
num_iteracoes=10

# Crie o diretório /traces se não existir
mkdir -p /traces

# Loop para executar o programa 10 vezes
for ((i=1; i<=$num_iteracoes; i++))
do
  # Configurar a variável de ambiente NS_LOG e executar o programa
  NS_LOG=ndn.Consumer:ndn.Producer ./waf --run=ndn-grid

  # Nome do arquivo de saída com base na iteração
  output_file="/home/couto/Desktop/ndnSIM_chunks_1interest/ns-3/traces/rate-trace-$i.txt"

  # Move o arquivo de saída para o local desejado
  mv rate-trace.txt "$output_file"

done

