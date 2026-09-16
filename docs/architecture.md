# Architecture V0

Pipeline: PCAP -> parsing réseau -> reconstruction TCP -> décodage Modbus/TCP -> Protocol IR -> modèle comportemental -> moteur d'anomalies -> explications grounded -> vérification -> rapport JSON.

Le parsing et les faits observés sont déterministes. Les explications sont contraintes par les preuves issues du Protocol IR.
