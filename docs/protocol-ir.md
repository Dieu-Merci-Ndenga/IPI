# Protocol IR v0.1

Chaque événement contient au minimum:
- timestamp
- src_ip / dst_ip
- transport=TCP
- protocol=Modbus/TCP
- transaction_id
- unit_id
- function
- address
- quantity
- direction

Le champ `evidence_ref` relie chaque événement aux données observées.
