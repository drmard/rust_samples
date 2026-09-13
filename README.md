Some rust code samples demonstrating its memory management features and asynchronous execution methods.
- - - - -

  1.The code presented in the 'anti_ddos' directory serves as an excellent application-layer (L7) intelligent proxy filter that implements a specific part of an Anti-DDoS service's functionality. User-space code is powerless to provide complete protection against attacks of "all types" (including UDP/ICMP amplification or raw SYN floods at terabit speeds), as the OS kernel still consumes resources processing network interrupts.
  
  2.The 'dlp' directory contains the code for the core components of any DLP service, which provide control over the majority of potential data leakage channels: a full-featured content analysis module(Content Inspection Engine that uses regular expressions, hash calculations, and digital fingerprints), an efficient network sniffer with proxy capabilities, and a package implementing a complete set of interception agents (Endpoint Hooks) for file operations.
  
  3.The 'dns_server' directory contains a Rust implementation of a DNS server prototype using the 'hickory-dns', 'tokio', and 'axum' packages, supporting recursive forwarding, Dynamic DNS(DDNS), and caching of external requests.

  4.The 'dns_telemetry' directory contains a Rust implementation of DNS telemetry. A brief description of the architecture follows below.
    - Capture Stream (Blocking Thread): By design, pcap blocks the thread while waiting for packets. We will offload this to a dedicated native thread.
    - Asynchronous Channel (tokio::sync::mpsc): The capture thread will capture raw packet bytes (Vec<u8>) and immediately send them via a thread-safe multi-producer, single-consumer (MPSC) channel. This ensures the network buffer does not overflow and packets are not dropped.
    - Asynchronous Handler (Tokio Task): The main asynchronous loop will read packets from the channel, parse them (Ethernet/IP/UDP/DNS), and output telemetry without blocking traffic capture.

  5.The 'siem_clickhouse_processor' directory contains a Rust implementation of a reliable asynchronous SIEM event processing service using Tokio, MPSC channels for backpressure, ClickHouse integration for batch insertion with Local WAL(Write-Ahead Log) that ensures reliable data delivery in rust client applications and protects against data loss during network outages or ClickHouse failures.

  How to test this.
    1.Start the local web application (or any service) you want to expose. Let's assume it runs on port 3000. You can run the command `python -m http.server 3000`.
    2.Start our server (simulating operation on a VPS):

      cargo run -- server 8001 8080

    Port 8001 is used for tunnel coordination, while external users will connect to port 8080.
    3.Start our client:

      cargo run -- client 127.0.0.1:8001 127.0.0.1:3000

    4.Verification:
    Open your browser and go to http://127.0.0.1:8080. You will see the content served by your application from port 3000.

    What is needed for a full-fledged ngrok?
    The code above is a basic demonstration (MVP). To turn it into a full-fledged product, you would need to implement:
      Multiplexing: Using libraries like yamux to handle hundreds of sessions within a single TCP connection, rather than opening new TCP ports for every single request.
      Authorization: Passing security tokens from the client to the server during the connection process.
      Dynamic subdomains: Integrating with an HTTP parser on the server to identify which subdomain (e.g., subdomain.yourdomain.com) the request is targeting and route   it to the specific client.



