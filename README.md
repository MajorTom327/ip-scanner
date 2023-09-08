# IP Scanner

This is a simple IP Scanner that scans the network for active hosts. It only connect to TCP port (Default are 80, 443 and 22) to check if thoses ports are open.

## Important to notice

This is a basic proof of concept. It is not optimized and it is not meant to be used in a production environment. It is only a simple script that I made to learn more about Rust and networking.

There is some optimizations that can be done, like adding the export to a file, working with ipv6, ensure the inputs are valid (Like a valid IP address or a valid port number), somes colors to the output, etc.
