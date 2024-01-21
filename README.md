# NetUtil
Network programming utility header for Linux

## MREPRO_COMMON v0.4.2
All in one utility header for Network Programming.

Currently features:
  - all necessary includes in one place       
  - some defines, typedefs, macros for ease of use
  - colored formatted multilevel (stdout and syslog abstracted) logging system
  - demonization of process
  - colored formatted asserts
  - utility functions for networking and filesystem
  - simple tcp, udp and http servers/listeners
  - wrappers for various functions
  - blocking listener for any kind of socket
  - simple web server

## USAGE

For each compile target(executable or library) do this in only ONE source file:

Before including header, define one of these
  - MREPRO_COMMON_IMPL_DEBUG 
  - MREPRO_COMMON_IMPL_RELEASE (omits logger functions)

Optionally define:
  - MREPRO_MAX_PACKET_SIZE [4096]
  - MREPRO_SOCKET_NUM_LISTEN [1024]
  - MREPRO_MAX_URI_SIZE [200]
  - MREPRO_MAX_HTTP_ATTRIBS [20]
  - MREPRO_MAX_HTTP_ATTRIB_SIZE [200]
