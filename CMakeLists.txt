cmake_minimum_required (VERSION 2.8)
project (chimera_pe_loader)

# modules:
set ( M_LOADER "chimera_pe" )
set ( M_PAYLOAD "chimera_pe_payload_template" )

# modules paths:
set (LOADER_DIR "${CMAKE_SOURCE_DIR}/${M_LOADER}" CACHE PATH "Loader path")
set (PAYLOAD_DIR "${CMAKE_SOURCE_DIR}/${M_PAYLOAD}" CACHE PATH "Payload template path")

# Add sub-directories
#
add_subdirectory( ${M_LOADER} )
add_subdirectory( ${M_PAYLOAD} )
