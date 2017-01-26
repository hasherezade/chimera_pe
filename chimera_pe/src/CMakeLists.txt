cmake_minimum_required (VERSION 2.8)
project (ChimeraPE)

add_definitions(-DUNICODE -D_UNICODE)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (peloader_srcs
	peloader/pe_hdrs_helper.cpp
	peloader/pe_raw_to_virtual.cpp
	peloader/load_imports.cpp
	peloader/relocate.cpp
	peloader/inject_pe.cpp
)


set (srcs
    main.cpp
	sysutil.cpp
	target_util.cpp
	process_util.cpp
	${peloader_srcs}
)

set (peloader_hdrs
	peloader/pe_hdrs_helper.h
	peloader/pe_raw_to_virtual.h
	peloader/load_imports.h
	peloader/relocate.h
	peloader/inject_pe.h
)

set (hdrs
	resource.h
	ntddk.h
	ntdll_undoc.h
	target_util.h
	process_util.h
	sysutil.h
	${peloader_hdrs}
)

set (rsrc
    resource.rc
)

SOURCE_GROUP("Source Files\\peloader" FILES ${peloader_srcs} )
SOURCE_GROUP("Header Files\\peloader" FILES ${peloader_hdrs} )

add_executable (ChimeraPE ${rsrc} ${hdrs} ${srcs})