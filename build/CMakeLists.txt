cmake_minimum_required (VERSION 2.8)

include_directories (.. 
					../hlsdk/dlls 
					../hlsdk/engine 
					../hlsdk/common 
					../metamod
		)

set (PROJECT floodblocker)
set (HEADERS
		../core.h
		../engFunc.h
		../fSV_ConnectClient.h
		../fIsSafeFileToDownload.h
		../dllinfo.h
	)
set (SOURCES
		../core.cpp
		../engFunc.cpp
		../fSV_ConnectClient.cpp
		../fIsSafeFileToDownload.cpp
	)

set (CMAKE_BUILD_TYPE Release)
if (WIN32)
	set (SOURCES ${SOURCES} ../floodblocker.rc)
endif ()

project (${PROJECT})
add_library (${PROJECT} MODULE ${HEADERS} ${SOURCES})
set_target_properties (${PROJECT} PROPERTIES PREFIX "")
if (NOT WIN32)
	set (CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-fvisibility=hidden")
endif ()
