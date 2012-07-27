CMAKE_MINIMUM_REQUIRED (VERSION 2.8)
PROJECT (AUTHSAE C)
LIST(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

#####################################################################
INCLUDE(FindPkgConfig)
IF(NOT PKG_CONFIG_FOUND)
	MESSAGE(FATAL_ERROR "Error: pkg-config not found on this system")
ENDIF(NOT PKG_CONFIG_FOUND)

#####################################################################
MESSAGE(STATUS "")
MESSAGE(STATUS "Configuring Host System and compiler flags ...")
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	ADD_DEFINITIONS(-g)
	ADD_DEFINITIONS(-DLINUX)
	ADD_DEFINITIONS(-Wall)
	ADD_DEFINITIONS(-Werror)

	INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})
	LINK_DIRECTORIES(${CMAKE_SOURCE_DIR})

ELSE(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	MESSAGE(FATAL_ERROR "Unsupported system ${CMAKE_SYSTEM_NAME}")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

#####################################################################
MESSAGE(STATUS "")
MESSAGE(STATUS "Configuring libcrypto ...")

PKG_CHECK_MODULES(LIBCRYPTO REQUIRED libcrypto)
IF(LIBCRYPTO_FOUND)
	INCLUDE_DIRECTORIES(${LIBCRYPTO_INCLUDE_DIRS})
	LINK_DIRECTORIES(${LIBCRYPTO_LIB_DIRS})
ENDIF(LIBCRYPTO_FOUND)

#####################################################################
MESSAGE(STATUS "")
MESSAGE(STATUS "Configuring libconfig ...")

PKG_CHECK_MODULES(LIBCONFIG REQUIRED libconfig>=1.3)
IF(LIBCONFIG_FOUND)
	INCLUDE_DIRECTORIES(${LIBCONFIG_INCLUDE_DIRS})
	LINK_DIRECTORIES(${LIBCONFIG_LIB_DIRS})
	IF(${LIBCONFIG_VERSION} VERSION_LESS "1.4.0")
		ADD_DEFINITIONS(-DLIBCONFIG_SETTING_INT_AS_LONG)
	ENDIF(${LIBCONFIG_VERSION} VERSION_LESS "1.4.0")
ENDIF(LIBCONFIG_FOUND)

#####################################################################
MESSAGE(STATUS "")
MESSAGE(STATUS "Configuring libsae ...")

LIST(APPEND libsae_libs
	${LIBCONFIG_LIBRARIES}
	${LIBCRYPTO_LIBRARIES}
)

LIST(APPEND libsae_sources
	common.c
	sae.c
	service.c
	ampe.c
	crypto/aes_siv.c
)

ADD_LIBRARY(sae ${libsae_sources})
TARGET_LINK_LIBRARIES(sae ${libsae_libs})

#####################################################################
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	ADD_SUBDIRECTORY(linux)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

#####################################################################
CONFIGURE_FILE("${CMAKE_SOURCE_DIR}/config/authsae.sample.cfg" "/etc/authsae.cfg" COPYONLY)
