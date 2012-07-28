#####################################################################
INCLUDE(FindPkgConfig)
IF(NOT PKG_CONFIG_FOUND)
	MESSAGE(FATAL_ERROR "Error: pkg-config not found on this system")
ENDIF(NOT PKG_CONFIG_FOUND)

#####################################################################
MESSAGE(STATUS "")
MESSAGE(STATUS "Configuring libnl ...")

PKG_SEARCH_MODULE(LIBNL libnl>=2.0 libnl-2.0 libnl-2)
IF(LIBNL_FOUND)
	INCLUDE_DIRECTORIES(${LIBNL_INCLUDE_DIRS})
	LINK_DIRECTORIES(${LIBNL_LIB_DIRS})
	LIST(APPEND LIBNL_LIBRARIES
		nl-genl
	)
ELSE(LIBNL_FOUND)
	PKG_SEARCH_MODULE(LIBNL3 libnl-3 libnl-3.0 libnl-3.1)
	IF(LIBNL3_FOUND)
		INCLUDE_DIRECTORIES(${LIBNL3_INCLUDE_DIRS})
		LINK_DIRECTORIES(${LIBNL3_LIB_DIRS})
		SET(LIBNL_LIBRARIES ${LIBNL3_LIBRARIES})

        #############################################################
		MESSAGE(STATUS "")
		MESSAGE(STATUS "Configuring libnl-genl ...")

		PKG_SEARCH_MODULE(LIBNL_GENL libnl-genl>=2.0 libnl-genl-3 libnl-genl-3.0 libnl-genl-3.1)
		IF(LIBNL_GENL_FOUND)
			INCLUDE_DIRECTORIES(${LIBNL_GENL_INCLUDE_DIRS})
			LINK_DIRECTORIES(${LIBNL_GENL_LIB_DIRS})
		ENDIF(LIBNL_GENL_FOUND)
	ELSE(LIBNL3_FOUND)
		MESSAGE(FATAL_ERROR "Error: libnl and libnl-genl not found")
	ENDIF(LIBNL3_FOUND)
ENDIF(LIBNL_FOUND)

#####################################################################
MESSAGE(STATUS "")
MESSAGE(STATUS "Configuring mon ...")

LIST(APPEND mon_sources
	mon.c
	../service.c
	../common.c
)

ADD_EXECUTABLE(mon ${mon_sources})
INSTALL(TARGETS mon DESTINATION bin)

#####################################################################
MESSAGE(STATUS "")
MESSAGE(STATUS "Configuring meshd ...")

LIST(APPEND meshd_libs
	${LIBCONFIG_LIBRARIES}
	${LIBCRYPTO_LIBRARIES}
	sae
)

LIST(APPEND meshd_sources
	meshd.c
	../common.c
	../service.c
	../ampe.c
	../crypto/aes_siv.c
)

ADD_EXECUTABLE(meshd ${meshd_sources})
TARGET_LINK_LIBRARIES(meshd ${meshd_libs})
INSTALL(TARGETS meshd DESTINATION bin)

#####################################################################
MESSAGE(STATUS "")
MESSAGE(STATUS "Configuring meshd-nl80211 ...")

LIST(APPEND meshd_nl80211_libs
	${LIBCONFIG_LIBRARIES}
	${LIBCRYPTO_LIBRARIES}
	${LIBNL_LIBRARIES}
	${LIBNL_GENL_LIBRARIES}
	sae
)

LIST(APPEND meshd_nl80211_sources
	meshd-nl80211.c
	nlutils.c
)

ADD_EXECUTABLE(meshd-nl80211 ${meshd_nl80211_sources})
TARGET_LINK_LIBRARIES(meshd-nl80211 ${meshd_nl80211_libs})
INSTALL(TARGETS meshd-nl80211 DESTINATION bin)
