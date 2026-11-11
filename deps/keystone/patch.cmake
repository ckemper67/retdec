# Keystone sets policy CMP0051 to OLD, which CMake 4.0+ no longer supports.
# Switch it to NEW in every CMakeLists.txt that does so.

file(GLOB_RECURSE cmake_files "${keystone_path}/CMakeLists.txt")

foreach(file ${cmake_files})
	file(READ "${file}" content)
	string(REPLACE
		"cmake_policy(SET CMP0051 OLD)"
		"cmake_policy(SET CMP0051 NEW)"
		new_content
		"${content}"
	)
	if(NOT "${content}" STREQUAL "${new_content}")
		file(WRITE "${file}" "${new_content}")
	endif()
endforeach()
