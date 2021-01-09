
if(NOT "D:/work/github/mlspp/build/third_party/src/mpark-variant-extern-stamp/mpark-variant-extern-gitinfo.txt" IS_NEWER_THAN "D:/work/github/mlspp/build/third_party/src/mpark-variant-extern-stamp/mpark-variant-extern-gitclone-lastrun.txt")
  message(STATUS "Avoiding repeated git clone, stamp file is up to date: 'D:/work/github/mlspp/build/third_party/src/mpark-variant-extern-stamp/mpark-variant-extern-gitclone-lastrun.txt'")
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E rm -rf "D:/work/github/mlspp/build/third_party/src/mpark-variant-extern"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: 'D:/work/github/mlspp/build/third_party/src/mpark-variant-extern'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "C:/Program Files/Git/cmd/git.exe"  clone --no-checkout "https://github.com/mpark/variant.git" "mpark-variant-extern"
    WORKING_DIRECTORY "D:/work/github/mlspp/build/third_party/src"
    RESULT_VARIABLE error_code
    )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once:
          ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/mpark/variant.git'")
endif()

execute_process(
  COMMAND "C:/Program Files/Git/cmd/git.exe"  checkout master --
  WORKING_DIRECTORY "D:/work/github/mlspp/build/third_party/src/mpark-variant-extern"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: 'master'")
endif()

set(init_submodules TRUE)
if(init_submodules)
  execute_process(
    COMMAND "C:/Program Files/Git/cmd/git.exe"  submodule update --recursive --init 
    WORKING_DIRECTORY "D:/work/github/mlspp/build/third_party/src/mpark-variant-extern"
    RESULT_VARIABLE error_code
    )
endif()
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: 'D:/work/github/mlspp/build/third_party/src/mpark-variant-extern'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy
    "D:/work/github/mlspp/build/third_party/src/mpark-variant-extern-stamp/mpark-variant-extern-gitinfo.txt"
    "D:/work/github/mlspp/build/third_party/src/mpark-variant-extern-stamp/mpark-variant-extern-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: 'D:/work/github/mlspp/build/third_party/src/mpark-variant-extern-stamp/mpark-variant-extern-gitclone-lastrun.txt'")
endif()

