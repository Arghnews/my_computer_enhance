include(FetchContent)

#set(FETCHCONTENT_QUIET FALSE)
FetchContent_Declare(
    vcpkg
    GIT_REPOSITORY https://github.com/microsoft/vcpkg.git
    GIT_TAG        2024.07.12 # release-1.10.0
    #GIT_TAG        1de2026 # release-1.10.0
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
)

FetchContent_MakeAvailable(vcpkg vcpkg)
set(CMAKE_TOOLCHAIN_FILE ${vcpkg_SOURCE_DIR}/scripts/buildsystems/vcpkg.cmake)
