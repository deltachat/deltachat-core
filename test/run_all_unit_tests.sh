#!/usr/bin/env bash

# TODO: Replace this script with a proper integration into the ninja build.
# Until then, further test files can be added to $test_source_file_paths

executable_folder_path='/tmp/delta_chat_unit_tests'
test_source_file_paths=(
    'dc_prefix_detection_test.c'
)

main() {
    initialise_executable_folder
    compile
    run
}

initialise_executable_folder() {
    mkdir -p "$executable_folder_path"
    rm -rf "${executable_folder_path}/"*
}

compile() {
    for test_source_file_path in "${test_source_file_paths[@]}"; do
        gcc -Wall -o "${executable_folder_path}/${test_source_file_path%.c}"  \
            "$test_source_file_path" \
            -l cmocka \
        || exit_with_message "$?" "Compilation failed, tests will not be executed."
    done
}

exit_with_message() {
    exit_code="$1"
    message="$2"

    echo "$message"
    exit "$exit_code"
}

run() {
    for test_source_file_path in "${test_source_file_paths[@]}"; do
        "${executable_folder_path}/${test_source_file_path%.c}"
    done
}

main
