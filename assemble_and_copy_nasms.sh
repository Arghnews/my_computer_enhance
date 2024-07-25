#!/usr/bin/env bash

set -u -o pipefail

source_dir="$1"
dest_dir="$1"
#dest_dir="$2"
#source_dir="x86_resources"
#dest_dir="test_dir"

for f in "$source_dir"/*.asm; do
    filename="$(basename $f .asm)" # Without extension
    #echo nasm -o "$dest_dir/$filename" "$source_dir/${filename}.asm"
    nasm -o "$dest_dir/$filename" "$source_dir/${filename}.asm"
done

