#!/bin/bash

export LC_ALL=C
export LANG=C

test -z "${srcdir}" && export srcdir=.

luamodule_bin="../luamodule"

lua_dir="${srcdir}/lua"
ref_dir="${srcdir}/reference"
in_dir="${srcdir}/unirec"
out_dir="./output"

# Usage: run_test <lua-script> <ur_in_file> <ur_out_file>
run_test() {
   local lua_script="${lua_dir}/$1"
   local ur_in_file="${in_dir}/$2"
   local ur_out_file="${out_dir}/$3"
   local ur_ref_file="${ref_dir}/$3"

   if ! [ -f "${luamodule_bin}" ]; then
      echo "luamodule not compiled"
      return 77
   fi

   if ! [ -d "${out_dir}" ]; then
      mkdir "${out_dir}"
   fi

   rm ${ur_out_file} 2>/dev/null
   "${luamodule_bin}" -i "f:${ur_in_file},f:${ur_out_file}" -l "${lua_script}" >/dev/null

   if cmp "${ur_ref_file}" "${ur_out_file}"; then
      echo "$1 script test OK"
   else
      echo "$1 script test FAILED"
      return 1
   fi
}
