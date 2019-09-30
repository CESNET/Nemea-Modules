-- del.lua

function tables_cmp(a, b)
   for key, val in pairs(a) do
      if val ~= b[key] then
         error("compare tables failed")
      end
   end
   for key, val in pairs(b) do
      if val ~= a[key] then
         error("compare tables failed")
      end
   end
end

function on_init()
   if pcall(ur_del, "FOO") then
      error("ur_del in on_init should have failed")
   end
end

function on_template_recv()
   if pcall(ur_del, "ipaddr") then
      error("ur_del should have failed")
   end
   if pcall(ur_del, "uint16") then
      error("ur_del should have failed")
   end

   if ur_del("BY") then
      error("ur_del prefix test failed")
   end
   if ur_del("TES") then
      error("ur_del sufix test failed")
   end
   if ur_del("T") or ur_del("_M") then
      error("ur_del substr test failed")
   end

   local ret = {ur_del("LINK_BIT_FIELD", "DIR_BIT_FIELD", "SRC_MAC", "DST_MAC")}
   tables_cmp(ret, {true, true, true, true})

   ret = {ur_del("SRC_IP", "BAR", "DST_IP", "TOS", "TTL", "TCP_FLAGS")}
   tables_cmp(ret, {true, false, true, true, true, true})
 
   ret = {ur_del("TIME_LAST", "TIME_FIRST", "TEST")}
   tables_cmp(ret, {true, true, false})

   --if not pcall(ur_del) then
   --   error("ur_del() failed")
   --end
   if ur_del("int FOO") or ur_del("BAR") then
      error("ur_del should failed to delete nonexistent fields")
   end
end

function on_record_recv()
   if pcall(ur_del, "FOO") then
      error("ur_del in on_record_recv should have failed")
   end

   ur_switch() -- in, out -> out, in
   local expected_fields = {"SRC_PORT", "DST_PORT", "BYTES", "PACKETS", "PROTOCOL"}
   local allfields = ur_get()
   ur_switch() -- out,in -> in, out

   local tmp_fields = {}
   for key, val in pairs(allfields) do
      table.insert(tmp_fields, key)
   end
   table.sort(expected_fields)
   table.sort(tmp_fields)
   tables_cmp(tmp_fields, expected_fields)
end
