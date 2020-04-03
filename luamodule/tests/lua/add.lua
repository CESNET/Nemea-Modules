-- add.lua

function on_init()
   if pcall(ur_add, "uint8 TEST1") then
      error("ur_add in on_init should have failed")
   end
end

function on_template_recv()
   if not ur_add("uint8 TEST1") then
      error("ur_add failed")
   end
   ur_add("int32* INT_ARR", "uint32 FOO, uint16 BAR", "double ABC");
   ur_add("ipaddr* IP_ARR");

   if ur_type("INT_ARR") ~= "int32*" or ur_type("FOO") ~= "uint32" or ur_type("BAR") ~= "uint16" or
      ur_type("ABC") ~= "double" or ur_type("TEST1") ~= "uint8" then
      error("ur_type failed")
   end
   if not ur_add("int32* INT_ARR") then
      error("double add failed")
   end
   if ur_add("int8* INT_ARR") then
      error("ur_add of existing field but with different type should fail")
   end

   if ur_add("uint32 F", "int INT") then
      error("ur_add should have failed")
   end
   if ur_add("tmp", "tmp") then
      error("ur_add should have failed - bad UniRec type 'tmp'")
   end
   if pcall(ur_add) then
      error("ur_add should have failed")
   end
end

function on_record_recv()
   if pcall(ur_add, "uint8 TEST2") then
      error("ur_add in on_record_recv should have failed")
   end

   ur_switch(); -- in,out -> out,in
   allfields = ur_get()
   ur_switch(); -- out,in -> in,out
   local expected_fields = {"SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT",
      "PROTOCOL", "TIME_FIRST", "TIME_LAST", "BYTES", "PACKETS", "TOS",
      "TTL", "TCP_FLAGS", "SRC_MAC", "DST_MAC", "DIR_BIT_FIELD", "LINK_BIT_FIELD",
      "TEST1", "INT_ARR", "FOO", "BAR", "ABC", "IP_ARR"}

   local tmp_fields = {}
   for key, val in pairs(allfields) do
      table.insert(tmp_fields, key)
   end
   table.sort(expected_fields)
   table.sort(tmp_fields)
   for key, val in pairs(tmp_fields) do
      if val ~= expected_fields[key] then
         error("compare tables failed, expected " .. val .. " got " .. expected_fields[key])
      end
   end
end
