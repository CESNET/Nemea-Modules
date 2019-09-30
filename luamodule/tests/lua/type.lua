-- type.lua

function test_type(fields, expected, should_fail)
   if #fields ~= #should_fail then
      error("Input sequences length mismatch")
   end
   for i = 1,#fields,1 do
      local ret, type_str = pcall(ur_type, fields[i])
      if not ret then
         if not should_fail[i] then
            error("ur_type failed: " .. type_str)
         end
      else
         if should_fail[i] then
            error("ur_type should have failed")
         end
         if type_str ~= expected[i] then
            if expected[i] == nil then expected[i] = "(nil)" end
            if type_str == nil then type_str = "(nil)" end
            error(fields[i] .. " has invalid type '" .. type_str .. "' expected '" .. expected[i] .. "'")
         end
      end
   end
end

function on_init()
   local fields = {"BYTES", "SRC_IP", "TIME_FIRST"}
   local expected = {"uint64", "ipaddr", "time"}
   local should_fail = {false, false, false}

   test_type(fields, expected, should_fail)

   local allfields = ur_type()
   local fields = {}
   local expected = {}
   local should_fail = {}
   local i = 0
   for key, val in pairs(allfields) do
      fields[i] = key
      expected[i] = val
      should_fail[i] = false
      i = i + 1
   end

   if i != 16 then
      error("Invalid number of fields")
   end
   test_type(fields, expected, should_fail)
end

function on_template_recv()
   local fields = {"DST_MAC", {1, 2, 3}, "TTL", "MY_FIELD"}
   local expected = {"macaddr", nil, "uint8", nil}
   local should_fail = {false, true, false, false}

   test_type(fields, expected, should_fail)

   if pcall(ur_type, nil) then
      error("ur_type call with nil value should fail")
   end
end

function on_record_recv()
   local fields = {"DST_MA", "PACKETS", "", "DST_PORT", 5}
   local expected = {nil, "uint32", nil, "uint16", nil}
   local should_fail = {false, false, false, false, true}

   test_type(fields, expected, should_fail)

   local ret, bytes, packets, foo, bar = pcall(ur_type, "BYTES", "PACKETS", "FOO", "BAR")
   if bytes ~= "uint64" or packets ~= "uint32" or foo ~= nil or bar ~= nil then
      error("ur_type with multiple arguments failed")
   end
end
