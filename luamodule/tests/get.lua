-- get.lua

function on_init()
   if pcall(ur_get, "BYTES") then
      error("ur_get in on_init should have failed")
   end
end

function on_template_recv()
   if pcall(ur_get, "BYTES") then
      error("ur_get in on_template_recv should have failed")
   end
end

function on_record_recv()
   if not pcall(ur_get, "BYTES") then
      error("ur_get failed")
   end

   local allfields = ur_get()
   local index = 0
   for key, val in pairs(allfields) do
      index = index + 1
   end
   if index ~= 16 then
      error("invalid number of fields")
   end
   if allfields["DST_IP"] / 24 ~= "77.147.32.0" or allfields["PROTOCOL"] ~= 6 or allfields["PACKETS"] ~= 19 then
      error("ur_get() table test failed")
   end

   if ur_get("MY_FIELD") ~= nil then
      error("ur_get to nonexistent field failed")
   end

   local sport, time, foo, tos = ur_get("SRC_PORT", "TIME_FIRST", "FOO", "TOS")
   if sport ~= 33624 or time ~= 1565886990.012 or foo ~= nil or tos ~= 0 then
      error("ur_get with multiple arguments failed")
   end

   if pcall(ur_get, 5) or pcall(ur_get, {"BYTES"}) then
      error("ur_get invalid arguments test should have failed")
   end
end
