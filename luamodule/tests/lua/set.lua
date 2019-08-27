-- set.lua

function on_init()
   if pcall(ur_set, "BYTES", "123") then
      error("ur_set in on_init should have failed")
   end
end

function on_template_recv()
   if pcall(ur_set, "BYTES", "123") then
      error("ur_set in on_template_recv should have failed")
   end
end

function on_record_recv()
   ur_switch() -- in,out -> out,in
   if not pcall(ur_set, "BYTES", 123) then
      error("ur_set failed")
   end
   ur_set("PACKETS", 456)
   ur_switch() -- out,in -> in,out

   local bytes, packets = ur_get("BYTES", "PACKETS")
   if bytes ~= 123 or packets ~= 456 then
      error("ur_set failed")
   end

   ur_switch() -- in,out -> out,in
   local res1, res2, res3 = ur_set("TOS", 64, "FIELD", 1, "DIR_BIT_FIELD", 128)
   ur_switch() -- out,in -> in,out
   local tos, field, dir = ur_get("TOS", "FIELD", "DIR_BIT_FIELD")
   if not res1 or res2 or not res3 or tos ~= 64 or field ~= nil or dir ~= 128 then
      error("ur_set with invalid fields failed")
   end
   if pcall(ur_set, "TOS") or pcall(ur_set, "TOS", 5, "TTL") then
      error("ur_set with invalid arguments should have failed")
   end
   if pcall(ur_set) then
      error("ur_set with no arguments failed")
   end
end
