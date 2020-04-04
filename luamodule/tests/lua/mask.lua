-- mask.lua

function on_init()
end

function on_template_recv()
   ur_del("SRC_IP")
   ur_add("ipaddr SRC_SUBNET")
   id_ip = ur_id("SRC_IP")
   id_sub = ur_id("SRC_SUBNET")
end

function on_record_recv()
   local ip = ur_get(id_ip)
   local subnet
   if ur_ip4(ip) then
      subnet = ip / 24
   else
      subnet = ip / 48
   end

   ur_set(id_sub, subnet)
   print(tostring(subnet))
end
