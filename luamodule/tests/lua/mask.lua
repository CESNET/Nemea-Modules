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
   ip = ur_get(id_ip)
   if ur_ip4(ip) then
      ur_set(id_sub, ip / 24)
   else
      ur_set(id_sub, ip / 48)
   end
end
