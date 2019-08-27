-- mask.lua

function on_init()
end

function on_template_recv()
   ur_del("SRC_IP")
   ur_add("ipaddr SRC_SUBNET")
end

function on_record_recv()
   ip = ur_get("SRC_IP")
   if ur_ip4(ip) then
      ur_set("SRC_SUBNET", ip / 24)
   else
      ur_set("SRC_SUBNET", ip / 48)
   end
end
