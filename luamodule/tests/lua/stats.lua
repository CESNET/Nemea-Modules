-- stats.lua

function on_init()
end

function on_template_recv()
   ur_add("uint32 PPS, uint32 BPS", "uint32 BPP", "double DURATION")
   ur_del("TIME_FIRST", "TIME_LAST", "TCP_FLAGS", "DIR_BIT_FIELD", "LINK_BIT_FIELD", "SRC_MAC", "DST_MAC", "TOS", "TTL")
end

function on_record_recv()
   local bytes, packets = ur_get("BYTES", "PACKETS")
   local first, last = ur_get("TIME_FIRST", "TIME_LAST")

   if bytes ~= nil and packets ~= nil and first ~= nil and last ~= nil then
      local DURATION = last - first
      local BPP = bytes / packets
      local PPS, BPS

      if DURATION ~= 0 then
         PPS = packets / DURATION
         BPS = bytes / DURATION
      else
         PPS = 0
         BPS = 0
      end

      ur_set("DURATION", DURATION, "BPP", BPP, "PPS", PPS, "BPS", BPS)
   end
end
