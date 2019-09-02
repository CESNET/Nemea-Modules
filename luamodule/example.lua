-- example.lua
--
-- Remove fields, keep IPs, PORTs, PROTOCOL
-- Add statistic fields like packets per second (PPS), bytes per second (BPS), bytes per packet (BPP) and duration (DURATION)
-- Example script expects to receive fields from flow_meter module

function on_init()
end

function on_template_recv()
   ur_add("uint32 PPS, uint32 BPS", "uint32 BPP", "double DURATION")
   ur_del("TIME_FIRST", "TIME_LAST", "TCP_FLAGS", "DIR_BIT_FIELD", "LINK_BIT_FIELD", "SRC_MAC", "DST_MAC", "TOS", "TTL")
   --ur_del("SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "PROTOCOL")
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

      local conv = string.format("%d@%s:%d->%s:%d", ur_get("PROTOCOL"), ur_get("SRC_IP"), ur_get("SRC_PORT"), ur_get("DST_IP"), ur_get("DST_PORT"))
      print(
         string.format("ID=% 5.0f", _REC_COUNT),
         string.format("%42s", conv),
         string.format("DUR=% 6.3f", DURATION),
         string.format("BPP=% 6.3f", BPP),
         string.format("PPS=% 6.3f", PPS),
         string.format("BPS=% 6.3f", BPS))
      ur_set("DURATION", DURATION, "BPP", BPP, "PPS", PPS, "BPS", BPS)
   end
end
