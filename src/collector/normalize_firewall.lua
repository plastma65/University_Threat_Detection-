-- pfSense filterlog CSV columns (1-indexed):
-- 1:rulenumber 2:subrule 3:anchor 4:tracker 5:interface 6:reason
-- 7:action 8:direction 9:ipversion 10:tos 11:ecn 12:ttl 13:id
-- 14:offset 15:flags 16:protoid 17:proto 18:length
-- 19:src 20:dst 21:srcport 22:dstport 23:datalen

local function split_csv(line)
    local fields = {}
    for field in (line .. ","):gmatch("([^,]*),") do
        fields[#fields + 1] = field
    end
    return fields
end

function normalize_firewall(tag, timestamp, record)
    local line = record["log"] or ""

    if line:match("^rulenumber") or line:match("^#") or line == "" then
        return -1, timestamp, record  -- drop header / empty lines
    end

    local f = split_csv(line)

    local action = (f[7] or ""):lower()
    record["interface"]  = f[5]  or ""
    record["action"]     = action
    record["direction"]  = f[8]  or ""
    record["proto"]      = f[17] or ""
    record["src_port"]   = f[21] or ""
    record["dst_port"]   = f[22] or ""

    record["ip"]         = f[19] or ""
    record["user"]       = nil
    record["event_type"] = (action == "block") and "block" or "pass"
    record["source"]     = "firewall"
    record["raw"]        = line

    record["log"] = nil
    return 1, timestamp, record
end
