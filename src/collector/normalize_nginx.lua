function normalize_nginx(tag, timestamp, record)
    record["ip"]         = record["remote_addr"] or ""
    local u              = record["remote_user"]
    record["user"]       = (u == nil or u == "-") and nil or u
    record["event_type"] = "request"
    record["source"]     = "nginx"
    record["raw"]        = record["log"]

    record["log"]         = nil
    record["remote_addr"] = nil
    record["remote_user"] = nil
    record["time_local"]  = nil

    return 1, timestamp, record
end
