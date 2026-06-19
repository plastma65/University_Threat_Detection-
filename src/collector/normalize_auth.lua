local PATTERNS = {
    -- order matters: more specific first
    { pat = "Failed password for invalid user (%S+) from ([%d%.]+)", etype = "login_fail",        has_ip = true  },
    { pat = "Failed password for (%S+) from ([%d%.]+)",             etype = "login_fail",        has_ip = true  },
    { pat = "Accepted %S+ for (%S+) from ([%d%.]+)",                etype = "login_success",     has_ip = true  },
    { pat = "Invalid user (%S+) from ([%d%.]+)",                    etype = "login_fail",        has_ip = true  },
    { pat = "session opened for user (%S+)",                        etype = "session_open",      has_ip = false },
    { pat = "session closed for user (%S+)",                        etype = "session_close",     has_ip = false },
    { pat = "Disconnected from (%S+ )?([%d%.]+)",                   etype = "disconnect",        has_ip = true  },
}

local function parse_message(msg)
    for _, p in ipairs(PATTERNS) do
        if p.has_ip then
            local user, ip = msg:match(p.pat)
            if user then return user, ip, p.etype end
        else
            local user = msg:match(p.pat)
            if user then return user, nil, p.etype end
        end
    end
    -- fallback: grab any IP-like token
    local ip = msg:match("from ([%d%.]+)")
    return nil, ip, "auth_event"
end

function normalize_auth(tag, timestamp, record)
    local msg        = record["message"] or ""
    local user, ip, etype = parse_message(msg)

    record["ip"]         = ip   or ""
    record["user"]       = user
    record["event_type"] = etype
    record["source"]     = "auth"
    record["raw"]        = record["log"]

    record["log"]     = nil
    record["time"]    = nil
    record["message"] = nil

    return 1, timestamp, record
end
