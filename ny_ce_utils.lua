local module = {}

module.tostring = function(o)
    if type(o) ~= "table" then return tostring(o) end
    if o.__tostring then return o:__tostring() end
    if next(o) == nil then return "{}" end
    local res = "{"
    for k, v in pairs(o) do
        if type(k) == "number" then
            k = "[" .. k .. "]"
        else
            k = '["' .. k .. '"]'
        end
        res = res .. k .. "=" .. module.tostring(v) .. ","
    end
    res = res .. "}"
    return res
end

module.aobScan = function(pattern, param)
    local i = -1
    local param_offset = nil
    local param_size = 0
    for segment in pattern:gmatch("%S+") do
        i = i + 1
        if segment == '*' then
            if param_offset == nil then
                param_offset = i
            end
            param_size = param_size + 1
        elseif param_offset ~= nil then
            break
        end
    end
    local read_param = nil
    if param_offset ~= nil then
        if param_size == 1 then
            read_param = function(ea, signed)
                local val = readBytes(ea)
                if signed and val > 127 then
                    val = val - 256
                end
                return val
            end
        elseif param_size == 2 then
            read_param = readSmallInteger
        elseif param_size == 4 then
            read_param = readInteger
        else
            error(("Unknown param size %d"):format(param_size))
        end
    end

    param = param or {}
    local startScan = 0
    local endScan = 0x7FFFFFFFFFFFFFFF
    local protectionflags = param.protectionflags ~= nil or ""
    local unique = param.unique ~= nil and param.unique or true
    if param.module ~= nil then
        local base = getAddress(param.module)
        local size = getModuleSize(param.module)
        if base == nil or size == nil then
            error(("%s is not a valid module"):format(param.module))
        end
        startScan = base
        endScan = base + size
    end
    if param.startScan ~= nil then
        startScan = startScan > param.startScan and startScan or param.startScan
    end
    if param.endScan ~= nil then
        endScan = endScan < param.endScan and endScan or param.endScan
    end

    local memscan = createMemScan()
    -- print(("%x -> %x protectionflags=%s Pattern=%s"):format(startScan, endScan, tostring(protectionflags), pattern))
    memscan.firstScan(
        soExactValue, vtByteArray, rtRounded,
        pattern, nil, startScan, endScan, protectionflags,
        fsmNotAligned, "", true, false, false, false)
    memscan.waitTillDone()

    local foundlist = createFoundList(memscan)
    foundlist.initialize()
    -- print(("found: %d"):format(foundlist.Count))
    local result = nil
    local addrs = foundlist.Address
    for i = 0, foundlist.Count - 1 do
        local res = getAddress(addrs[i])
        if read_param ~= nil then
            res = read_param(res + param_offset, true)
        end
        if result == nil then
            result = res
            if not unique then break end
        elseif result ~= res then
            error("Found more than one result")
        end
    end

    foundlist.destroy()
    memscan.destroy()

    if result == nil then
        error("aob " .. pattern .. " not found")
    end

    return result
end

module.aobScanModule = function(name, m, aob)
    local res = module.aobScan(aob, { module = m })
    if name ~= nil then
        registerSymbol(name, res)
    end
    return res
end

module.defAobScanModule = function(issyntaxcheck, vname, m, aob)
    if issyntaxcheck then
        return ("define(%s,%x)"):format(vname, 0)
    else
        return ("define(%s,%x)"):format(vname, module.aobScanModule(vname, m, aob))
    end
end

module.ensure_monopipe = function()
    if monopipe then return monopipe end
    LaunchMonoDataCollector()
    if monopipe then return monopipe end
    error(MessageDialog('Failed to Launch Mono Data Collector', mtError, mbClose))
end

module.findMonoFunction = function(namespace, cls, method, sign)
    module.ensure_monopipe()
    local methods = mono_class_enumMethods(mono_findClass(namespace, cls))
    for i = 1, #methods do
        if methods[i].name == method then
            if sign == nil or mono_method_getSignature(methods[i].method) == sign then
                return mono_compile_method(methods[i].method)
            end
        end
    end
    error(("cannot find method %s:%s:%s with sign "):format(namespace, cls, method, sign))
end

module.defMonoFunction = function(issyntaxcheck, vname, namespace, cls, method, sign)
    if issyntaxcheck then
        return ("define(%s,%x)"):format(vname, 0)
    else
        return ("define(%s,%x)"):format(vname, module.findMonoFunction(namespace, cls, method, sign))
    end
end

module.autoAttach = function (process_name)
  if process == process_name and getAddress(process_name) ~= 0 then
    return
  end
  local pid = getProcessIDFromProcessName(process_name)
  if pid == nil then
    error("process " .. process_name .. " not found")
  end
  openProcess(pid)
end

module.addCompactMenu = function()
  if compactmenualreadyexists then return end
  compactmenualreadyexists = 'yes'

  local parent = getMainForm().Menu.Items
  local compactmenuitem = createMenuItem(parent); parent.add(compactmenuitem)
  compactmenuitem.Caption = 'Compact View Mode'
  compactmenuitem.OnClick = function(sender, force)
    local state = not (compactmenuitem.Caption == 'Compact View Mode')
    if force ~= nil then state = not force end
    compactmenuitem.Caption         = state and 'Compact View Mode' or 'Full View Mode'
    getMainForm().Splitter1.Visible = state
    getMainForm().Panel4.Visible    = state
    getMainForm().Panel5.Visible    = state
  end
end

module.createMonoInstanceRecord = function (options)
    -- local al = getAddressList()
    -- local mr = module.createMonoInstanceRecord({
    --   fields = {
    --       {path="player.Gold", name="Gold"},
    --   },
    --   parent=mr,
    --   class=mono_findClass("", "Battle"),
    -- })
    -- mr.Description = "Battle"
    -- mr.ShowAsHex = true
    -- mr.Address = "data_at"
    -- mr.Type = vtQword
    -- mr.OffsetCount = 1
    -- mr.DontSave = true

    module.ensure_monopipe()
    options = options or {}
    local al = getAddressList()
    local parent = options.parent
    if parent == nil then
        parent = al.createMemoryRecord()
    end
    local fields = {}
    local cls = options.class
    if cls == nil then
        error("Required option 'class' is not provided")
    end
    
    if options.fields == nil then
        local _fields = mono_class_enumFields(cls,1)
        for i = 1, #_fields do
            local f = _fields[i]
            if not f.isStatic then
                local field = {
                    name = f.name,
                    offsets = {f.offset},
                    type = monoTypeToVarType(f.monotype),
                }
                if field.type == vtPointer then
                    field.class = mono_field_getClass(f.field)
                end
                fields[#fields + 1] = field
            end
        end
    else
        local function resolveOffset(cls, path)
            local current, _, next = path:match("([^%.]+)(%.?)(.*)")
            local fields = mono_class_enumFields(cls, 1)
            for i = 1, #fields do
                local f = fields[i]
                if f.name == current then
                    local vType = monoTypeToVarType(f.monotype)
                    if next == "" then
                        return {f.offset}, vType, f.field
                    end
                    if vType ~= vtPointer then
                        error(("Field %s is not a pointer in class %s"):format(current, mono_class_getName(cls)))
                    end
                    local offsets, ftype, member = resolveOffset(mono_field_getClass(f.field), next)
                    return {f.offset, table.unpack(offsets)}, ftype, member
                end
            end
            error(("Field %s not found in class %s"):format(current, mono_class_getName(cls)))
        end

        for i = 1, #options.fields do
            local field_ = options.fields[i]
            if type(field_) ~= "table" or field_.path == nil then
                error("Invalid field definition: " .. module.tostring(field_))
            end
            local offsets, vType, member = resolveOffset(cls, field_.path)
            local field = {
                name = field_.name or field_.path,
                offsets = offsets,
                type = vType
            }
            if vType == vtPointer then
                field.class = mono_field_getClass(member)
            end
            fields[#fields + 1] = field
        end
    end

    for i = 1, #fields do
        local field = fields[i]
        local mr = al.createMemoryRecord()
        mr.DontSave = true
        mr.Description = field.name
        if options.onCreateField then
            options.onCreateField(mr, field)
        end
        mr.address = ("+%x"):format(field.offsets[1])
        -- mr.OffsetCount = #field.offsets
        -- for j = 1, #field.offsets do
        --     mr.Offset[j - 1] = field.offsets[j]
        -- end
        if #field.offsets > 1 then
            mr.OffsetCount = #field.offsets - 1
            for j = 2, #field.offsets do
                mr.Offset[j - 2] = field.offsets[j]
            end
        end
        if field.type == vtPointer then
            mr.Type = vtAutoAssembler
            mr.OffsetCount = mr.OffsetCount + 1
            mr.Script = ([[{$lua}
[ENABLE]
if not syntaxcheck then require("ny_ce_utils").createMonoInstanceRecord({
    class = 0x%x,
    parent = memrec,
}) end

[DISABLE]
if not syntaxcheck then (function()
  while memrec.Count > 0 do
    memrec.Child[0].destroy()
  end
end)() end
]]):format(field.class)
        else
            mr.Type = field.type
        end
        
        mr:appendToEntry(parent)
    end

    return parent
end

return module
