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

module.autoAttach = function(process_name)
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

module.resolveMonoPath = function(cls, path, instance)
    module.ensure_monopipe()
    local current, _, next = path:match("([^%.]+)(%.?)(.*)")
    local fields = mono_class_enumFields(cls, 1)
    for i = 1, #fields do
        local f = fields[i]
        if f.name == current then
            -- print(module.tostring(f))
            local address;
            if f.isStatic then
                address = f.staticAddress
            else
                if instance == nil then
                    error(("Field %s is not static, but no instance provided"):format(current))
                end
                address = instance + f.offset
            end
            if next == "" then
                return address, f.monotype, f.field
            end
            local vType = monoTypeToVarType(f.monotype)
            if next == "" then
                return { address }, vType, f.field
            end
            if vType ~= vtPointer then
                error(("Field %s is not a pointer in class %s"):format(current, mono_class_getName(cls)))
            end
            local next_cls = mono_field_getClass(f.field);
            -- print(("Resolving next path %s in class %s with address %x"):format(next, mono_class_getName(next_cls), address))
            return module.resolveMonoPath(next_cls, next, readPointer(address))
        end
    end
end

local fmtMrAddress = function(memoryRecord)
    local address = memoryRecord.Address
    if memoryRecord.OffsetCount then
        for i = 0, memoryRecord.OffsetCount - 1 do
            address = ("%s+%x"):format(address, memoryRecord.Offset[i])
        end
    end
    return address
end

module.createMonoInstanceRecord = function(options)
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
    -- print(("Creating Mono Instance %s for class %s"):format(fmtMrAddress(parent), mono_class_getName(cls)))
    if options.fields == nil then
        local _fields = mono_class_enumFields(cls, 1)
        for i = 1, #_fields do
            local f = _fields[i]
            if not f.isStatic then
                local field = {
                    name = f.name,
                    offsets = { ("+%x"):format(f.offset) },
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
                    -- print(module.tostring(f))
                    local address;
                    if f.isStatic then
                        address = ("%x"):format(f.staticAddress)
                    else
                        address = ("+%x"):format(f.offset)
                    end
                    local vType = monoTypeToVarType(f.monotype)
                    if next == "" then
                        return { address }, vType, f.field
                    end
                    if vType ~= vtPointer then
                        error(("Field %s is not a pointer in class %s"):format(current, mono_class_getName(cls)))
                    end
                    local offsets, ftype, member = resolveOffset(mono_field_getClass(f.field), next)
                    local new_offsets;
                    if offsets[1]:sub(1, 1) == '+' then
                        new_offsets = { address, table.unpack(offsets) }
                    else
                        new_offsets = offsets
                    end
                    return new_offsets, ftype, member
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
        -- print(("Creating field %s"):format(module.tostring(field)))
        local mr = al.createMemoryRecord()
        mr.DontSave = true
        mr.Description = field.name
        if options.onCreateField then
            options.onCreateField(mr, field)
        end
        mr.address = field.offsets[1]
        -- mr.OffsetCount = #field.offsets
        -- for j = 1, #field.offsets do
        --     mr.Offset[j - 1] = field.offsets[j]
        -- end
        if #field.offsets > 1 then
            mr.OffsetCount = #field.offsets - 1
            for j = 2, #field.offsets do
                local offset = field.offsets[j]
                if offset:sub(1, 1) == '+' then
                    mr.Offset[mr.OffsetCount - j + 1] = tonumber(offset:sub(2), 16)
                else
                    error(("Invalid offset %s for field %s"):format(offset, field.name))
                end
            end
        end
        if field.type == vtPointer then
            mr.Type = vtAutoAssembler
            mr.OffsetCount = mr.OffsetCount + 1
            for j = mr.OffsetCount - 1, 1, -1 do
                mr.Offset[j] = mr.Offset[j - 1]
            end
            mr.Offset[0] = 0
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

local function formatWithKeys(formatString, data)
  return formatString:gsub('(%${([%w_]+)})', function(match, key)
    return data[key] or match
  end)
end

local unique_id = 0
local function get_unique_prefix()
    unique_id = unique_id + 1
    return ("_unique_%d"):format(unique_id)
end

module.createSimpleHook = function(params)
    -- params = {
    --   method: number
    --   code: string (user_code)
    --   vars?: string
    -- }
    local method_at = params.method
    local allocate_at = allocateMemory(1024, method_at)
    local jmp_size = 5
    if math.abs(allocate_at - method_at) >= 0x7FFFFFFF then
        jmp_size = 14 -- use absolute jmp
    end
    local bytes_to_take = 0
    local d = createDisassembler()
    while bytes_to_take < jmp_size do
        d.disassemble(method_at + bytes_to_take)
        bytes_to_take = bytes_to_take + #d.LastDisassembleData.bytes
    end
    d.destroy()
    local prefix = get_unique_prefix()

    local code = formatWithKeys([[
define(_MethodAt_,${method_at})
define(_Alloc_,${allocate_at})
label(${prefix}_Backup_)
label(${prefix}_Var_)
label(_Code_)
label(_RETURN_)
_Alloc_:
_Code_:
${user_code}
${prefix}_Backup_:
readmem(_MethodAt_,${bytes_to_take})
jmp _RETURN_
${prefix}_Var_:
_MethodAt_:
jmp _Code_
nop ${nop_count}
_RETURN_:
registerSymbol(${prefix}_Backup_,${prefix}_Var_)
]], {
        method_at = ("%x"):format(method_at),
        allocate_at = ("%x"):format(allocate_at),
        user_code = formatWithKeys(params.code, {
            _ORIG_ = prefix .. "_Backup_",
            _Var_ = prefix .. "_Var_",
        }),
        bytes_to_take = ("%d"):format(bytes_to_take),
        nop_count = ("%d"):format(bytes_to_take - jmp_size),
        prefix = prefix,
    })
    if not autoAssemble(code) then
        print("Auto assemble failed:\n" .. code)
        error("Auto assemble failed")
    end

    if params.vars ~= nil then
        local var_at = getAddressSafe(prefix .. "_Var_")
        if var_at == nil then
            error("Cannot find var address")
        end
        registerSymbol(params.vars, var_at, true)
    end

    -- info to restore
    return {
        method_at = method_at,
        allocate_at = allocate_at,
        bytes_to_take = bytes_to_take,
        prefix = prefix,
        vars = params.vars,
    }
end

module.removeSimpleHook = function(hook_info)
    local code = [[
define(_MethodAt_,${method_at})
_MethodAt_:
readmem(${prefix}_Backup_,${bytes_to_take})
unregisterSymbol(${prefix}_Backup_,${prefix}_Var_)
]]
    code = formatWithKeys(code, {
        method_at = ("%x"):format(hook_info.method_at),
        bytes_to_take = ("%d"):format(hook_info.bytes_to_take),
        prefix = hook_info.prefix,
    })
    if not autoAssemble(code) then
        print("Auto assemble failed:\n" .. code)
        error("Auto assemble failed")
    end
    if hook_info.vars ~= nil then
        unregisterSymbol(hook_info.vars)
    end
    deAlloc(hook_info.allocate_at)
end

return module
