local module = {}

local function op_func(name, default)
    return function (a, ...)
        if module.isobject(a) then
            return module.getattr(a, name)(a, ...)
        end
        return default(a, ...)
    end
end

module.getattr = function (obj, name, nil_is_ok)
    local v = obj[name]
    if v == nil and not nil_is_ok then
        error(("'%s' object has no attribute '%s'"):format(module.op.str(obj), name))
    end
    return v
end

module.op = {
    iter = op_func("__iter", function (a, cb)
        local res
        for i, v in ipairs(a) do
            res = cb(v, i)
            if res then
                return res
            end
        end
     end),
    str = op_func("__str", function (a) return tostring(a) end),
    repr = op_func("__repr", function (a) 
        if type(a) == "string" then
            return ("%q"):format(a)
        end
        return tostring(a)
     end),
    contains = op_func("__contains", function (a, b)
        local flag = false
        module.op.iter(a, function (v)
            if v == b then
                flag = true
                return true
            end
        end)
        return flag
    end),
    copy = op_func("__copy", function (a) 
        if type(a) == "table" then
            local t = {}
            for k, v in pairs(a) do
                t[k] = v
            end
            return t
        end
        return a
     end),
}

module.Type = {
    __name = "Type",
}

module.Type.new = function (self, ...)
    -- local o = getmetatable(self):new(...);
    local o = {};
    setmetatable(o, self)
    o:__init(...)
    return o
end

module.Type.__init = function (self, ...)
end

module.Type.__repr = function (self)
    return ("<%s object>"):format(self.__name)
end

module.Type.__str = function (self)
    return self:__repr()
end

module.class = function (name, super)
    super = super or module.Type
    local cls = {__name = name}
    setmetatable(cls, {__index = super})
    cls.__super = super
    cls.__index = cls
    return cls
end

module.isobject = function (obj)
    if type(obj) ~= "table" then return false end
    local mt = getmetatable(obj)
    return mt and mt.__index ~= nil
end

module.typeof = function (obj)
    if module.isclass(obj) then
        return obj
    else
        return getmetatable(obj)
    end
end

module.isinstance = function (obj, cls)
    while obj do
        if obj == cls then return true end
        obj = getmetatable(obj)
    end
    return false
end

module.iterator = module.class("iterator")

module.iterator.__init = function (self, iterable)
    self.base = iterable
    self.chain = {}
end

module.iterator.__copy = function (self)
    local it = getmetatable(self):new(self.base)
    it.chain = {}
    for i, v in ipairs(self.chain) do
        table.insert(it.chain, v)
    end
    return it
end

module.iterator.filter = function (self,func)
    local it = self:__copy()
    table.insert(it.chain, {
        type = "filter",
        func = func
    })
    return it
end

module.iterator.map = function (self,func)
    local it = self:__copy()
    table.insert(it.chain, {
        type = "map",
        func = func
    })
    return it
end

module.iterator.reduce = function (self, func, init)
    local acc = init
    self:__iter(function (v, i)
        acc = func(acc, v, i)
    end)
    return acc
end

module.iterator.__iter = function (self, cb)
    module.op.iter(self.base,function (v, i)
        for _, chain in ipairs(self.chain) do
            if chain.type == "filter" then
                if not chain.func(v, i) then
                    return
                end
            elseif chain.type == "map" then
                v = chain.func(v, i)
            end
        end
        return cb(v, i)
    end)
end

module.iterator.foreach = function (self, cb)
    self:__iter(cb)
end

module.list = module.class("list")

module.list.__init = function (self, iterable)
    self._data = {}
    if iterable then
        module.op.iter(iterable, function (v)
            table.insert(self._data, v)
        end)
    end
end

module.list.__copy = function (self)
    local lst = getmetatable(self):new()
    for i, v in ipairs(self._data) do
        table.insert(lst._data, v)
    end
    return lst
end

module.list.__len = function (self) return #self._data end

module.list.__iter = function (self, cb) module.op.iter(self._data, cb) end

module.list.__str = function (self) return "["..table.concat(self._data, ", ").."]" end

module.list.append = function (self, v) table.insert(self._data, v) end

module.list.extend = function (self, iterable) module.op.iter(iterable, function (v) table.insert(self._data, v) end) end

module.list.insert = function (self, i, v) table.insert(self._data, i, v) end

module.list.remove = function (self, v)
    local i = self:indexof(v)
    if i > 0 then
        table.remove(self._data, i)
    end
end

module.list.pop = function (self, i) return table.remove(self._data, i) end

module.list.indexof = function (self, v)
    for i, _v in ipairs(self._data) do
        if _v == v then
            return i
        end
    end
    return -1
end

module.list.__fix_index = function (self, i)
    if type(i) ~= "number" then
        error("list indices must be integers")
    end
    if i > #self._data then
        error("list assignment index out of range")
    end
    if i < 0 then
        i = #self._data + i + 1
        if i < 0 then
            error("list assignment index out of range")
        end
    end
    return i
end

module.list.get = function (self, i)
    return self._data[self:__fix_index(i)]
end

module.list.set = function (self, i, v)
    self._data[self:__fix_index(i)] = v
end

module.list.size = function (self) return #self._data end

module.list.clear = function (self) self._data = {} end

module.list.sort = function (self, cmp)
    table.sort(self._data, cmp)
end

module.range = module.class("range")

module.range.__init = function (self, a1,a2,a3)
    self.step = a3 or 1
    if a2 then
        self.start = a1
        self.stop = a2
    else
        self.start = 0
        self.stop = a1
    end
end

module.range.__iter = function (self, cb)
    for i = self.start, self.stop - 1, self.step do
        if cb(i) then
            break
        end
    end
end

module.range.__str = function (self)
    return ("range(start=%s, stop=%s, step=%s)"):format(self.start, self.stop, self.step)
end

module.handles = module.class("handles")

module.handles.__init = function (self, ...)
    self.counter = 1
    self.free_handle = {}
end

module.handles.get = function (self)
    if #self.free_handle > 0 then
        return table.remove(self.free_handle)
    end
    local h = self.counter
    self.counter = self.counter + 1
    return h
end

module.handles.free = function (self, h)
    if type(h) ~= "number" then
        error("handle must be a number")
    end
    if h < 1 or h > self.counter then
        error(("handle %s is out of range"):format(h))
    end
    if module.op.contains(self.free_handle, h) then
        error(("handle %s is already free"):format(h))
    end
    table.insert(self.free_handle, h)
end

module.dict = module.class("dict")

module.dict.__init = function (self, iterable)
    self._handles = module.handles:new()
    self._keys = {}
    self._values = {}
    if iterable then
        module.op.iter(iterable, function (v, i) self:set(i,v) end)
    end
end

module.dict.__copy = function (self)
    return getmetatable(self):new(self)
end

module.dict.set = function (self, k, v)
    local h = self._keys[k] or self._handles:get()
    self._keys[k] = h
    self._values[h] = v
end

module.dict.get = function (self, k, default)
    local h = self._keys[k]
    if h then
        return self._values[h]
    end
    return default
end

module.dict.has_key = function (self, k)
    return self._keys[k] ~= nil
end

module.dict.pop = function (self, k, default)
    local h = self._keys[k]
    if h then
        self._keys[k] = nil
        local v = self._values[h]
        self._values[h] = nil
        self._handles:free(h)
        return v
    end
    return default
end

module.dict.keys = function (self, cb)
    for k, _ in pairs(self._keys) do
        if cb(k) then
            break
        end
    end
end

module.dict.values = function (self, cb)
    for _, v in pairs(self._values) do
        if cb(v) then
            break
        end
    end
end

module.dict.items = function (self, cb)
    for k, v in pairs(self._keys) do
        if cb(self._values[v], k) then
            break
        end
    end
end

module.dict.__iter = function (self, cb)
    self:items(cb)
end

module.dict.__str = function (self)
    local items = {}
    self:items(function (k, v)
        table.insert(items, ("%s: %s"):format(module.op.repr(k), module.op.repr(v)))
    end)
    return "{"..table.concat(items, ", ").."}"
end


local function test()
    local it = module.iterator:new(module.range:new(10)):filter(function (v) return v % 2 == 0 end):map(function (v) return v * 2 end)
    local l = module.list:new(it)
    print(module.op.str(l))
    print(#l)

    local ParentClass = module.class("ParentClass")
    ParentClass.__init = function (self, n)
        self.n = n
    end

    ParentClass.get_number = function (self)
        return self.n
    end

    local ChildClass = module.class("ChildClass", ParentClass)
    ChildClass.__init = function (self, n, m)
        ChildClass.__super.__init(self, n)
        self.m = m
    end

    ChildClass.get_number = function (self)
        return ChildClass.__super.get_number(self) + self.m
    end

    print(module.op.str(ChildClass:new(1, 2):get_number()))
end

-- test()

return module