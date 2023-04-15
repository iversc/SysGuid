open "Release\SysGuid.dll" for DLL as #sg
CallDLL #sg, "GetSystemGUID",_
ret as ulong

print winstring(ret)

close #sg
end
