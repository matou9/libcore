1、修改了sing-box的libbox的service.go中增加了NewGuiChaoService函数，方便libbox核心调用;
2、sing包中修改了newJSONObject，增加了nil参数的判断，对应github.com\sagernet\sing@v0.6.10-0.20250505040842-ba62fee9470f\common\json\badjson\merge_object.go
