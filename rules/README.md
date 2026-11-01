# 域名到应用的规则

`apps.json` 是生成的，不要手改：`python3 tools/build_app_rules.py` 从
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)（MIT 许可）的固定提交下载域名清单，
逐个文件核对 sha256，再按 `tools/build_app_rules.py` 里的 `APPS` 表归到「应用 / 类别」。
`python3 tools/build_app_rules.py --check` 重新生成并和这里的文件比较（需要联网）。

- 来源提交、用到的每个清单文件和它的 sha256 都写在 `apps.json` 的 `source` 里。
- 带 `@ads` 属性的（广告 / 统计）域名跳过，`keyword:` / `regexp:` 规则不支持，跳过的个数记在 `skipped` 里。
- 同一个域名被多个应用的清单收录时，`APPS` 表里排在前面的应用先占（YouTube 在 Google 之前，Prime Video 在 Amazon 之前），冲突个数记在 `conflicts`。
- 这是公开的域名归属，不是「这台设备在用这个应用」的证明：CDN、广告 SDK、一个公司的多个产品共用域名都会让归属偏粗（腾讯、Google、Apple、Microsoft 是整家公司的归类）。
  用你自己网络里的真实抓包看哪些域名没被归类（`apps.unmatched`），把它们写进自己的规则。

## 自己的规则

格式和 `apps.json` 一样，只需要 `apps` 一项；自己的规则优先于自带的（同一个域名以自己的为准）：

```json
{"apps": [{"app": "公司内网", "category": "办公", "suffix": ["corp.example.com"], "full": ["intranet.example.net"]}]}
```

`suffix` 匹配这个域名和它的所有子域名（落在标签边界上），`full` 只匹配这个名字本身；域名写小写，不带前导点和通配符。
用法：`apps.load("my_rules.json")`。
