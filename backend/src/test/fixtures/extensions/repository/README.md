# Sub-Store Extensions collection repository

此目录是整个 Git 仓库的静态集合订阅源，不属于某一个插件。

```text
repository/
├── catalog.json
└── packages/<extension-id>/<version>/<variant>.json
```

用户只添加一次：

当前滚动地址：

```text
https://raw.githubusercontent.com/dompling/Sub-Store-Extensions/main/repository/catalog.json
```

正式版本推荐固定 tag 或 commit：

```text
https://raw.githubusercontent.com/dompling/Sub-Store-Extensions/<tag-or-commit>/repository/catalog.json
```

catalog 会展示仓库中的所有插件；每个 entry 保留自己的 ID、版本、作者、publisher、package digest 和 envelope URL。

从仓库根生成并校验：

```bash
corepack pnpm package
corepack pnpm repository
corepack pnpm verify
```

本地服务：

```bash
corepack pnpm repository:serve
```

```text
http://127.0.0.1:8765/catalog.json
```

`catalog.json` 使用相对 package URL，因此必须与整个 `packages/` 子目录一起托管。不要手工编辑 catalog 或 envelope；根生成器会清理 stale package、聚合全部 workspace 并验证摘要闭包。

集合来源不是可执行代码信任根。trusted-official mirror 仍由 Host 官方授权和 Ed25519 签名控制，community entry 只能是 content-only 完整性包。

完整说明见 [集合源文档](../docs/CATALOG.md)。
